package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// upgrader WS 升级器。Origin 白名单校验在 hWS 内完成（需 Server 上下文，
// 见 hWS 注释），此处 CheckOrigin 无条件放行，校验逻辑不入 CheckOrigin。
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	// Origin 白名单策略（方案 3.7/8.2：仅允许白名单 Origin，防恶意网页跨站
	// 连接本地端口，D-04 验收项）：校验在 hWS 内实现，此处无条件放行。
	CheckOrigin: func(r *http.Request) bool { return true },
}

// wsClient 单个 WS 连接。
type wsClient struct {
	conn *websocket.Conn
	send chan []byte // 待发送帧（缓冲 64；满则丢弃陈旧帧——方案 2.2.3 非阻塞可丢弃）
}

// wsHub 连接管理与广播。
type wsHub struct {
	mu      sync.Mutex
	clients map[*wsClient]bool
}

func newWSHub() *wsHub {
	return &wsHub{clients: make(map[*wsClient]bool)}
}

func (h *wsHub) add(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = true
}

// tryAdd 尝试加入连接（VS-03：超过 wsMaxConns 上限时拒绝，防连接洪泛资源耗尽）。
// 返回 false 表示已达上限（调用方返回 503 并关闭新连接）。
func (h *wsHub) tryAdd(c *wsClient, max int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= max {
		return false
	}
	h.clients[c] = true
	return true
}

func (h *wsHub) remove(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
}

func (h *wsHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// broadcast 向所有客户端发送帧（非阻塞：发送缓冲满则丢弃该帧，防慢客户端拖垮）。
func (h *wsHub) broadcast(frame []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- frame:
		default:
			// 慢客户端：丢弃陈旧帧（方案 2.2.3：可丢弃陈旧快照）
		}
	}
}

// hWS WebSocket 升级与读写循环。
// Origin 白名单校验（方案 3.7）：Origin 头必须等于白名单（默认 http://127.0.0.1:8080）。
// M-02（auditor Minor）：无 Origin 头请求——监听回环地址（allowNoOrigin=true）时放行
// （本机 CLI/非浏览器工具场景）；监听非回环地址（0.0.0.0 等）时拒绝，
// 防止任意远程非浏览器客户端绕过白名单直连。
// VS-03（DEV-P1-001，AUD-VPS-001）：
//   - 连接数上限 ws_max_conns（默认 100），超限拒绝返回 503；
//   - SetReadLimit(4KB) 防超大帧内存消耗（客户端仅发探测消息，无业务上行帧）；
//   - 握手 deadline 5s（写 deadline：升级 101 响应须在 5s 内完成；
//     读侧已由 http.Server ReadHeaderTimeout=5s 覆盖，二者合为完整握手超时）。
func (s *Server) hWS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if !s.allowNoOrigin {
			writeErr(w, http.StatusForbidden, "缺少 Origin 头（非回环监听拒绝无 Origin 连接）")
			return
		}
		origin = "no-origin"
	} else if origin != s.wsOrigin {
		writeErr(w, http.StatusForbidden, "Origin 不在白名单")
		return
	}
	// 连接数上限（VS-03）：先原子占位（tryAdd），升级失败回滚——
	// 必须在 Upgrade 之前检查：hijack 后 101 响应已发出，无法再写 503。
	c := &wsClient{conn: nil, send: make(chan []byte, 64)}
	if !s.hub.tryAdd(c, s.wsMaxConns) {
		writeErr(w, http.StatusServiceUnavailable, "WS 连接数已达上限")
		return
	}
	// 握手 deadline：升级写响应 5s 超时（httptest/ResponseRecorder 下返回 ErrNotSupported，忽略；
	// 真实连接下在 Upgrade 内生效，hijack 后由 websocket.Conn 自管 deadline，不残留）。
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.hub.remove(c) // 升级失败回滚占位（remove 关闭 c.send，广播互斥保证无写后关）
		return          // 升级失败（非 WS 请求等），响应已由库写入
	}
	c.conn = conn
	// 帧大小上限（VS-03）：4KB，客户端异常/恶意大帧直接被库断开（超出返回错误，读循环退出）。
	conn.SetReadLimit(4 * 1024)
	defer func() {
		s.hub.remove(c)
		_ = conn.Close()
	}()
	// 读循环退出信号（VS-03 修复：客户端断开后写循环必须及时退出释放占位——
	// 否则占位回收依赖下一次广播写失败，上限场景下僵尸占位会耗尽 ws_max_conns）。
	// close 唯一方为读循环；函数返回后 channel 无引用由 GC 回收，无需 defer close。
	done := make(chan struct{})

	// 读循环：仅用于探测客户端关闭（服务端不消费消息）。
	// 客户端断开 → 读错误 → close(done) 通知写循环退出（同时关闭连接，双保险）。
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				close(done)
				_ = conn.Close()
				return
			}
		}
	}()
	// 写循环：select 同时监听读循环退出信号与待发帧（读退出后不再阻塞于 c.send，
	// 立即 return 走 defer 释放占位；remove 在 defer 内 close(c.send)，无双 close 竞态）。
	for {
		select {
		case <-done:
			return
		case frame, ok := <-c.send:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
				return
			}
		}
	}
}

// PushLoop 定时推送帧（方案 3.7：resource 5s / conn_stats 1s / system 1s / heartbeat 30s）。
// 实现选择（记录）：帧内容由只读连接查询生成（独立连接，WAL 多读者），
// 与方案"从采集 channel 复制订阅"等效（面板数据一致性：推送=查询快照，延迟 ≤ 轮询周期）。
// conn_stats 计数（W-01 修订）：独立双游标（NEW/DESTROY 各一）按 id 递增计数——
// 对批量落库延迟与归档停摆天然免疫（事件晚落库只是晚出现，不会永久排除）；
// 查询失败不推进游标（恢复后从旧游标补齐，失败窗口计数不丢失）。
func (s *Server) PushLoop(ctx context.Context) {
	resourceT := time.NewTicker(5 * time.Second)
	statT := time.NewTicker(1 * time.Second)
	heartT := time.NewTicker(30 * time.Second)
	defer resourceT.Stop()
	defer statT.Stop()
	defer heartT.Stop()
	lastNewID := int64(0)  // NEW 事件游标（W-01）
	lastDestID := int64(0) // DESTROY 事件游标（W-01：独立于 NEW，防跨类型互漏）
	lastSysID := int64(0)  // system 事件游标（R-04：id 单调游标，同秒多条不漏推）
	for {
		select {
		case <-ctx.Done():
			return
		case <-resourceT.C:
			frame, ok := s.frameResource()
			if ok {
				s.hub.broadcast(frame)
			}
		case <-statT.C:
			now := time.Now().Unix()
			newCnt, destCnt, newMax, destMax, active, ok := s.frameConnStats(lastNewID, lastDestID)
			if ok {
				lastNewID = newMax
				lastDestID = destMax
				frame, _ := json.Marshal(map[string]any{
					"type": "conn_stats", "ts": now,
					"new": newCnt, "destroy": destCnt, "active": active,
				})
				s.hub.broadcast(frame)
			}
			if id, frames := s.frameSystem(lastSysID); len(frames) > 0 {
				lastSysID = id
				for _, f := range frames {
					s.hub.broadcast(f)
				}
			}
		case <-heartT.C:
			frame, _ := json.Marshal(map[string]any{"type": "heartbeat", "ts": time.Now().Unix()})
			s.hub.broadcast(frame)
		}
	}
}

// frameResource 最新资源采样帧。
func (s *Server) frameResource() ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var ts int64
	var cpu, mem, disk float64
	var rx, tx int64
	err := s.db.QueryRowContext(ctx, `SELECT ts, cpu_percent, mem_percent, disk_percent, net_rx_bps, net_tx_bps
		FROM resources ORDER BY ts DESC LIMIT 1`).Scan(&ts, &cpu, &mem, &disk, &rx, &tx)
	if err != nil {
		return nil, false
	}
	frame, _ := json.Marshal(map[string]any{
		"type": "resource", "ts": ts, "cpu": cpu, "mem": mem, "disk": disk,
		"net_rx_bps": rx, "net_tx_bps": tx,
	})
	return frame, true
}

// frameConnStats 每秒 NEW/DESTROY 计数 + 当前活跃数（W-01：独立双游标按 id 递增）。
// 返回（newCnt, destCnt, newMaxID, destMaxID, active, ok）。
// 语义：
//   - 计数 = id 落在 (lastXID, 当前 MAX(id)] 区间内的事件数——批量落库延迟/归档停摆
//     只影响事件"何时出现"，不产生永久排除（晚落库的事件 id 大于旧游标，下轮计数补齐）；
//   - 查询失败返回 ok=false 且不推进游标——调用方保持旧游标，恢复后从旧游标补齐，
//     失败窗口计数不丢失（与 ts 窗口方案不同：ts 方案失败窗口永久计 0）。
func (s *Server) frameConnStats(lastNewID, lastDestID int64) (int64, int64, int64, int64, int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var newCnt, destCnt, newMax, destMax int64
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM connections WHERE id > ?1 AND ev_type = 1),
		(SELECT COALESCE(MAX(id), ?1) FROM connections WHERE ev_type = 1),
		(SELECT COUNT(*) FROM connections WHERE id > ?2 AND ev_type = 3),
		(SELECT COALESCE(MAX(id), ?2) FROM connections WHERE ev_type = 3)`,
		lastNewID, lastDestID).Scan(&newCnt, &newMax, &destCnt, &destMax)
	if err != nil {
		// 查询失败：不推进游标（返回 ok=false，调用方保持旧游标待恢复后补齐）。
		return 0, 0, lastNewID, lastDestID, 0, false
	}
	return newCnt, destCnt, newMax, destMax, s.activeConns(), true
}

// frameSystem 查询新增 system_events 并构造帧列表（R-04：id 单调游标，
// 同秒多条全部推送不漏推）。返回（最新 id, 帧列表）。
func (s *Server) frameSystem(afterID int64) (int64, [][]byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, source, level, message FROM system_events
		WHERE id > ? ORDER BY id LIMIT 20`, afterID)
	if err != nil {
		return afterID, nil
	}
	defer rows.Close()
	lastID := afterID
	var frames [][]byte
	for rows.Next() {
		var id, ts int64
		var source, level, message string
		if rows.Scan(&id, &ts, &source, &level, &message) != nil {
			break
		}
		lastID = id
		f, _ := json.Marshal(map[string]any{
			"type": "system", "id": id, "ts": ts, "source": source, "level": level, "message": message,
		})
		frames = append(frames, f)
	}
	return lastID, frames
}
