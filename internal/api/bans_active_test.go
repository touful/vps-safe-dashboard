package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentry-agent/internal/event"
)

// TestBansActive P3-1：当前封禁名单端点（nil fn 空名单 / 快照转换与排序保持）。
func TestBansActive(t *testing.T) {
	t.Run("未注入fn输出空名单", func(t *testing.T) {
		s := &Server{}
		w := httptest.NewRecorder()
		s.hBansActive(w, httptest.NewRequest(http.MethodGet, "/api/v1/bans/active", nil))
		var got struct {
			TS    int64    `json:"ts"`
			Count int      `json:"count"`
			Rows  []string `json:"rows"`
		}
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.TS != 0 || got.Count != 0 || got.Rows == nil || len(got.Rows) != 0 {
			t.Errorf("空名单语义错误: %+v", got)
		}
	})
	t.Run("快照IP转换字符串", func(t *testing.T) {
		s := &Server{bannedFn: func() ([]uint32, int64) {
			return []uint32{
				event.IPv4ToUint32(net.ParseIP("198.51.100.7")),
				event.IPv4ToUint32(net.ParseIP("203.0.113.5")),
			}, 1700000000
		}}
		w := httptest.NewRecorder()
		s.hBansActive(w, httptest.NewRequest(http.MethodGet, "/api/v1/bans/active", nil))
		var got struct {
			TS    int64    `json:"ts"`
			Count int      `json:"count"`
			Rows  []string `json:"rows"`
		}
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.TS != 1700000000 || got.Count != 2 {
			t.Fatalf("ts/count 错误: %+v", got)
		}
		if len(got.Rows) != 2 || got.Rows[0] != "198.51.100.7" || got.Rows[1] != "203.0.113.5" {
			t.Errorf("IP 转换/顺序错误: %v", got.Rows)
		}
	})
}
