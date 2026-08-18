// 阶段 3 复杂/加密协议占位（阶段 2 自测期间保持可编译；阶段 3 替换为完整实现）。
package honeypot

import (
	"context"
	"net"

	"sentry-agent/internal/event"
)

// stubHandler 占位处理器：循环读丢弃数据（依赖框架 30s 连接超时兜底）。
func stubHandler(ctx context.Context, conn net.Conn, srcIP uint32, rec func(event.CredEvent)) {
	buf := make([]byte, 1024)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

var (
	handleMySQL     = stubHandler
	handleMongoDB   = stubHandler
	handleMSSQL     = stubHandler
	handleSMB       = stubHandler
	handleRDP       = stubHandler
	handleMemcached = stubHandler
)
