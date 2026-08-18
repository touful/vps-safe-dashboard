// 协议处理器占位实现（阶段 1 框架自测用；阶段 2/3 按协议分组替换为完整实现）。
// 占位行为：仅读取并丢弃客户端数据直至超时/断开（不产生凭据事件），
// 保证 protoHandlers 注册表可编译、框架连接治理路径可自测。
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

// 阶段 2/3 替换为真实实现。
var (
	handleTelnet    = stubHandler
	handleFTP       = stubHandler
	handleRedis     = stubHandler
	handlePostgres  = stubHandler
	handleMySQL     = stubHandler
	handleMongoDB   = stubHandler
	handleMSSQL     = stubHandler
	handleSMB       = stubHandler
	handleRDP       = stubHandler
	handleMemcached = stubHandler
)
