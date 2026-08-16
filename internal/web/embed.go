// Package web 内嵌前端静态资源（方案 3.8：Go embed 单二进制交付，零 CDN 依赖，
// VPS 无外网场景可用；ECharts 为本地静态文件 echarts.min.js）。
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Handler 返回前端静态文件处理器（首页 / 与静态资源）。
// VS-12/CSP（DEV-P1-001，AUD-VPS-001 VS-12 + AUD-FE-001 SC-02）：静态响应附加安全头
// ——CSP 纵深防御（暴露场景防点击劫持/内容嗅探/数据外传）。
// CSP 取舍说明（connect-src）：显式写死 ws://127.0.0.1:8080 覆盖默认部署形态；
// 用户改监听端口/域名时同源 WS 由 'self' 覆盖（现代浏览器 CSP3 语义：'self' 匹配
// 同 host+port 的 ws/wss），显式条目仅作老浏览器兜底——即改端口无需改代码，
// 但如改监听为域名 + 反代，须同步本头（见部署手册 §WS Origin 说明）。
func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embed 路径错误属编译期问题，启动即暴露
	}
	return withSecurityHeaders(http.FileServer(http.FS(sub)))
}

// withSecurityHeaders 附加安全响应头（CSP / nosniff / frame deny）。
// 前提核验（DEV-P1-001）：index.html 无内联 <script>（echarts.min.js/app.js 均为
// 外部文件，script-src 'self' 可行）；内联 <style> 与 style 属性需 style-src 'unsafe-inline'；
// data URI favicon 需 img-src data:；内联 SVG 图标不受 img-src 限制（非资源加载）。
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:8080; font-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
