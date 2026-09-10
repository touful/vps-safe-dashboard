package api

import "net/http"

// limitStats 不排队、不放宽既有令牌桶。两路长聚合共享 128 MB 临时空间，
// 超额请求在占用数据库连接之前明确返回可退避的 429，而非等到磁盘满后 500。
// 短窗口也经过此门禁，避免以不同参数绕过全局聚合并发约束。
func (s *Server) limitStats(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Err() != nil {
			return
		}
		select {
		case s.statsSlots <- struct{}{}:
			defer func() { <-s.statsSlots }()
			next(w, r)
		default:
			w.Header().Set("Retry-After", "2")
			writeErr(w, http.StatusTooManyRequests, "统计查询繁忙，请稍后重试")
		}
	}
}
