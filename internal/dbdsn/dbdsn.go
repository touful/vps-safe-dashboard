// Package dbdsn 提供 SQLite DSN 构造（DEV-ARCH-002 D9 收敛）。
// 原分散于 api.NewServer / f2b.readOnlyDSN / store.openDB 三处，统一于此；
// 路径 URL 编码规则一致（url.PathEscape，转义 '?'/'#'/'%' 等 DSN 特殊字符）。
package dbdsn

import (
	"fmt"
	"net/url"
)

// ReadOnly 构造只读连接 DSN（mode=ro + busy_timeout=5000；WAL 多读者，
// 供 api 只读查询与 f2b 封禁名单查询使用）。
func ReadOnly(path string) string {
	return "file:" + url.PathEscape(path) + "?mode=ro&_pragma=busy_timeout(5000)"
}

// ReadWrite 构造主库读写连接 DSN（WAL + synchronous=NORMAL + busy_timeout +
// foreign_keys；供 store 单写线程使用）。
func ReadWrite(path string) string {
	return fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", url.PathEscape(path))
}
