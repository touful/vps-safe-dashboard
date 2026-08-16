// archive-trigger 归档演练触发工具（开发/验证用，非交付组件）。
// 用法：archive-trigger -db <主库路径> -month <YYYY-MM> -dir <归档目录> -gzip <级别>
// 调用 archive.ArchiveMonthDB（与 Store 写线程内执行路径相同）。
//
// 警示：本工具以读写方式直接打开主库执行归档；若 sentry-agent 正在运行，
// 其写线程持有同一主库（单写者），并发操作可能冲突——演练前必须先停止 agent。
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "modernc.org/sqlite"

	"sentry-agent/internal/archive"
)

func main() {
	dbPath := flag.String("db", "", "主库路径")
	month := flag.String("month", "", "归档月份 YYYY-MM")
	dir := flag.String("dir", "", "归档目录")
	gzipLevel := flag.Int("gzip", 6, "gzip 级别 1-9")
	flag.Parse()

	if *dbPath == "" || *month == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "用法: archive-trigger -db <path> -month <YYYY-MM> -dir <dir> [-gzip N]")
		os.Exit(2)
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s", *dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开主库失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := archive.ArchiveMonthDB(db, *dir, *month, *gzipLevel); err != nil {
		fmt.Fprintf(os.Stderr, "归档失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("归档完成: %s → %s\n", *month, *dir)
}
