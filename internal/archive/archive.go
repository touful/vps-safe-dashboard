// Package archive 实现 M-09 归档模块（方案 3.9/4.6）。
// 语义（D-04 定稿）：仅生成压缩副本、主库永久保留、无任何删除路径。
// DELETE 仅允许出现在归档临时文件（.tmp）清理中——那是副本文件而非主库数据。
package archive

import (
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ArchivedTables 返回归档导出表清单（方案 4.4 示例；meta 不导出）。
// 单点定义：store 包归档执行与 archive 包均引用此处（DRY）。
func ArchivedTables() []string {
	return []string{"resources", "connections", "ssh_attempts", "firewall_events", "ban_events", "system_events"}
}

// archivedTables 内部使用视图（避免每次调用分配）。
var archivedTables = ArchivedTables()

// metaCopiedMonths meta 键：已归档月份（逗号分隔 "2026-06,2026-07"）。
const metaCopiedMonths = "copied_months"

// ParseMonth 解析 "YYYY-MM" 月份标识，返回（年, 月, 起始秒, 结束秒, error）。
// 区间：月初 00:00:00 到次月月初（左闭右开）。
func ParseMonth(month string) (int, time.Month, int64, int64, error) {
	parts := strings.SplitN(month, "-", 2)
	if len(parts) != 2 || len(parts[0]) != 4 || len(parts[1]) != 2 {
		return 0, 0, 0, 0, fmt.Errorf("月份格式应为 YYYY-MM: %q", month)
	}
	var y, m int
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return 0, 0, 0, 0, fmt.Errorf("月份格式应为 YYYY-MM: %q", month)
		}
		y = y*10 + int(c-'0')
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return 0, 0, 0, 0, fmt.Errorf("月份格式应为 YYYY-MM: %q", month)
		}
		m = m*10 + int(c-'0')
	}
	if m < 1 || m > 12 {
		return 0, 0, 0, 0, fmt.Errorf("月份超出范围: %q", month)
	}
	loc := time.Local
	start := time.Date(y, time.Month(m), 1, 0, 0, 0, 0, loc)
	end := time.Date(y, time.Month(m)+1, 1, 0, 0, 0, 0, loc)
	return y, time.Month(m), start.Unix(), end.Unix(), nil
}

// ArchiveMonthDB 在给定主库连接上导出指定月份数据到独立 SQLite 文件并 gzip。
// 幂等与自愈（方案 3.9/4.6）：
//   - meta.copied_months 记录且副本文件存在 → 跳过；
//   - meta 已记录但副本文件缺失（被外部删除）→ 从 meta 移除后重新导出（R-08）；
//   - 残留 .db.tmp / .db.gz.tmp → 删除后重新导出（中断恢复，R-01）；
//   - finalPath 存在但 meta 未记录（半截残留）→ 删除后重新导出（R-01 自愈）；
//   - 行数校验 + MAX(ts) 校验（逐表主库区间 vs 副本）不一致 → 报错（重跑幂等）。
//
// 主库无任何 DELETE（D-04）。本函数可单测（临时目录 + 临时主库）。
func ArchiveMonthDB(db *sql.DB, archiveDir, month string, gzipLevel int) error {
	y, m, start, end, err := ParseMonth(month)
	if err != nil {
		return err
	}
	// VS-01（DEV-P1-001）：归档目录 0700（与 store.NewStore 同语义——数据目录收权，
	// 同机其他用户不可读归档副本；目录由 store 先行创建时此处为 no-op，模式保持一致）。
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return fmt.Errorf("创建归档目录失败: %w", err)
	}
	finalPath := filepath.Join(archiveDir, fmt.Sprintf("%04d-%02d.db.gz", y, m))
	tmpDB := filepath.Join(archiveDir, fmt.Sprintf("%04d-%02d.db.tmp", y, m))
	tmpGZ := filepath.Join(archiveDir, fmt.Sprintf("%04d-%02d.db.gz.tmp", y, m))

	// 清理各类残留（仅归档临时/半截副本文件，非主库数据）。
	for _, stale := range []string{tmpDB, tmpGZ} {
		if err := os.Remove(stale); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清理归档残留 %s 失败: %w", stale, err)
		}
	}

	copied, err := readCopiedMonths(db)
	if err != nil {
		return err
	}
	_, finalExists := os.Stat(finalPath)
	if containsMonth(copied, month) {
		if finalExists == nil {
			return nil // meta 记录且文件存在 → 已归档，跳过
		}
		// meta 记录但文件缺失（外部删除/损坏）→ 移除记录重新导出（R-08 自愈）。
		remain := copied[:0]
		for _, m := range copied {
			if m != month {
				remain = append(remain, m)
			}
		}
		if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			metaCopiedMonths, strings.Join(remain, ",")); err != nil {
			return fmt.Errorf("移除失效归档记录失败: %w", err)
		}
	}
	if finalExists == nil {
		// finalPath 存在但 meta 未记录 → 半截残留（R-01），删除后重新导出。
		if err := os.Remove(finalPath); err != nil {
			return fmt.Errorf("清理半截副本失败: %w", err)
		}
	}

	// 空月检查：该月无任何数据 → 不产文件（R-06，避免空副本堆积）。
	hasData, err := monthHasData(db, start, end)
	if err != nil {
		return err
	}
	if !hasData {
		return nil
	}

	// 导出：写 .db.tmp → gzip 写 .db.gz.tmp → 原子 rename 为 .db.gz（R-01 原子替换）。
	if err := exportMonth(db, tmpDB, start, end); err != nil {
		return err
	}
	// VS-01：中间 .db.tmp 由 SQLite ATTACH 创建（mode 受 umask 影响，可能 0644），
	// gzip 前显式收权 0600——中间文件含同量级敏感数据，且存在时间横跨 gzip 全程。
	if err := os.Chmod(tmpDB, 0o600); err != nil {
		return fmt.Errorf("归档临时文件权限收权失败: %w", err)
	}
	if err := gzipFile(tmpDB, tmpGZ, gzipLevel); err != nil {
		return fmt.Errorf("gzip 归档文件失败: %w", err)
	}
	if err := os.Rename(tmpGZ, finalPath); err != nil {
		return fmt.Errorf("归档文件原子替换失败: %w", err)
	}
	if err := os.Remove(tmpDB); err != nil {
		return fmt.Errorf("清理归档临时文件失败: %w", err)
	}

	// 记录已归档月份。
	if err := recordCopiedMonth(db, month); err != nil {
		return fmt.Errorf("记录归档月份失败: %w", err)
	}
	return nil
}

// monthHasData 检查主库 [start, end) 区间是否有任何数据（任一归档表有行即 true）。
func monthHasData(db *sql.DB, start, end int64) (bool, error) {
	for _, t := range archivedTables {
		var n int64
		if err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM main."%s" WHERE ts >= ?1 AND ts < ?2`, t), start, end).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// exportMonth 将主库 [start, end) 区间数据导出到 tmpPath 独立 SQLite 库并校验行数。
// 实现：主库连接上 ATTACH 副本文件 → 逐表复制结构+数据 → 行数+MAX(ts) 校验 → DETACH。
func exportMonth(db *sql.DB, tmpPath string, start, end int64) error {
	// ATTACH 自动创建不存在的副本文件；路径按 SQLite 字符串字面量规则转义
	// （单引号双写，兼容含引号/反斜杠路径；%q Go 转义与 SQLite 语义不一致）。
	if _, err := db.Exec("ATTACH DATABASE " + sqliteQuote(tmpPath) + " AS arc"); err != nil {
		return fmt.Errorf("ATTACH 归档副本失败: %w", err)
	}
	defer db.Exec("DETACH DATABASE arc") //nolint:errcheck // 失败不影响返回

	for _, t := range archivedTables {
		// 复制表结构（无数据；CREATE TABLE AS SELECT 保留列类型）。
		if _, err := db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS arc."%s" AS SELECT * FROM main."%s" WHERE 1=0`, t, t)); err != nil {
			return fmt.Errorf("创建副本表 %s 失败: %w", t, err)
		}
		// 复制区间数据。
		if _, err := db.Exec(fmt.Sprintf(`INSERT INTO arc."%s" SELECT * FROM main."%s" WHERE ts >= ?1 AND ts < ?2`, t, t), start, end); err != nil {
			return fmt.Errorf("导出表 %s 失败: %w", t, err)
		}
	}
	// 行数校验 + MAX(ts) 校验（方案 3.9）：逐表主库区间 vs 副本。
	for _, t := range archivedTables {
		var mainCount, arcCount int64
		if err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM main."%s" WHERE ts >= ?1 AND ts < ?2`, t), start, end).Scan(&mainCount); err != nil {
			return fmt.Errorf("主库计数 %s 失败: %w", t, err)
		}
		if err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM arc."%s"`, t)).Scan(&arcCount); err != nil {
			return fmt.Errorf("副本计数 %s 失败: %w", t, err)
		}
		if mainCount != arcCount {
			return fmt.Errorf("行数校验不一致（%s）：主库 %d vs 副本 %d", t, mainCount, arcCount)
		}
		if mainCount > 0 {
			var mainMax, arcMax sql.NullInt64
			if err := db.QueryRow(fmt.Sprintf(`SELECT MAX(ts) FROM main."%s" WHERE ts >= ?1 AND ts < ?2`, t), start, end).Scan(&mainMax); err != nil {
				return fmt.Errorf("主库 MAX(ts) 查询 %s 失败: %w", t, err)
			}
			if err := db.QueryRow(fmt.Sprintf(`SELECT MAX(ts) FROM arc."%s"`, t)).Scan(&arcMax); err != nil {
				return fmt.Errorf("副本 MAX(ts) 查询 %s 失败: %w", t, err)
			}
			if !mainMax.Valid || !arcMax.Valid || mainMax.Int64 != arcMax.Int64 {
				return fmt.Errorf("MAX(ts) 校验不一致（%s）：主库 %v vs 副本 %v", t, mainMax, arcMax)
			}
		}
	}
	return nil
}

// gzipFile 将 src 压缩为 dst.gz（gzip_level 1-9）。
// 注：关闭前 fsync 落盘，降低"rename 已生效但数据仍滞留 page cache"
// 的掉电窗口（与主库 synchronous=NORMAL 的掉电风险级别相当；进程中断路径已由
// .tmp/半截自愈闭环覆盖，此 Sync 仅封堵掉电场景）。
func gzipFile(src, dst string, gzipLevel int) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// VS-01（DEV-P1-001）：gzip 归档文件 0600（原 0644）——归档副本含全部历史敏感数据，
	// 同机其他用户不可读。OpenFile mode 在 Linux 上受 umask 求反（0600 &^ 022 = 0600），直接生效。
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	gw, err := gzip.NewWriterLevel(out, gzipLevel)
	if err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(gw, in); err != nil {
		gw.Close()
		out.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// readCopiedMonths 读取 meta.copied_months。
func readCopiedMonths(db *sql.DB) ([]string, error) {
	var val string
	err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaCopiedMonths).Scan(&val)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	return strings.Split(val, ","), nil
}

// recordCopiedMonth 追加记录已归档月份。
func recordCopiedMonth(db *sql.DB, month string) error {
	copied, err := readCopiedMonths(db)
	if err != nil {
		return err
	}
	if containsMonth(copied, month) {
		return nil
	}
	copied = append(copied, month)
	_, err = db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		metaCopiedMonths, strings.Join(copied, ","))
	return err
}

// containsMonth 判断月份是否已归档。
func containsMonth(copied []string, month string) bool {
	for _, m := range copied {
		if m == month {
			return true
		}
	}
	return false
}

// CleanStaleTmp 清理归档目录中残留的临时/半截文件（方案 4.6"启动自愈"）。
// 启动时调用：删除 *.db.tmp / *.db.gz.tmp（中断残留，下次归档该月时重新导出）。
// 注意：不删除 *.db.gz（半截 .gz 由 ArchiveMonthDB 的 meta 一致性检查自愈）。
func CleanStaleTmp(archiveDir string) error {
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 目录不存在（从未归档）视为干净
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".db.tmp") || strings.HasSuffix(name, ".db.gz.tmp") {
			if err := os.Remove(filepath.Join(archiveDir, name)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("清理归档残留 %s 失败: %w", name, err)
			}
		}
	}
	return nil
}

// RunArchiver 定时检查协程（方案 2.3.2 archiver）：// 每日检查是否"每月 1 日且已到 monthly_hour"，满足则对超过 copy_after_days 的月份
// 逐个投递 request（store.RequestArchive，写线程内同步执行）。
// checkInterval 可配置（演练用短间隔）；每月 1 日当天只执行一次（meta 幂等兜底）。
func RunArchiver(ctx context.Context, checkInterval time.Duration, monthlyHour string, copyAfterDays int, request func(month string) error) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			// 判定：每月 1 日且时刻 >= monthly_hour（方案 3.9：每日 02:00 检查是否每月 1 日）。
			if now.Day() != 1 {
				continue
			}
			var hh, mm int
			if _, err := fmt.Sscanf(monthlyHour, "%02d:%02d", &hh, &mm); err != nil {
				continue
			}
			deadline := time.Date(now.Year(), now.Month(), 1, hh, mm, 0, 0, time.Local)
			if now.Before(deadline) {
				continue
			}
			// 应归档截止月：now - copy_after_days 所在月。
			cutoff := now.AddDate(0, 0, -copyAfterDays)
			cutoffStart := time.Date(cutoff.Year(), cutoff.Month(), 1, 0, 0, 0, 0, time.Local)
			// 候选月份：从 cutoff 月起向前（含 cutoff 月）最多 24 个月（防极端数据积累）。
			for i := 0; i < 24; i++ {
				cand := cutoffStart.AddDate(0, -i, 0)
				month := fmt.Sprintf("%04d-%02d", cand.Year(), cand.Month())
				if err := request(month); err != nil {
					// 投递失败不终止检查循环（跳过该月，下个周期重试）。
					continue
				}
			}
		}
	}
}

// DefaultCriticalUsagePct 磁盘 critical 水位默认值（方案 7.3：warn 80 / critical 90 / emergency 95）。
// 归档在 critical 及以上时跳过（方案 3.9"critical 时跳过归档并告警"）。
// 实际阈值由配置 disk.critical_percent 传入（与 diskmon 共用配置，见 ShouldSkipArchive 签名）。
const DefaultCriticalUsagePct = 90.0

// ShouldSkipArchive 判定磁盘水位是否阻止归档（纯函数，可单测）：
// 使用率 >= criticalPercent（配置阈值）时跳过；statfs 失败时保守跳过（无法确认空间充足）。
func ShouldSkipArchive(usagePercent float64, statfsOK bool, criticalPercent float64) bool {
	if !statfsOK {
		return true
	}
	return usagePercent >= criticalPercent
}

// sqliteQuote 将字符串转为 SQLite 字符串字面量：单引号双写（” 转义），
// 与 SQLite 字面量语义一致；Go 的 %q 转义（\x 风格）在 SQLite 中不生效。
func sqliteQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// MonthOf 返回 ts 对应的月份标识 "YYYY-MM"。
func MonthOf(ts int64) string {
	t := time.Unix(ts, 0)
	return fmt.Sprintf("%04d-%02d", t.Year(), t.Month())
}
