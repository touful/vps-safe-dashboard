package api

import (
	"database/sql"
	"testing"
)

// createTestSchema 创建 api 测试所需全部表与索引（m5 单一来源修复）。
// 权威定义位置：internal/store/store.go 的 schema 常量（本 DDL 与其对齐；
// store 侧新增表/索引时须同步更新此处）。历史教训：api 测试曾四处自维护 DDL 副本，
// 曾因副本缺 idx_fw_ts 踩坑——现统一收敛到本 helper，四处测试 fixture 均调用它。
// 说明：store schema 中的 PRAGMA（journal_mode/busy_timeout 等）为连接级运行参数
// 而非建库结构，测试环境按 modernc/sqlite 默认值即可，不在此复制。
// meta 种子行 schema_version=1 为四个 fixture 的共同需求，一并在此写入。
func createTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS resources (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    cpu_percent  REAL    NOT NULL,
    mem_used_mb  REAL    NOT NULL,
    mem_percent  REAL    NOT NULL,
    disk_used_mb REAL    NOT NULL,
    disk_percent REAL    NOT NULL,
    net_rx_bps   INTEGER NOT NULL DEFAULT 0,
    net_tx_bps   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_resources_ts ON resources(ts);

CREATE TABLE IF NOT EXISTS connections (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    ev_type  INTEGER NOT NULL,
    proto    INTEGER NOT NULL,
    src_ip   INTEGER NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip   INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    packets  INTEGER NOT NULL DEFAULT 0,
    bytes    INTEGER NOT NULL DEFAULT 0,
    mark     INTEGER NOT NULL DEFAULT 0,
    src_ip6  TEXT    NOT NULL DEFAULT '',
    dst_ip6  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_conn_ts    ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_dport ON connections(dst_port);
CREATE INDEX IF NOT EXISTS idx_conn_src   ON connections(src_ip);
CREATE INDEX IF NOT EXISTS idx_conn_evid  ON connections(ev_type, id);

CREATE TABLE IF NOT EXISTS ssh_attempts (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    src_ip      INTEGER NOT NULL,
    username    TEXT    NOT NULL DEFAULT '',
    auth_method TEXT    NOT NULL DEFAULT '',
    result      INTEGER NOT NULL,
    fingerprint TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ssh_ts   ON ssh_attempts(ts);
CREATE INDEX IF NOT EXISTS idx_ssh_src  ON ssh_attempts(src_ip);
CREATE INDEX IF NOT EXISTS idx_ssh_user ON ssh_attempts(username);
CREATE INDEX IF NOT EXISTS idx_ssh_ts_result ON ssh_attempts(ts, result);

CREATE TABLE IF NOT EXISTS firewall_events (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    chain    TEXT    NOT NULL,
    action   TEXT    NOT NULL,
    proto    INTEGER NOT NULL,
    src_ip   INTEGER NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip   INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    raw      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_fw_ts     ON firewall_events(ts);
CREATE INDEX IF NOT EXISTS idx_fw_dport  ON firewall_events(dst_port);
CREATE INDEX IF NOT EXISTS idx_fw_action ON firewall_events(action);
CREATE INDEX IF NOT EXISTS idx_fw_src_ts ON firewall_events(src_ip, ts);

CREATE TABLE IF NOT EXISTS ban_events (
    id   INTEGER PRIMARY KEY,
    ts   INTEGER NOT NULL,
    ip   INTEGER NOT NULL,
    type TEXT    NOT NULL,
    jail TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ban_ts ON ban_events(ts);
CREATE INDEX IF NOT EXISTS idx_ban_ip ON ban_events(ip);

CREATE TABLE IF NOT EXISTS system_events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    source  TEXT    NOT NULL,
    level   TEXT    NOT NULL,
    message TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_se_ts ON system_events(ts);

CREATE TABLE IF NOT EXISTS cred_events (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    proto    TEXT    NOT NULL,
    src_ip   INTEGER NOT NULL,
    username TEXT    NOT NULL DEFAULT '',
    password TEXT    NOT NULL DEFAULT '',
    extra    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cred_ts    ON cred_events(ts);
CREATE INDEX IF NOT EXISTS idx_cred_src   ON cred_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_cred_proto ON cred_events(proto);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO meta(key, value) VALUES('schema_version', '1');
`)
	if err != nil {
		t.Fatalf("createTestSchema 建库失败: %v", err)
	}
}
