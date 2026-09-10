package api

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAggregationTimeoutWindows(t *testing.T) {
	for _, tc := range []struct {
		window string
		want   time.Duration
	}{{"1h", 5 * time.Second}, {"24h", 15 * time.Second}, {"7d", 15 * time.Second},
		{"30d", 30 * time.Second}, {"", 15 * time.Second}, {"invalid", 15 * time.Second}} {
		r := httptest.NewRequest("GET", "/?range="+tc.window, nil)
		if got := aggTimeout(r, 15*time.Second); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.window, got, tc.want)
		}
	}
}

func TestStatsCoveringIndexAndEquivalentCounts(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, col := range []string{"dst_port", "src_ip"} {
		query := `SELECT ` + col + `, COUNT(*) FROM firewall_events INDEXED BY idx_fw_ts_stats
			WHERE ts >= ? GROUP BY ` + col + ` ORDER BY COUNT(*) DESC LIMIT 50`
		rows, err := srv.db.Query("EXPLAIN QUERY PLAN "+query, 0)
		if err != nil {
			t.Fatal(err)
		}
		covering := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			covering = covering || strings.Contains(detail, "COVERING INDEX idx_fw_ts_stats")
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		if !covering {
			t.Fatal("查询未使用覆盖索引")
		}
		old, err := srv.db.Query(strings.ReplaceAll(query, "idx_fw_ts_stats", "idx_fw_ts"), 0)
		if err != nil {
			t.Fatal(err)
		}
		want := map[int64]int64{}
		for old.Next() {
			var value, count int64
			if err := old.Scan(&value, &count); err != nil {
				t.Fatal(err)
			}
			want[value] = count
		}
		if err := old.Err(); err != nil {
			t.Fatal(err)
		}
		old.Close()
		got, err := srv.topHits(context.Background(), 0, 50, col)
		if err != nil || len(got) != len(want) {
			t.Fatalf("聚合不等价: %v, %v", got, err)
		}
		for _, hit := range got {
			if want[hit.V] != hit.Hits {
				t.Fatal("覆盖索引改变计数")
			}
		}
	}
}

// 独立驱动在成功读出一行后注入迭代错误，确保 handler 不会返回部分成功数据。
type failingStatsDriver struct{}
type failingStatsConn struct{}
type failingStatsRows struct {
	columns int
	count   bool
	sent    bool
}

func (failingStatsDriver) Open(string) (driver.Conn, error)  { return failingStatsConn{}, nil }
func (failingStatsConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (failingStatsConn) Close() error                        { return nil }
func (failingStatsConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (failingStatsConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "SUM(CASE") {
		return &failingStatsRows{columns: 5}, nil
	}
	if strings.HasPrefix(query, "SELECT COUNT(*)") {
		return &failingStatsRows{columns: 1, count: true}, nil
	}
	return &failingStatsRows{columns: 2}, nil
}
func (r *failingStatsRows) Columns() []string { return make([]string, r.columns) }
func (r *failingStatsRows) Close() error      { return nil }
func (r *failingStatsRows) Next(dest []driver.Value) error {
	if r.sent {
		if r.count {
			return io.EOF
		}
		return errors.New("injected iteration failure")
	}
	r.sent = true
	for i := range dest {
		dest[i] = int64(1)
	}
	return nil
}

func init() { sql.Register("perf-failing-stats", failingStatsDriver{}) }

func TestAggregationIterationFailureIsNotSuccess(t *testing.T) {
	for _, endpoint := range []string{"summary", "attacks/top_ports", "attacks/top_sources", "firewall/timeline"} {
		t.Run(endpoint, func(t *testing.T) {
			srv, _ := newTestServer(t)
			srv.db.Close()
			var err error
			srv.db, err = sql.Open("perf-failing-stats", "")
			if err != nil {
				t.Fatal(err)
			}
			code, out := doGet(t, srv, "/api/v1/"+endpoint+"?range=24h")
			if code != 500 {
				t.Fatalf("迭代中断必须报错，got %d, %v", code, out)
			}
		})
	}
}

func TestStatsConcurrencyRejectsBeforeQueryAndRecovers(t *testing.T) {
	srv, _ := newTestServer(t)
	entered, release, finished := make(chan struct{}, 2), make(chan struct{}), make(chan struct{}, 2)
	handler := srv.limitStats(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})
	for i := 0; i < 2; i++ {
		go func() {
			handler(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			finished <- struct{}{}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("执行槽未按预期开放")
		}
	}
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("超额应立即退避，got %d", rec.Code)
	}
	// 轻查询不被统计执行槽阻塞。
	if code, _ := doGet(t, srv, "/api/v1/resources?range=1h"); code != 200 {
		t.Fatalf("轻查询被误伤: %d", code)
	}
	close(release)
	<-finished
	<-finished
	rec = httptest.NewRecorder()
	srv.limitStats(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || len(srv.statsSlots) != 0 {
		t.Fatal("执行槽未释放")
	}
}
