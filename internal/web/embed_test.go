// AUDIT-005 A-04 静态核对测试：前端 range 选择器显示数据保留提示
// （index.html 含 retention-note 元素 + app.js 从 health 读取 retention_days 更新）。
package web

import (
	"strings"
	"testing"
)

// TestRetentionNoteStatic（AUDIT-005 A-04）：静态核对前端数据保留提示已落地。
func TestRetentionNoteStatic(t *testing.T) {
	idx, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	idxStr := string(idx)
	if !strings.Contains(idxStr, "retention-note") {
		t.Error("index.html 应包含 retention-note 元素（数据保留提示）")
	}
	if !strings.Contains(idxStr, "数据保留 7 天") {
		t.Error("index.html 应包含静态默认文案'数据保留 7 天'（health 读取失败时兜底）")
	}
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	appStr := string(app)
	if !strings.Contains(appStr, "retention_days") {
		t.Error("app.js 应包含 retention_days 读取逻辑（从 health 获取保留天数）")
	}
	if !strings.Contains(appStr, "retention-note") {
		t.Error("app.js 应引用 retention-note 元素更新提示")
	}
}

// TestSampleNoteTerminology（AUDIT-005 A-05）：sample-note 用户可见文案无"防火墙"术语残留
// （与"外部威胁事件"术语统一）。
func TestSampleNoteTerminology(t *testing.T) {
	idx, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	idxStr := string(idx)
	// 定位 sample-note 元素行（id="sample-note"，排除 CSS 选择器 #sample-note 行）并断言文案。
	for _, line := range strings.Split(idxStr, "\n") {
		if strings.Contains(line, `id="sample-note"`) {
			if strings.Contains(line, "防火墙日志") {
				t.Errorf("sample-note 文案仍含'防火墙日志'术语残留: %s", strings.TrimSpace(line))
			}
			if !strings.Contains(line, "外部威胁事件") {
				t.Errorf("sample-note 文案应统一为'外部威胁事件': %s", strings.TrimSpace(line))
			}
			return
		}
	}
	t.Error("index.html 未找到 sample-note 元素")
}
