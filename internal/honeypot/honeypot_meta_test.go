package honeypot

import "testing"

// TestProtoKindsMatchHandlers 守卫 ProtoKinds 与 protoHandlers 键集合完全一致（双向），
// 防两表漂移（m3 单一来源修复配套）：新增协议时只登记其一即在本测试失败，
// 促使开发者同时补齐处理器与捕获分类。
func TestProtoKindsMatchHandlers(t *testing.T) {
	for p := range protoHandlers {
		if _, ok := ProtoKinds[p]; !ok {
			t.Errorf("协议 %q 在 protoHandlers 有处理器但 ProtoKinds 未登记（单一来源漂移）", p)
		}
	}
	for p := range ProtoKinds {
		if _, ok := protoHandlers[p]; !ok {
			t.Errorf("协议 %q 在 ProtoKinds 已登记但 protoHandlers 无处理器（单一来源漂移）", p)
		}
	}
	// 分类取值守卫：ProtoKinds 的值须落在三个已定义常量内（防手滑写入未定义值）。
	for p, k := range ProtoKinds {
		switch k {
		case KindPlaintext, KindHash, KindNone:
		default:
			t.Errorf("协议 %q 的捕获分类 %q 非法（须为 plaintext/hash/none 之一）", p, k)
		}
	}
}
