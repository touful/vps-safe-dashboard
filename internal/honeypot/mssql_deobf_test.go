package honeypot

import (
	"encoding/hex"
	"testing"
)

// TestDeobfuscateTDSPassword 已知向量还原（向量由 Python 独立实现生成——
// 与 impacket encryptPassword（impacket/tds.py 0.13.1）完全同构的算法，
// 交叉验证 Go 实现的字节序与运算顺序：swap 与 XOR 0xA5 不可交换，先 XOR 再 swap）。
func TestDeobfuscateTDSPassword(t *testing.T) {
	cases := []struct {
		name string
		obf  string // 混淆字段 hex
		want string // 期望还原明文
	}{
		{"常见爆破密码", "a0a5a1a592a592a5d2a5a6a582a5e3a5b7a5", "P@ssw0rd!"},
		{"字母数字", "b3a5e3a573a533a543a5b6a586a596a5", "admin123"},
		{"混合符号", "90a5b2a563a586a553a586a5f6a597a5e2a5f3a592a5e2a5", "Sql2o25#test"},
	}
	for _, c := range cases {
		obf, err := hex.DecodeString(c.obf)
		if err != nil {
			t.Fatalf("%s: 测试向量 hex 非法: %v", c.name, err)
		}
		got, ok := deobfuscateTDSPassword(obf)
		if !ok {
			t.Errorf("%s: 还原失败（期望成功）", c.name)
			continue
		}
		if got != c.want {
			t.Errorf("%s: 还原错误：got %q want %q", c.name, got, c.want)
		}
	}
}

// TestDeobfuscateTDSPasswordRejects 畸形输入拒绝（非标准客户端垃圾数据
// 不得伪装成"明文"进入字典）。
func TestDeobfuscateTDSPasswordRejects(t *testing.T) {
	cases := []struct {
		name string
		obf  []byte
	}{
		{"空", nil},
		{"奇数字节（非完整 UTF-16 码元）", []byte{0xa0}},
		{"解码后含控制字符", obfuscateTDSForTest("\x01\x02")},
	}
	for _, c := range cases {
		if got, ok := deobfuscateTDSPassword(c.obf); ok {
			t.Errorf("%s: 期望拒绝，got %q", c.name, got)
		}
	}
}

// obfuscateTDSForTest 测试辅助：按 [MS-TDS] 2.2.6.3 混淆 UTF-16LE 明文
// （swap(p) ^ 0xA5，与 impacket encryptPassword 同构）。
func obfuscateTDSForTest(s string) []byte {
	// UTF-16LE 编码
	u := utf16EncodeForTest(s)
	out := make([]byte, 0, len(u)*2)
	for _, code := range u {
		out = append(out, byte(code), byte(code>>8))
	}
	res := make([]byte, len(out))
	for i, b := range out {
		res[i] = (b&0x0F)<<4 | (b&0xF0)>>4 ^ 0xA5
	}
	return res
}

// utf16EncodeForTest rune → UTF-16 码元序列（BMP 内直接映射，够测试用）。
func utf16EncodeForTest(s string) []uint16 {
	rs := []rune(s)
	out := make([]uint16, 0, len(rs))
	for _, r := range rs {
		out = append(out, uint16(r))
	}
	return out
}
