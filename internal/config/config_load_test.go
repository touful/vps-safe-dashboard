// 真实配置文件加载验证（DEV-042）：config.example.json / deploy/config.json 可加载
// 且含新增 ssh_learn_* 配置项（验收标准 10：config.example.json 和 deploy/config.json 同步更新）。
package config

import (
	"os"
	"testing"
)

// TestLoadExampleConfig config.example.json 可加载且含 ssh_learn_* 配置。
func TestLoadExampleConfig(t *testing.T) {
	path := "../../config.example.json"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("配置文件不存在: %s", path)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载 %s 失败: %v", path, err)
	}
	if !cfg.FW.SSHLearnEnabled {
		t.Error("config.example.json 应启用 ssh_learn_enabled")
	}
	if cfg.FW.SSHLearnWindowDays != 30 || cfg.FW.SSHLearnIntervalMin != 10 {
		t.Errorf("ssh_learn 配置错误: window=%d interval=%d",
			cfg.FW.SSHLearnWindowDays, cfg.FW.SSHLearnIntervalMin)
	}
}

// TestLoadDeployConfig deploy/config.json 可加载且含 ssh_learn_* 配置。
func TestLoadDeployConfig(t *testing.T) {
	path := "../../deploy/config.json"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("配置文件不存在: %s", path)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载 %s 失败: %v", path, err)
	}
	if !cfg.FW.SSHLearnEnabled {
		t.Error("deploy/config.json 应启用 ssh_learn_enabled")
	}
	if cfg.FW.SSHLearnWindowDays != 30 || cfg.FW.SSHLearnIntervalMin != 10 {
		t.Errorf("ssh_learn 配置错误: window=%d interval=%d",
			cfg.FW.SSHLearnWindowDays, cfg.FW.SSHLearnIntervalMin)
	}
}
