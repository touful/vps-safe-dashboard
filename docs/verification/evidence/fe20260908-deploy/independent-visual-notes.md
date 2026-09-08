# 独立视觉证据说明

- verifier：同一独立验证 Agent 完成；最终候选 `f886bec891ec3754ccaad62fe355a32b8652f49f`。
- 结论：视觉/浏览器运行时子集 `PASS_WITH_NOTES`，不代表完整 API 通过。
- 实测：资产 SHA 正确；1440px 五张 KPI 同行；390px 为 2+2+1；两档视口无页面水平溢出；未处理脚本异常为 0；WS 打开 1 次、收到 170 条消息。
- 原始 JSON 中 `status=FAIL` 的唯一脚本失败是 `networkidle_after_1h`；保留原始结果，不把持续轮询的网络空闲等待失败改写成已执行成功。
- 16 个 HTTP 500/429 仍保留。控制台全部为 HTTP 资源错误，未发现其他控制台错误。
- 原始 JSON 的 image 字段误沿用首轮镜像。verifier 后续真实只读 inspect 得到容器 `6ecad40fae2944e61668e98e4cbf51a481d9696fc52ec23cddfd73235d562106`，实际镜像 `sha256:5201f02d13bd199692d7cfbbd37df41b32f687e62a84d117e34d6e35dcf5c806`，Config.Image 为 `sentry-agent:fe-20260908-f886bec`。
- 收尾时 stage 已被主 Agent 按发布流程停止，verifier 正确观察为 exited；这不是生产容器退出。
- 独立 verifier 未执行生产切换或公网最终验收，后两项证据由主 Agent 提供。
