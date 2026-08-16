# sentry-agent 多阶段构建（方案 6.4.1 落地）
# ===== builder 阶段：交叉编译静态二进制 =====
# VS-05（AUD-VPS-001 P1-5）：锁定 Go patch 版本消除浮动标签（golang:1.26-alpine）构建不确定性；
# 1.26.2~1.26.5 存在标准库安全漏洞（CVE-2026-33814 net/http HTTP/2 无限循环、
# CVE-2026-56860 net/url 二次复杂度、CVE-2026-56862 TLS KeyUpdate），1.26.6 已修复。
# go.mod 保持 go 1.26.2（本机工具链约束）；构建产物版本以 builder 镜像为准，
# 后续升级 Go 时须同步更新此处版本与 go.mod 指令。
FROM golang:1.26.6-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 交叉编译（本地 x86_64；目标 VPS 如为 arm64 需改 GOARCH，见部署手册）
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/sentry-agent ./cmd/sentry-agent

# ===== 运行时阶段 =====
# 基础层选择说明（R-01 修订，DEV-008 reviewer）：alpine 无 systemd 包（journalctl 不可用），
# 而默认配置 ssh.source=journald / fw.source=journald-kernel 依赖 journalctl 二进制；
# 改用 debian:bookworm-slim + systemd 包（提供 journalctl）+ iproute2（ss）——
# journal 挂载路径与代码默认 /var/log/journal 对齐（compose 覆盖挂载宿主 journal）。
# 镜像大小实测（DEV-008）：压缩后 <50MB 目标复测见方案 6.4.1。
FROM debian:bookworm-slim
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends systemd iproute2 ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m -d /home/sentry -s /usr/sbin/nologin sentry
COPY --from=builder /out/sentry-agent /usr/local/bin/sentry-agent
USER sentry
EXPOSE 8080
# 冒烟验证发现（DEV-008）：默认 -config config.json 为相对路径（容器工作目录 /），
# 挂载配置位于 /etc/sentry-agent/config.json——ENTRYPOINT 显式指定。
ENTRYPOINT ["/usr/local/bin/sentry-agent", "-config", "/etc/sentry-agent/config.json"]
# 配置：/etc/sentry-agent/config.json（只读挂载）
# 数据：/var/lib/sentry-agent（卷挂载，rw）
# 运行方式（--network host + --cap-add=NET_ADMIN）见 docker-compose.yml 与部署手册
