# 仅替换嵌有前端资源的二进制，沿用已验证的生产系统层。
FROM sentry-agent:rollback-20260908@sha256:46b9425a2baa8741a2a5471c6fd53160ba889f3b5d0ab2b832dc338963bdf1c8
USER root
COPY sentry-agent /usr/local/bin/sentry-agent
RUN chmod 755 /usr/local/bin/sentry-agent && setcap cap_net_bind_service=+ep /usr/local/bin/sentry-agent
USER sentry
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
LABEL sentry.frontend.upstream="91c6c311e9c8caf32a1e20147d95e503216cbdcc"
