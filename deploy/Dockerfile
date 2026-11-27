# Thalion 企业知识库离线最小运行镜像（基于固定摘要的 Python 3.14-slim）
# 构建前请在构建上下文中准备：
#   - wheels/          目标架构的完整离线 wheelhouse
#   - requirements.txt 带 sha256 校验值的锁定依赖清单（不含项目自身）
#   - dist/thalion_enterprise_kb-*.whl 应用 wheel
#
# 离线构建示例：
#   docker build --pull=false --network=none -f deploy/Dockerfile \
#     -t thalion-enterprise-kb:local /path/to/offline-build-context

FROM python@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144 AS builder

ARG WHEELHOUSE_DIR=wheels
ARG REQUIREMENTS_FILE=requirements.txt
ARG APP_DIST_DIR=dist

WORKDIR /build
COPY ${WHEELHOUSE_DIR} /build/wheels
COPY ${REQUIREMENTS_FILE} /build/requirements.txt
COPY ${APP_DIST_DIR} /build/dist

RUN set -eu; \
    umask 022; \
    python -I -m venv /opt/thalion-venv; \
    /opt/thalion-venv/bin/python -I -m pip --isolated --disable-pip-version-check install \
        --no-cache-dir --no-index --find-links /build/wheels --require-hashes --only-binary=:all: \
        -r /build/requirements.txt; \
    /opt/thalion-venv/bin/python -I -m pip --isolated --disable-pip-version-check install \
        --no-cache-dir --no-index --no-deps /build/dist/thalion_enterprise_kb-*.whl; \
    /opt/thalion-venv/bin/python -I -m pip --isolated --disable-pip-version-check check

FROM python@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144

ENV PATH="/opt/thalion-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN set -eu; \
    groupadd --gid 10001 thalion; \
    useradd --uid 10001 --gid 10001 --home-dir /var/lib/thalion \
        --create-home --shell /usr/sbin/nologin thalion; \
    chmod 0700 /var/lib/thalion

COPY --from=builder --chown=root:root /opt/thalion-venv /opt/thalion-venv

WORKDIR /var/lib/thalion
USER thalion

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-I", "-m", "enterprise_kb.healthcheck"]

# 默认启动合成资料本地取证服务；可通过覆盖 entrypoint 运行 thalion-db upgrade / thalion-parse / --check-config
ENTRYPOINT ["thalion-serve"]
CMD ["--help"]
