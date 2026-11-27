#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "用法: bash scripts/linux_offline_smoke.sh APP.whl REQUIREMENTS.txt WHEELHOUSE"
}

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -ne 3 ]]; then
  usage >&2
  exit 2
fi

wheel="$1"
requirements="$2"
wheelhouse="$3"
if [[ ! -f "$wheel" || "${wheel##*/}" != thalion_enterprise_kb-*.whl ||
      ! -s "$requirements" || ! -d "$wheelhouse" ]]; then
  echo "FAIL 请提供 Thalion wheel、锁定依赖清单和本地 wheelhouse。" >&2
  exit 2
fi

python_image="python@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144"
postgres_image="pgvector/pgvector@sha256:c29f30688a9ad961691bdf0ec1650717cc132a5814619d80f80463d6e4c42e47"
for image in "$python_image" "$postgres_image"; do
  if ! docker image inspect "$image" --format '{{.Id}} {{.Os}}/{{.Architecture}}'; then
    echo "FAIL 请先准备固定镜像：${image}。预检不拉取镜像。" >&2
    exit 1
  fi
done

database=""
app=""
cleanup() {
  if [[ -n "$app" ]]; then
    docker rm -fv "$app" >/dev/null || true
  fi
  if [[ -n "$database" ]]; then
    docker rm -fv "$database" >/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

database="$(docker create --pull never --network none --label thalion.test=linux-offline \
  --tmpfs /var/lib/postgresql:size=256m \
  -e POSTGRES_PASSWORD=offline-smoke -e POSTGRES_DB=thalion_smoke "$postgres_image")"
docker start "$database" >/dev/null
for attempt in {1..60}; do
  if docker exec "$database" pg_isready -q -h 127.0.0.1 -U postgres -d thalion_smoke -t 1 2>/dev/null; then
    break
  fi
  if [[ "$attempt" -eq 60 || "$(docker inspect --format '{{.State.Running}}' "$database")" != true ]]; then
    echo "FAIL 临时 PostgreSQL 未就绪。" >&2
    docker logs "$database" >&2
    exit 1
  fi
  sleep 1
done

app="$(docker create --pull never --network "container:$database" --label thalion.test=linux-offline \
  --read-only --tmpfs /tmp:exec,size=384m \
  -e THALION_DATABASE_URL=postgresql://postgres:offline-smoke@127.0.0.1:5432/thalion_smoke \
  "$python_image" sleep infinity)"
docker start "$app" >/dev/null
docker exec "$app" mkdir /tmp/wheels
tar --no-xattrs -cf - -C "$wheelhouse" . | docker exec -i "$app" tar -xf - -C /tmp/wheels
docker exec -i "$app" bash -c 'cat > /tmp/requirements.txt' < "$requirements"
docker exec -i "$app" bash -c 'cat > "$1"' -- "/tmp/${wheel##*/}" < "$wheel"
docker exec -i "$app" bash -se -- "/tmp/${wheel##*/}" <<'BASH'
set -euo pipefail
umask 077
python -m venv /tmp/thalion-env
export PATH="/tmp/thalion-env/bin:$PATH"
python -I --version
python -I -m pip --isolated --disable-pip-version-check install --quiet --no-cache-dir \
  --no-index --find-links /tmp/wheels --require-hashes --only-binary=:all: -r /tmp/requirements.txt
python -I -m pip --isolated --disable-pip-version-check install --quiet --no-cache-dir --no-index --no-deps "$1"
python -I -m pip --isolated --disable-pip-version-check check
python -I -c 'import pypdfium2'
python -I -c 'from enterprise_kb.ports import OidcJwksIdentityVerifier, HttpSourceAuthorityAdapter, HttpSourceConnectorAdapter, HttpModelGatewayAdapter, HttpSecurityAuditLogAdapter'
thalion-db upgrade
thalion-parse --help >/dev/null
thalion-worker --help >/dev/null
THALION_MODE=production \
THALION_BUSINESS_TIMEZONE=Asia/Shanghai \
THALION_DATABASE_URL_REF=env:THALION_DATABASE_URL \
THALION_ALLOWED_HOSTS=kb.corp.example \
THALION_OIDC_ISSUER=https://idp.corp.example \
THALION_OIDC_AUDIENCE=thalion-kb \
THALION_OIDC_JWKS_URL=https://idp.corp.example/.well-known/jwks.json \
THALION_SOURCE_AUTHORITY_ENDPOINT=https://source-auth.corp.example/v1/check \
THALION_SOURCE_AUTHORITY_CREDENTIAL_REF=env:THALION_SMOKE_DUMMY_SECRET \
THALION_SOURCE_AUTHORITY_REF=00000000-0000-4000-8000-000000000901 \
THALION_OBJECT_STORAGE_ENDPOINT=https://object.corp.example \
THALION_OBJECT_STORAGE_BUCKET=thalion-originals-smoke \
THALION_OBJECT_STORAGE_CREDENTIAL_REF=env:THALION_SMOKE_DUMMY_SECRET \
THALION_SECURITY_AUDIT_ENDPOINT=https://audit.corp.example/v1/events \
THALION_SECURITY_AUDIT_CREDENTIAL_REF=env:THALION_SMOKE_DUMMY_SECRET \
THALION_SECURITY_AUDIT_LOG_REF=00000000-0000-4000-8000-000000000902 \
THALION_SMOKE_DUMMY_SECRET=smoke-placeholder-not-live \
  thalion-serve --mode production --check-config | python -I -c '
import json, sys
data = json.load(sys.stdin)
assert data["status"] == "ok" and data["mode"] == "production", data
assert "0111_production_mode_admission" in data["schema_revisions"], data
for port in ("identity", "source_authority", "object_storage", "security_audit_log"):
    assert data["ports"][port] == "production_approved", data
print("PASS thalion-serve --mode production --check-config")
'
THALION_MODE=production \
THALION_BUSINESS_TIMEZONE=Asia/Shanghai \
THALION_DATABASE_URL_REF=env:THALION_DATABASE_URL \
THALION_ALLOWED_HOSTS=kb.corp.example \
THALION_OIDC_ISSUER=https://idp.corp.example \
THALION_OIDC_AUDIENCE=thalion-kb \
THALION_OIDC_JWKS_URL=https://idp.corp.example/.well-known/jwks.json \
THALION_SOURCE_AUTHORITY_ENDPOINT=https://source-auth.corp.example/v1/check \
THALION_SOURCE_AUTHORITY_CREDENTIAL_REF=env:THALION_SMOKE_DUMMY_SECRET \
THALION_SOURCE_AUTHORITY_REF=00000000-0000-4000-8000-000000000901 \
THALION_OBJECT_STORAGE_ENDPOINT=https://object.corp.example \
THALION_OBJECT_STORAGE_BUCKET=thalion-originals-smoke \
THALION_OBJECT_STORAGE_CREDENTIAL_REF=env:THALION_SMOKE_DUMMY_SECRET \
THALION_SECURITY_AUDIT_ENDPOINT=https://audit.corp.example/v1/events \
THALION_SECURITY_AUDIT_CREDENTIAL_REF=env:THALION_SMOKE_DUMMY_SECRET \
THALION_SECURITY_AUDIT_LOG_REF=00000000-0000-4000-8000-000000000902 \
THALION_SMOKE_DUMMY_SECRET=smoke-placeholder-not-live \
  thalion-worker --mode production --check-config | python -I -c '
import json, sys
data = json.load(sys.stdin)
assert data["status"] == "ok" and data["mode"] == "production" and data["admission"] == "production_approved", data
assert data["strict_audit_sink"] is True, data
print("PASS thalion-worker --mode production --check-config")
'
mkdir -p /tmp/profile/originals
printf '[]\n' >/tmp/profile/credentials.json
printf '{}\n' >/tmp/profile/source-grants.json
thalion-serve --profile /tmp/profile &
server="$!"
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true' EXIT
python -I - <<'PYTHON'
from http.client import HTTPConnection
from time import monotonic, sleep


def status(method, route):
    connection = HTTPConnection("127.0.0.1", 8765, timeout=2)
    try:
        connection.request(method, route)
        return connection.getresponse().status
    finally:
        connection.close()


deadline = monotonic() + 20
while True:
    try:
        portal = status("GET", "/")
        break
    except ConnectionRefusedError:
        if monotonic() >= deadline:
            raise SystemExit("FAIL 合成服务未在回环地址就绪。") from None
        sleep(0.1)

for route, actual, expected in (
    ("/", portal, 200),
    ("/manage/catalog", status("GET", "/manage/catalog"), 200),
    ("/manage/glossary", status("GET", "/manage/glossary"), 200),
    ("/manage/effectivity", status("GET", "/manage/effectivity"), 200),
    ("/manage/lifecycle", status("GET", "/manage/lifecycle"), 200),
    ("/manage/archives", status("GET", "/manage/archives"), 200),
    ("/auth/oidc/status", status("GET", "/auth/oidc/status"), 200),
    ("/v1/search", status("POST", "/v1/search"), 401),
    ("/mcp", status("POST", "/mcp"), 401),
):
    if actual != expected:
        raise SystemExit(f"FAIL {route}: HTTP {actual}，预期 {expected}。")
    print(f"PASS {route}: HTTP {actual}")
PYTHON
BASH

docker exec "$database" psql -U postgres -d thalion_smoke -Atqc \
  "SELECT 'PostgreSQL ' || current_setting('server_version') || '; pgvector ' || extversion FROM pg_extension WHERE extname = 'vector'"
echo "PASS Linux 离线安装与启动预检"
