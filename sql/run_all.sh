#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "需要 Docker 才能运行夹具。" >&2
  exit 1
fi

postgres_image="${POSTGRES_IMAGE:-postgres@sha256:ff64c9e3bdf8e2120107d3559de8db314e8305f7e38c5105903c6295876738ff}"
if ! docker image inspect "$postgres_image" >/dev/null 2>&1; then
  echo "拉取 $postgres_image ..." >&2
  docker pull "$postgres_image" >/dev/null
fi

suites=(lint version gap compile tree evidence temporal ingest)
name=""
log=""

cleanup() {
  if [ -n "$log" ]; then
    rm -f "$log"
  fi
  if [ -n "$name" ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "PostgreSQL image: $postgres_image"
docker image inspect "$postgres_image" --format 'Image ID: {{.Id}}; platform: {{.Os}}/{{.Architecture}}'

for suite in "${suites[@]}"; do
  name="kb-sql-${suite}-$$-${RANDOM}"
  docker run -d --rm --network none --name "$name" \
    -e POSTGRES_PASSWORD=pg -e POSTGRES_DB="$suite" \
    "$postgres_image" >/dev/null

  ready=0
  for _ in $(seq 1 60); do
    if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres -d "$suite" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    echo "FAIL $suite: PostgreSQL 未就绪" >&2
    exit 1
  fi
  if [ "$suite" = "lint" ]; then
    docker exec "$name" psql -U postgres -d "$suite" -Atqc 'show server_version'
  fi

  vars=(-v suite="$suite")
  if [ "$suite" = "lint" ]; then
    vars+=(-v run_id=1 -v space_id=1 -v biz_date=2026-11-20)
  fi

  for file in sql/"$suite"/*.sql; do
    log="$(mktemp)"
    if ! docker exec -i "$name" psql -U postgres -d "$suite" -q \
        -v ON_ERROR_STOP=1 "${vars[@]}" -f - < "$file" >/dev/null 2>"$log"; then
      echo "FAIL $suite / $(basename "$file")" >&2
      cat "$log" >&2
      exit 1
    fi
    rm -f "$log"
    log=""
  done

  echo "PASS $suite"
  docker rm -f "$name" >/dev/null
  name=""
done

echo "全部夹具通过"
