#!/usr/bin/env bash
set -Eeuo pipefail

image=${1:?Usage: production_backup_smoke.sh IMAGE_WITH_POSTGRES_PGBACKREST_RESTIC_RCLONE_JQ}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
prefix=thalion-restore-test-$$-$(date +%s)
source_name=$prefix-source
restore_name=$prefix-restore
volume=$(docker volume create --label thalion.test=production-backup "$prefix")
cleanup() {
  local status=$?
  if [[ $status != 0 ]]; then
    docker exec "$source_name" tail -n 50 /work/log >&2 || true
    docker exec "$restore_name" tail -n 50 /restore-test/point/postgres.log >&2 || true
  fi
  docker rm -fv "$source_name" "$restore_name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for container in "$source_name" "$restore_name"; do
  docker run --pull never -d --name "$container" --label thalion.test=production-backup \
    --network none --volume "$volume:/backup-test" --entrypoint sleep "$image" infinity >/dev/null
  docker cp "$root/deploy/backup/thalion-backup.sh" "$container:/tmp/thalion-backup.sh"
done

docker exec -i "$source_name" bash -seu -o pipefail <<'SOURCE'
install -d -m 700 -o postgres -g postgres /backup-test/postgres /backup-test/restic /work /work/state /work/socket /work/live/originals
printf '%s\n' 'synthetic-backup-test-only' > /backup-test/restic-password
chown postgres:postgres /backup-test/restic-password
chmod 600 /backup-test/restic-password
printf '%s\n' '[global]' 'repo1-path=/backup-test/postgres' 'repo1-retention-full=2' 'start-fast=y' \
  '[thalion]' 'pg1-path=/work/pgdata' 'pg1-socket-path=/work/socket' > /etc/pgbackrest.conf
printf '%s\n' '[live]' 'type = alias' 'remote = /work/live' > /work/rclone.conf
export PGHOST=/work/socket PGDATABASE=thalion_rehearsal RCLONE_CONFIG=/work/rclone.conf
export RESTIC_REPOSITORY=/backup-test/restic RESTIC_PASSWORD_FILE=/backup-test/restic-password
export THALION_BACKUP_STANZA=thalion THALION_BACKUP_STATE_DIR=/work/state THALION_BACKUP_OBJECT_REMOTE=live:originals

runuser -u postgres -- initdb -D /work/pgdata --auth-local=trust --auth-host=reject --no-locale >/dev/null
printf '%s\n' "listen_addresses = ''" "unix_socket_directories = '/work/socket'" 'archive_mode = on' \
  "archive_command = 'pgbackrest --stanza=thalion archive-push %p'" >> /work/pgdata/postgresql.conf
runuser -u postgres -- pg_ctl -D /work/pgdata -l /work/log -w start
runuser -u postgres -- pgbackrest --stanza=thalion stanza-create
runuser -u postgres -- restic init
runuser -u postgres -- createdb "$PGDATABASE"
key=$(printf '%064d' 1)
printf 'synthetic original content\n' > "/work/live/originals/$key"
digest=$(sha256sum "/work/live/originals/$key" | cut -d ' ' -f 1)
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -c "CREATE SCHEMA thalion;
CREATE TABLE thalion.asset (storage_kind text NOT NULL, storage_key text NOT NULL, content_digest bytea NOT NULL);
INSERT INTO thalion.asset VALUES ('https_object_store', '$key', decode('$digest', 'hex'));
CREATE TABLE public.recovery_evidence (name text NOT NULL);
INSERT INTO public.recovery_evidence VALUES ('before-backup');"
runuser -u postgres -- bash /tmp/thalion-backup.sh backup
runuser -u postgres -- pgbackrest --stanza=thalion --output=json info | jq -er '.[0].backup[-1].label' > /backup-test/label
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -c "INSERT INTO public.recovery_evidence VALUES ('after-backup'); SELECT pg_switch_wal();"
runuser -u postgres -- pgbackrest --stanza=thalion check
runuser -u postgres -- pg_ctl -D /work/pgdata -m fast -w stop
SOURCE

docker exec -i "$restore_name" bash -seu -o pipefail <<'RESTORE'
install -d -m 700 -o postgres -g postgres /restore-test
printf '%s\n' '[global]' 'repo1-path=/backup-test/postgres' '[thalion]' > /etc/pgbackrest.conf
export PGDATABASE=thalion_rehearsal RESTIC_REPOSITORY=/backup-test/restic RESTIC_PASSWORD_FILE=/backup-test/restic-password
export THALION_BACKUP_STANZA=thalion THALION_RESTORE_ISOLATED=1
label=$(cat /backup-test/label)
runuser -u postgres -- bash /tmp/thalion-backup.sh restore "$label" /restore-test/point
point=/restore-test/point
test "$(cat "$point/bundle/objects/$(printf '%064d' 1)")" = 'synthetic original content'
test ! -e "$point/pgdata/postmaster.pid"
runuser -u postgres -- pg_ctl -D "$point/pgdata" -l /restore-test/verify.log -o "-c config_file=$point/rehearsal.conf" -w start
trap 'runuser -u postgres -- pg_ctl -D "$point/pgdata" -m fast -w stop >/dev/null' EXIT
test "$(runuser -u postgres -- psql -X -qAt --host="$point/socket" -c 'TABLE public.recovery_evidence')" = before-backup
test "$(runuser -u postgres -- psql -X -qAt --host="$point/socket" -c "SELECT current_setting('thalion.restore_rehearsal')")" = isolated
RESTORE

printf '%s\n' 'PASS: WAL archive, paired object snapshot and restore verified across two isolated containers.'
