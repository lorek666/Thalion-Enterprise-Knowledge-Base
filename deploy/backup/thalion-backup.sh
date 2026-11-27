#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

read_configuration() {
  stanza=${THALION_BACKUP_STANZA:-}
  database=${PGDATABASE:-}
  [[ $stanza =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$ ]] || fail 'Set THALION_BACKUP_STANZA explicitly.'
  [[ $database =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,62}$ ]] || fail 'Set PGDATABASE to the Thalion database name.'
  [[ -n ${RESTIC_REPOSITORY:-} && -n ${RESTIC_PASSWORD_FILE:-} ]] || fail 'Set RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE.'
  if [[ -n ${PGBACKREST_REPO1_CIPHER_PASS_FILE:-} ]]; then
    local pass_file=${PGBACKREST_REPO1_CIPHER_PASS_FILE}
    [[ $pass_file = /* && -f $pass_file && ! -L $pass_file && -O $pass_file ]] || fail 'Set PGBACKREST_REPO1_CIPHER_PASS_FILE to a private file owned by the backup user.'
    [[ $(stat -c '%a' "$pass_file") == 600 ]] || fail 'The pgBackRest cipher passphrase file must have mode 0600.'
    PGBACKREST_REPO1_CIPHER_PASS=$(<"$pass_file")
    export PGBACKREST_REPO1_CIPHER_PASS
    unset PGBACKREST_REPO1_CIPHER_PASS_FILE
  fi
}

backup_label() {
  pgbackrest --stanza="$stanza" --repo=1 --output=json info |
    jq -er '.[0].backup[-1] | select(.error != true and .type == "full") | .label'
}

asset_manifest() {
  "$@" -c "SELECT storage_key, encode(content_digest, 'hex') FROM thalion.asset
    WHERE storage_kind = 'https_object_store' ORDER BY storage_key COLLATE \"C\""
}

verify_objects() {
  local bundle=$1
  [[ -d $bundle/objects && -f $bundle/originals.tsv ]] || fail 'Originals snapshot is incomplete.'
  if [[ -s $bundle/originals.tsv ]]; then
    awk -F '\t' 'NF != 2 || length($1) != 64 || length($2) != 64 || $1 !~ /^[0-9a-f]+$/ || $2 !~ /^[0-9a-f]+$/ { exit 1 } { print $2 "  " $1 }' \
      "$bundle/originals.tsv" | (cd "$bundle/objects" && sha256sum --check --strict --status) || fail 'An original is missing or failed SHA-256 verification.'
  fi
}

backup() {
  read_configuration
  local state=${THALION_BACKUP_STATE_DIR:-} remote=${THALION_BACKUP_OBJECT_REMOTE:-}
  [[ $state = /* && -d $state && ! -L $state && -O $state ]] || fail 'Set THALION_BACKUP_STATE_DIR to a private directory owned by the backup user.'
  [[ $(stat -c '%a' "$state") == 700 ]] || fail 'The backup state directory must have mode 0700.'
  [[ $remote =~ ^[A-Za-z0-9_-]+:[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || fail 'Set THALION_BACKUP_OBJECT_REMOTE to a named rclone remote and a bucket or prefix.'
  [[ ${PGHOST:-} = /* && -z ${PGHOSTADDR:-} ]] || fail 'Backup requires an explicit local PostgreSQL socket in PGHOST.'
  exec 9>"$state/backup.lock"
  flock -n 9 || fail 'A backup job is already running.'
  backup_stage=$(mktemp -d "$state/point.XXXXXXXX")
  trap 'rm -rf -- "$backup_stage"' EXIT
  mkdir "$backup_stage/objects"

  local -a sql=(psql -X --no-password -v ON_ERROR_STOP=1 -qAt -F $'\t' --host="$PGHOST" --dbname="$database")
  local data_directory previous label
  data_directory=$("${sql[@]}" -c 'SHOW data_directory')
  [[ $data_directory = /* && -d $data_directory ]] || fail 'Could not identify the local PostgreSQL data directory.'
  asset_manifest "${sql[@]}" > "$backup_stage/originals.tsv"
  previous=$(backup_label || true)
  pgbackrest --stanza="$stanza" --pg1-path="$data_directory" check
  pgbackrest --stanza="$stanza" --repo=1 --pg1-path="$data_directory" --type=full backup
  label=$(backup_label)
  [[ $label =~ ^[0-9]{8}-[0-9]{6}F$ && $label != "$previous" ]] || fail 'No new full PostgreSQL backup was confirmed.'

  if [[ -s $backup_stage/originals.tsv ]]; then
    cut -f 1 "$backup_stage/originals.tsv" > "$backup_stage/keys"
    rclone copy "$remote" "$backup_stage/objects" --files-from-raw "$backup_stage/keys"
    rm -- "$backup_stage/keys"
  fi
  verify_objects "$backup_stage"
  asset_manifest "${sql[@]}" | cmp -s "$backup_stage/originals.tsv" - || fail 'Originals changed during backup; no paired recovery point was published.'
  (cd "$backup_stage" && restic backup --tag "thalion-$label" objects originals.tsv)
  printf 'PASS: paired recovery point %s\n' "$label"
}

restore() {
  local label=${1:-} target=${2:-}
  [[ $label =~ ^[0-9]{8}-[0-9]{6}F$ ]] || fail 'Restore requires an explicit backup label, not latest.'
  [[ $target =~ ^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$ && ! -e $target && ! -L $target ]] || fail 'Restore requires a new absolute directory.'
  [[ ${THALION_RESTORE_ISOLATED:-} == 1 ]] || fail 'Run on an isolated recovery host and set THALION_RESTORE_ISOLATED=1.'
  read_configuration
  local snapshot
  snapshot=$(restic snapshots --tag "thalion-$label" --json | jq -er 'select(length == 1) | .[0].id')
  [[ $snapshot =~ ^[a-f0-9]{64}$ ]] || fail 'Exactly one originals snapshot must match the database backup.'

  mkdir -m 700 -- "$target"
  mkdir -m 700 -- "$target/pgdata" "$target/tablespaces" "$target/socket"
  restic restore "$snapshot" --target "$target/bundle" --verify
  verify_objects "$target/bundle"
  pgbackrest --stanza="$stanza" --repo=1 --set="$label" --pg1-path="$target/pgdata" \
    --tablespace-map-all="$target/tablespaces" --type=none --archive-mode=off restore

  local restore_user=${THALION_RESTORE_DB_USER:-postgres}
  [[ $restore_user =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,62}$ ]] || fail 'Invalid THALION_RESTORE_DB_USER.'
  printf 'local all all trust\n' > "$target/pg_hba.conf"
  printf '%s\n' \
    "listen_addresses = ''" \
    "unix_socket_directories = '$target/socket'" \
    'unix_socket_permissions = 0700' \
    "hba_file = '$target/pg_hba.conf'" \
    'archive_mode = off' \
    'hot_standby = off' \
    'autovacuum = off' \
    "restore_command = 'pgbackrest --stanza=$stanza --repo=1 --pg1-path=$target/pgdata archive-get %f \"%p\"'" \
    "recovery_target = 'immediate'" \
    "recovery_target_action = 'promote'" \
    "recovery_target_timeline = 'current'" > "$target/rehearsal.conf"
  [[ ! -L $target/pgdata/postgresql.auto.conf && ! -e $target/pgdata/standby.signal ]] || fail 'Unexpected recovered cluster configuration.'
  truncate -s 0 -- "$target/pgdata/postgresql.auto.conf"
  touch -- "$target/pgdata/recovery.signal"

  restore_pgdata=$target/pgdata
  trap 'pg_ctl -D "$restore_pgdata" -m fast -w stop >/dev/null 2>&1 || true' EXIT
  pg_ctl -D "$restore_pgdata" -l "$target/postgres.log" -o "-c config_file='$target/rehearsal.conf'" -t 180 -w start
  unset PGHOSTADDR PGSERVICE PGSERVICEFILE PGOPTIONS
  local -a sql=(psql -X --no-password -v ON_ERROR_STOP=1 -qAt -F $'\t' --host="$target/socket" --port=5432 --username="$restore_user" --dbname="$database")
  local deadline=$((SECONDS + 180))
  until [[ $(PGCONNECT_TIMEOUT=2 "${sql[@]}" -c 'SELECT NOT pg_is_in_recovery()' 2>/dev/null) == t ]]; do
    if (( SECONDS >= deadline )) || ! pg_ctl -D "$restore_pgdata" status >/dev/null 2>&1; then
      fail "Restored database did not become writable; see $target/postgres.log."
    fi
    sleep 1
  done
  "${sql[@]}" -c "ALTER DATABASE \"$database\" SET thalion.restore_rehearsal = 'isolated'"
  asset_manifest "${sql[@]}" | cmp -s "$target/bundle/originals.tsv" - || fail 'The restored database and originals do not match.'
  pg_ctl -D "$restore_pgdata" -m fast -t 60 -w stop
  trap - EXIT
  printf 'PASS: verified isolated recovery point %s\n' "$label"
}

case ${1:-} in
  backup) [[ $# == 1 ]] || fail 'Usage: thalion-backup.sh backup'; backup ;;
  restore) [[ $# == 3 ]] || fail 'Usage: thalion-backup.sh restore LABEL NEW_DIRECTORY'; restore "$2" "$3" ;;
  *) fail 'Usage: thalion-backup.sh {backup|restore LABEL NEW_DIRECTORY}' ;;
esac
