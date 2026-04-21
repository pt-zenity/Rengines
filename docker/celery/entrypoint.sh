#!/bin/bash
# reNgine Celery worker entrypoint
# Compatible with Celery 5.6.x + gevent pool

print_msg() {
  printf "\r\n"
  printf "========================================\r\n"
  printf "$1\r\n"
  printf "========================================\r\n\r\n"
}

RENGINE_FOLDER="/home/$USERNAME/rengine"
MAX_CONCURRENCY=${MAX_CONCURRENCY:-10}
MIN_CONCURRENCY=${MIN_CONCURRENCY:-2}
CELERY_LOGLEVEL=${CELERY_LOGLEVEL:-info}

# ── Database bootstrap ────────────────────────────────────────────────────────
print_msg "Generate Django migrations files"
poetry run -C $RENGINE_FOLDER python3 manage.py makemigrations

print_msg "Migrate database"
poetry run -C $RENGINE_FOLDER python3 manage.py migrate

print_msg "Collect static files"
poetry run -C $RENGINE_FOLDER python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
print_msg "Load default engines"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddefaultengines

print_msg "Load default keywords"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata \
    fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel

print_msg "Load default external tools"
poetry run -C $RENGINE_FOLDER python3 manage.py loaddata \
    fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

# ── Worker command builder ────────────────────────────────────────────────────
worker_command() {
    local queue=$1
    local worker_name=$2

    if [ "$CELERY_DEBUG" = "1" ]; then
        # Debug mode: solo pool + file watcher for hot-reload
        echo "watchmedo auto-restart --recursive --pattern=\"*.py\" \
            --directory=\"$RENGINE_FOLDER\" -- \
            poetry run -C $RENGINE_FOLDER celery -A reNgine worker \
            --pool=solo \
            --loglevel=$CELERY_LOGLEVEL \
            -Q $queue -n ${worker_name}@%h"
    else
        # Production mode: gevent pool (Celery 5.6 compatible)
        #
        # --pool=gevent          : async I/O pool, ideal for network-heavy scan tasks
        # --autoscale=MAX,MIN    : scale greenlets between MIN and MAX per worker process
        # --without-heartbeat    : disable heartbeat thread (not needed with gevent)
        # --without-mingle       : skip worker synchronisation on startup (faster boot)
        # --without-gossip       : disable worker gossip (reduces Redis chatter)
        # --prefetch-multiplier=1: fetch 1 task at a time (set in settings, repeated here)
        # --max-tasks-per-child  : handled via CELERY_WORKER_MAX_TASKS_PER_CHILD in settings
        echo "poetry run -C $RENGINE_FOLDER celery -A reNgine worker \
            --pool=gevent \
            --loglevel=$CELERY_LOGLEVEL \
            --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY \
            --without-heartbeat \
            --without-mingle \
            --without-gossip \
            -Q $queue -n ${worker_name}@%h"
    fi
}

# ── Queue definitions ─────────────────────────────────────────────────────────
# Each queue gets its own worker process for isolation.
# Format: "queue_name:worker_name"
queues=(
    "orchestrator_queue:orchestrator_worker"
    "io_queue:io_worker"
    "run_command_queue:run_command_worker"
    "group_queue:group_worker"
    "cpu_queue:cpu_worker"
    "report_queue:report_worker"
    "send_notif_queue:send_notif_worker"
)

# ── Launch all workers ────────────────────────────────────────────────────────
print_msg "Starting ${#queues[@]} Celery workers (Celery 5.6.x / gevent)"

commands=""
for queue in "${queues[@]}"; do
    IFS=':' read -r queue_name worker_name <<< "$queue"
    commands+="$(worker_command "$queue_name" "$worker_name") &"$'\n'
done

eval "$commands"

wait

exec "$@"
