import mimetypes
import os
from pathlib import Path

import environ

from reNgine.init import first_run
from reNgine.utilities.logging import RengineTaskFormatter


env = environ.FileAwareEnv()

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       RENGINE CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Root env vars
RENGINE_HOME = env("RENGINE_HOME", default=str(Path.home() / "rengine"))
RENGINE_RESULTS = env("RENGINE_RESULTS", default=str(Path.home() / "scan_results"))
RENGINE_CUSTOM_ENGINES = env("RENGINE_CUSTOM_ENGINES", default=str(Path.home() / "custom_engines"))
RENGINE_WORDLISTS = env("RENGINE_WORDLISTS", default=str(Path.home() / "wordlists"))
RENGINE_TOOL_PATH = env("RENGINE_TOOL_PATH", default=str(Path.home() / "tools"))
RENGINE_TOOL_GITHUB_PATH = env("RENGINE_TOOL_GITHUB_PATH", default=str(Path(RENGINE_TOOL_PATH) / ".github"))

RENGINE_CACHE_ENABLED = env.bool("RENGINE_CACHE_ENABLED", default=False)
RENGINE_RECORD_ENABLED = env.bool("RENGINE_RECORD_ENABLED", default=True)
RENGINE_RAISE_ON_ERROR = env.bool("RENGINE_RAISE_ON_ERROR", default=False)

with open(Path(RENGINE_HOME) / "reNgine" / "version.txt", "r", encoding="utf-8") as f:
    RENGINE_CURRENT_VERSION = f.read().strip()

# Debug env vars
UI_DEBUG = bool(int(os.environ.get("UI_DEBUG", "0")))
UI_ERROR_LOGGING = bool(int(os.environ.get("UI_ERROR_LOGGING", "0")))
UI_REMOTE_DEBUG = bool(int(os.environ.get("UI_REMOTE_DEBUG", "0")))
UI_REMOTE_DEBUG_PORT = int(os.environ.get("UI_REMOTE_DEBUG_PORT", 5678))
CELERY_DEBUG = bool(int(os.environ.get("CELERY_DEBUG", "0")))
CELERY_REMOTE_DEBUG = bool(int(os.environ.get("CELERY_REMOTE_DEBUG", "0")))
CELERY_REMOTE_DEBUG_PORT = int(os.environ.get("CELERY_REMOTE_DEBUG_PORT", 5679))

# Common env vars
DEBUG = env.bool("UI_DEBUG", default=False)
DOMAIN_NAME = env("DOMAIN_NAME", default="localhost:8000")
TEMPLATE_DEBUG = env.bool("TEMPLATE_DEBUG", default=UI_DEBUG)
DISABLE_TEMPLATE_CACHE = env.bool("DISABLE_TEMPLATE_CACHE", default=UI_DEBUG)
SECRET_FILE = os.path.join(RENGINE_HOME, "secret")
DEFAULT_RATE_LIMIT = env.int("DEFAULT_RATE_LIMIT", default=150)  # requests / second
DEFAULT_HTTP_TIMEOUT = env.int("DEFAULT_HTTP_TIMEOUT", default=5)  # seconds
DEFAULT_RETRIES = env.int("DEFAULT_RETRIES", default=1)
DEFAULT_THREADS = env.int("DEFAULT_THREADS", default=30)
DEFAULT_GET_LLM_REPORT = env.bool("DEFAULT_GET_LLM_REPORT", default=True)

# Globals
ALLOWED_HOSTS = ["*"]
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# CSRF Configuration - compatible with IP-based deployments
CSRF_TRUSTED_ORIGINS = [
    f"http://{DOMAIN_NAME}",
    f"https://{DOMAIN_NAME}",
    "http://localhost",
    "https://localhost",
    "http://localhost:8000",
    "https://localhost:8000",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "http://127.0.0.1:8000",
    "https://127.0.0.1:8000",
]

# CSRF cookie settings - standard cookie mode (no session storage)
# CSRF_USE_SESSIONS intentionally NOT set (defaults to False)
# CSRF_COOKIE_HTTPONLY must be False so JavaScript can read the csrftoken cookie
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_AGE = 31449600  # 1 year in seconds

# Session security settings
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

# Databases
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB"),
        "USER": env("POSTGRES_USER"),
        "PASSWORD": env("POSTGRES_PASSWORD"),
        "HOST": env("POSTGRES_HOST"),
        "PORT": env("POSTGRES_PORT"),
        # CONN_MAX_AGE=0: Celery workers close DB connections after each task,
        # preventing "too many clients" errors when many workers run in parallel.
        # Web workers (uvicorn) use CONN_MAX_AGE=60 for connection reuse.
        "CONN_MAX_AGE": 0,
        "CONN_HEALTH_CHECKS": False,
        "OPTIONS": {
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 60,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    }
}

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "rest_framework",
    "rest_framework_api_key",
    "rest_framework_datatables",
    "dashboard.apps.DashboardConfig",
    "targetApp.apps.TargetappConfig",
    "scanEngine.apps.ScanengineConfig",
    "startScan.apps.StartscanConfig",
    "recon_note.apps.ReconNoteConfig",
    "commonFilters.apps.CommonfiltersConfig",
    "django_ace",
    "django_celery_beat",
    "django_extensions",
    "mathfilters",
    "drf_yasg",
    "rolepermissions",
    "channels",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "api.middleware.APIKeyAuthenticationMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "login_required.middleware.LoginRequiredMiddleware",
    "dashboard.middleware.SlugMiddleware",
    "dashboard.middleware.ProjectAccessMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "reNgine.middleware.CustomErrorMiddleware",
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [(os.path.join(BASE_DIR, "templates"))],
        "APP_DIRS": False,  # Must be False when loaders is defined
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "reNgine.context_processors.version",
                "reNgine.context_processors.misc",
                "dashboard.context_processors.project_context",
            ],
            # Disable template caching in development
            "loaders": [
                "django.template.loaders.filesystem.Loader",
                "django.template.loaders.app_directories.Loader",
            ]
            if DISABLE_TEMPLATE_CACHE
            else [
                (
                    "django.template.loaders.cached.Loader",
                    [
                        "django.template.loaders.filesystem.Loader",
                        "django.template.loaders.app_directories.Loader",
                    ],
                )
            ],
        },
    }
]
ROOT_URLCONF = "reNgine.urls"
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "api.permissions.HasAPIKeyOrIsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
        "rest_framework_datatables.renderers.DatatablesRenderer",
    ),
    "DEFAULT_FILTER_BACKENDS": ("rest_framework_datatables.filters.DatatablesFilterBackend",),
    "DEFAULT_PAGINATION_CLASS": ("rest_framework_datatables.pagination.DatatablesPageNumberPagination"),
    "PAGE_SIZE": 500,
}
WSGI_APPLICATION = "reNgine.wsgi.application"

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation." + "UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

MEDIA_URL = "/media/"
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = "/staticfiles/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    "login",
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "onboarding"
LOGOUT_REDIRECT_URL = "login"

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

"""
CELERY settings (Celery 5.6.x)
"""
CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = "UTC"
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# ── Serialisation ────────────────────────────────────────────────────────────
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]

# ── Task acknowledgement & reliability ───────────────────────────────────────
# acks_late=True: task is acknowledged AFTER completion, not on receipt.
# Ensures no task is lost if a worker crashes mid-execution.
CELERY_TASK_ACKS_LATE = True
# reject_on_worker_lost: if worker is killed (OOM/SIGKILL), re-queue the task
CELERY_TASK_REJECT_ON_WORKER_LOST = True
# prefetch_multiplier=1: each gevent worker fetches 1 task at a time.
# Prevents task starvation across queues when one queue is busy.
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

# ── Timeouts (prevent hanging scans) ─────────────────────────────────────────
# SOFT_TIME_LIMIT: raises SoftTimeLimitExceeded (catchable) after 3 hours.
# TIME_LIMIT: hard-kills the worker process after 4 hours.
CELERY_TASK_SOFT_TIME_LIMIT = 10800  # 3 hours
CELERY_TASK_TIME_LIMIT = 14400       # 4 hours

# ── Memory management ────────────────────────────────────────────────────────
# Recycle worker after N tasks to prevent memory leaks in long-running scans.
CELERY_WORKER_MAX_TASKS_PER_CHILD = 100
# Recycle worker after it consumes 512 MB of memory (Celery 5.6+ feature)
CELERY_WORKER_MAX_MEMORY_PER_CHILD = 524288  # 512 MB in KB

# ── Result backend ───────────────────────────────────────────────────────────
# Store results for 1 hour (enough to check scan status)
CELERY_RESULT_EXPIRES = 3600

# ── Broker transport (Redis) ─────────────────────────────────────────────────
CELERY_BROKER_TRANSPORT_OPTIONS = {
    # visibility_timeout must be > TASK_TIME_LIMIT to prevent re-queuing running tasks
    "visibility_timeout": 18000,  # 5 hours
    "max_retries": 5,
    # socket_timeout: raise error if Redis doesn't respond within 30s
    "socket_timeout": 30,
    "socket_connect_timeout": 30,
    # retry_on_timeout: auto-reconnect to Redis on timeout
    "retry_on_timeout": True,
}

# ── Broker connection pool ───────────────────────────────────────────────────
# Limit broker connection pool to avoid Redis connection overload
CELERY_BROKER_POOL_LIMIT = 10
CELERY_REDIS_MAX_CONNECTIONS = 20

# ── Chord / canvas reliability ───────────────────────────────────────────────
# chord_unlock retry delay: how often to poll for chord completion (seconds)
CELERY_CHORD_UNLOCK_MAX_RETRIES = 60  # max 60 retries = 10 min
CELERY_CHORD_UNLOCK_DELAY = 10        # poll every 10 seconds

"""
Redis settings for distributed locking
"""
REDIS_HOST = env("REDIS_HOST", default="redis")
REDIS_PORT = env("REDIS_PORT", default=6379)
REDIS_DB = env("REDIS_DB", default=0)
REDIS_PASSWORD = env("REDIS_PASSWORD", default=None)
"""
ROLES and PERMISSIONS
"""
ROLEPERMISSIONS_MODULE = "reNgine.roles"
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

"""
Cache settings
"""
RENGINE_TASK_IGNORE_CACHE_KWARGS = ["ctx"]

# Django Cache Configuration
# In development, disable caching to ensure templates and views reload properly
if DEBUG:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.dummy.DummyCache",
        }
    }
else:
    # Production cache using Redis
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": CELERY_BROKER_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
            "KEY_PREFIX": "rengine_cache",
            "TIMEOUT": 300,  # 5 minutes default timeout
        }
    }


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

"""
LOGGING settings
"""
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {
        "file": {
            "level": "ERROR",
            "class": "logging.FileHandler",
            "filename": "errors.log",
        },
        "null": {"class": "logging.NullHandler"},
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
        "brief": {"class": "logging.StreamHandler", "formatter": "brief"},
        "console": {"class": "logging.StreamHandler", "formatter": "brief"},
        "task": {"class": "logging.StreamHandler", "formatter": "task"},
        "db": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "brief",
            "filename": str(Path.home() / "db.log"),
            "maxBytes": 1024,
            "backupCount": 3,
        },
        "celery": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "simple",
            "filename": "celery.log",
            "maxBytes": 1024 * 1024 * 100,  # 100 mb
        },
        "celery_beat": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "simple",
            "filename": "celery_beat.log",
            "maxBytes": 1024 * 1024 * 100,  # 100 mb
            "backupCount": 5,
        },
        "error_console": {
            "class": "logging.StreamHandler",
            "formatter": "brief",
            "stream": "ext://sys.stderr",
        },
    },
    "formatters": {
        "default": {"format": "%(message)s"},
        "brief": {"format": "%(name)-10s | %(message)s"},
        "task": {"()": lambda: RengineTaskFormatter("%(task_name)-34s | %(levelname)s | %(message)s")},
        "simple": {
            "format": "%(levelname)s %(message)s",
            "datefmt": "%y %b %d, %H:%M:%S",
        },
        "migration": {"format": "%(asctime)s [%(levelname)s] %(app)s: %(message)s (Migrations: %(migration_count)s)"},
    },
    "loggers": {
        "django": {
            "handlers": ["file", "error_console"] if UI_ERROR_LOGGING else ["file"],
            "level": "ERROR" if (UI_DEBUG or UI_ERROR_LOGGING) else "CRITICAL",
            "propagate": True,
        },
        "celery.app.trace": {
            "handlers": ["null"],
            "propagate": False,
        },
        "celery.task": {"handlers": ["task"], "propagate": False},
        "celery.worker": {
            "handlers": ["null"],
            "propagate": False,
        },
        "django.server": {"handlers": ["console"], "propagate": False},
        "django.db.backends": {"handlers": ["db"], "level": "INFO", "propagate": False},
        "reNgine": {
            "handlers": ["task"],
            "level": "DEBUG" if CELERY_DEBUG else "INFO",
            "propagate": True,  # Allow log messages to propagate to root logger
        },
        "kombu.pidbox": {
            "handlers": ["null"],
            "propagate": False,
        },
        "celery.pool": {
            "handlers": ["null"],
            "propagate": False,
        },
        "celery.bootsteps": {
            "handlers": ["null"],
            "propagate": False,
        },
        "celery.utils.functional": {
            "handlers": ["null"],
            "propagate": False,
        },
        "django_celery_beat": {
            "handlers": ["celery_beat", "console"],
            "level": "DEBUG",
            "propagate": True,
        },
        "migrations": {
            "handlers": ["console", "file"],
            "level": "DEBUG" if CELERY_DEBUG else "INFO",
            "formatter": "migration",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG" if CELERY_DEBUG else "INFO",
    },
}


# debug
def show_toolbar(request):
    return bool(UI_DEBUG)


if UI_DEBUG:
    DEBUG_TOOLBAR_CONFIG = {
        "SHOW_TOOLBAR_CALLBACK": "reNgine.settings.show_toolbar",
    }

    INSTALLED_APPS.append("debug_toolbar")
    MIDDLEWARE.append("debug_toolbar.middleware.DebugToolbarMiddleware")

# Channels configuration
ASGI_APPLICATION = "reNgine.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("redis", 6379)],
        },
    },
}

# WebSocket settings
WEBSOCKET_ACCEPT_ALL = True  # For development, change in production
