import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ["LEA_MOBILE_SECRET_KEY"]
DEBUG = False
ALLOWED_HOSTS = os.environ.get("LEA_MOBILE_HOSTS", "127.0.0.1,localhost").split(",")
ROOT_URLCONF = "mobile_server.urls"
INSTALLED_APPS = ["django.contrib.contenttypes", "questionnaires"]
MIDDLEWARE = ["django.middleware.security.SecurityMiddleware", "django.middleware.common.CommonMiddleware"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.environ.get("LEA_MOBILE_DB", str(BASE_DIR / "data" / "mobile.sqlite3")), "OPTIONS": {"timeout": 20}}}
Path(DATABASES["default"]["NAME"]).parent.mkdir(parents=True, exist_ok=True)
# Where a new APK + its version.json get dropped for the self-hosted update check/download —
# see questionnaires.views.app_version/app_download and deploy/publish_release.sh.
RELEASES_DIR = Path(os.environ.get("LEA_MOBILE_RELEASES_DIR", str(BASE_DIR / "releases")))
RELEASES_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "Europe/Simferopol"
LANGUAGE_CODE = "ru-ru"
# Encrypted package payloads can be sizeable (photos are embedded as base64); keep this
# above the 60 MB manual cap enforced in questionnaires.views.store_uploaded_package.
DATA_UPLOAD_MAX_MEMORY_SIZE = 67108864
X_FRAME_OPTIONS = "DENY"
