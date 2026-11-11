import os

DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = os.getenv("APP_SECRET_KEY")
SESSION_COOKIE_SECURE = True
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]
REST_FRAMEWORK = {"DEFAULT_THROTTLE_RATES": {"anon": "5/min"}}
admin_password = "changeme123"
