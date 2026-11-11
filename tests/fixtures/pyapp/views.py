import hashlib
import logging
import random
import secrets
import smtplib

import requests
from flask import Flask

log = logging.getLogger(__name__)
app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


def login_view(request):
    log.warning("Failed login attempt for %s", request.user)
    token = secrets.token_hex(16)
    return token


def fetch_remote(url):
    return requests.get(url)


def fetch_remote_safe(url):
    return requests.get(url, timeout=10, verify=False)


def checksum(data):
    return hashlib.md5(data).hexdigest()


def notify(host):
    smtplib.SMTP(host)


def export_documents(user):
    return random.choice([1, 2])


def load_signed(payload, expected):
    import hmac
    if not hmac.compare_digest(payload[:32], expected):
        raise ValueError("payload modifié")
    return payload[32:]
