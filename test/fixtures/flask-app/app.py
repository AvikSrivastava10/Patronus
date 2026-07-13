# Fixture: a Flask app with auth/rate-limit/header gaps (for checker tests).
from flask import Flask
from functools import wraps

app = Flask(__name__)


# Sensitive path, no auth decorator -> flagged by missing-auth.
@app.route("/admin/delete", methods=["POST"])
def delete_user():
    return "deleted"


# Sensitive path guarded by @login_required -> NOT flagged.
@app.route("/admin/users")
@login_required
def list_users():
    return "users"


# Auth-style route, no limiter anywhere -> flagged by missing-rate-limit.
@app.route("/login", methods=["POST"])
def login():
    return "ok"


# Public route -> not flagged.
@app.route("/health")
def health():
    return "ok"
