"""Vercel serverless Flask app for Garmin Connect authentication with MFA."""

import base64
import json
import os
import pickle
import traceback

from flask import Flask, jsonify, request, send_from_directory

import garth
from garth.sso import (
    login as sso_login,
    handle_mfa,
    _complete_login,
)

app = Flask(__name__)

# Resolve path to public/ relative to this file (api/index.py -> ../public)
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "public")


@app.route("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")


def _serialize_client_state(client_state):
    """Serialize garth Client session cookies for stateless serverless."""
    client = client_state["client"]
    cookies_bytes = pickle.dumps(dict(client.sess.cookies))
    return {
        "login_params": client_state["login_params"],
        "mfa_method": client_state.get("mfa_method", "email"),
        "domain": client.domain,
        "cookies_b64": base64.b64encode(cookies_bytes).decode("ascii"),
        "headers": dict(client.sess.headers),
    }


def _deserialize_client_state(serialized):
    """Reconstruct garth Client with preserved cookies from login step."""
    from garth.http import Client

    domain = serialized["domain"]
    cookies_bytes = base64.b64decode(serialized["cookies_b64"])
    cookies_dict = pickle.loads(cookies_bytes)  # noqa: S301

    client = Client()
    client.configure(domain=domain)
    client.sess.cookies.update(cookies_dict)
    if serialized.get("headers"):
        client.sess.headers.update(serialized["headers"])

    return {
        "login_params": serialized["login_params"],
        "mfa_method": serialized.get("mfa_method", "email"),
        "client": client,
    }


def _build_token_response(oauth1, oauth2, domain):
    tokens = {}
    if oauth1:
        tokens["oauth1"] = {
            "oauth_token": oauth1.oauth_token,
            "oauth_token_secret": oauth1.oauth_token_secret,
        }
        if oauth1.mfa_token:
            tokens["oauth1"]["mfa_token"] = oauth1.mfa_token
    if oauth2:
        tokens["oauth2"] = {
            "access_token": oauth2.access_token,
            "refresh_token": oauth2.refresh_token,
            "token_type": oauth2.token_type,
            "expires_at": oauth2.expires_at,
            "refresh_token_expires_at": oauth2.refresh_token_expires_at,
        }

    display_name = ""
    try:
        display_name = garth.client.username or ""
    except Exception:
        pass

    return {
        "status": "success",
        "message": "Authentication successful!",
        "display_name": display_name,
        "domain": domain,
        "tokens": tokens,
    }


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    domain = data.get("domain", "garmin.com").strip()

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    try:
        garth.configure(domain=domain)
        result = sso_login(email, password, client=garth.client, return_on_mfa=True)

        if isinstance(result, tuple) and result[0] == "needs_mfa":
            serialized = _serialize_client_state(result[1])
            return jsonify({
                "status": "mfa_required",
                "message": "Please enter your MFA verification code.",
                "client_state": serialized,
            })

        oauth1, oauth2 = result
        garth.client.oauth1_token = oauth1
        garth.client.oauth2_token = oauth2
        return jsonify(_build_token_response(oauth1, oauth2, domain))

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 401


@app.route("/api/mfa", methods=["POST"])
def submit_mfa():
    data = request.get_json() or {}
    mfa_code = data.get("mfa_code", "").strip()
    serialized_state = data.get("client_state")

    if not mfa_code:
        return jsonify({"status": "error", "message": "MFA code is required."}), 400
    if not serialized_state:
        return jsonify({"status": "error", "message": "Session expired. Please login again."}), 400

    try:
        client_state = _deserialize_client_state(serialized_state)
        client = client_state["client"]
        login_params = client_state["login_params"]
        mfa_method = client_state.get("mfa_method", "email")

        ticket = handle_mfa(client, login_params, lambda: mfa_code, mfa_method=mfa_method)
        oauth1, oauth2 = _complete_login(ticket, client)

        garth.client.oauth1_token = oauth1
        garth.client.oauth2_token = oauth2
        domain = serialized_state.get("domain", "garmin.com")

        return jsonify(_build_token_response(oauth1, oauth2, domain))

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 401
