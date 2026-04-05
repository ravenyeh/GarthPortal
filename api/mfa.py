"""Vercel serverless function for Garmin MFA verification."""

import base64
import json
import pickle
import traceback
from http.server import BaseHTTPRequestHandler

import garth
import requests
from garth.http import Client
from garth.sso import handle_mfa, OAuth1Token, OAuth2Token


def deserialize_client_state(serialized):
    """Reconstruct garth Client with preserved cookies from login step."""
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


def _complete_login(ticket, client):
    """Exchange SSO ticket for OAuth1 + OAuth2 tokens."""
    from garth.sso import _complete_login as garth_complete
    return garth_complete(ticket, client)


def build_token_response(oauth1, oauth2, domain):
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


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        data = json.loads(body) if body else {}

        mfa_code = data.get("mfa_code", "").strip()
        serialized_state = data.get("client_state")

        if not mfa_code:
            self._json(400, {"status": "error", "message": "MFA code is required."})
            return
        if not serialized_state:
            self._json(400, {"status": "error", "message": "No MFA session state. Please login again."})
            return

        try:
            client_state = deserialize_client_state(serialized_state)
            client = client_state["client"]
            login_params = client_state["login_params"]
            mfa_method = client_state.get("mfa_method", "email")

            ticket = handle_mfa(client, login_params, lambda: mfa_code, mfa_method=mfa_method)
            oauth1, oauth2 = _complete_login(ticket, client)

            garth.client.oauth1_token = oauth1
            garth.client.oauth2_token = oauth2
            domain = serialized_state.get("domain", "garmin.com")

            self._json(200, build_token_response(oauth1, oauth2, domain))

        except Exception as e:
            traceback.print_exc()
            self._json(401, {"status": "error", "message": str(e)})

    def _json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())
