"""Vercel serverless function for Garmin login."""

import json
import traceback

from http.server import BaseHTTPRequestHandler

import garth
from garth.sso import login as sso_login


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        data = json.loads(body) if body else {}

        email = data.get("email", "").strip()
        password = data.get("password", "")
        domain = data.get("domain", "garmin.com").strip()

        if not email or not password:
            self._json_response(
                400, {"status": "error", "message": "Email and password are required."}
            )
            return

        try:
            garth.configure(domain=domain)
            result = sso_login(
                email, password, client=garth.client, return_on_mfa=True
            )

            if isinstance(result, tuple) and result[0] == "needs_mfa":
                client_state = result[1]
                self._json_response(200, {
                    "status": "mfa_required",
                    "message": "Please enter your MFA verification code.",
                    "client_state": client_state,
                })
                return

            oauth1, oauth2 = result
            garth.client.oauth1_token = oauth1
            garth.client.oauth2_token = oauth2
            self._json_response(200, build_success_response(oauth1, oauth2, domain))

        except Exception as e:
            traceback.print_exc()
            self._json_response(401, {"status": "error", "message": str(e)})

    def _json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())


def build_success_response(oauth1, oauth2, domain):
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
