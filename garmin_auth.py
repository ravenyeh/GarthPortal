"""Garmin Connect authentication with MFA support using garth library."""

import garth
from garth.sso import login as sso_login, resume_login as sso_resume_login


class GarminAuth:
    """Handles Garmin Connect authentication flow including MFA."""

    def __init__(self):
        self._client_state = None

    @property
    def mfa_pending(self):
        return self._client_state is not None

    def login(self, email: str, password: str, domain: str = "garmin.com"):
        """
        Attempt login. If MFA is required, returns {"status": "mfa_required"}.
        On success, returns {"status": "success", "tokens": ...}.
        """
        self._client_state = None
        garth.configure(domain=domain)

        result = sso_login(
            email, password, client=garth.client, return_on_mfa=True
        )

        if isinstance(result, tuple) and result[0] == "needs_mfa":
            self._client_state = result[1]
            return {
                "status": "mfa_required",
                "message": "Please enter your MFA verification code.",
            }

        # Direct success (no MFA)
        oauth1, oauth2 = result
        garth.client.oauth1_token = oauth1
        garth.client.oauth2_token = oauth2
        return self._build_success_response(domain)

    def submit_mfa(self, mfa_code: str):
        """Submit MFA code to complete authentication."""
        if not self._client_state:
            raise ValueError("No MFA verification pending.")

        oauth1, oauth2 = sso_resume_login(self._client_state, mfa_code)
        garth.client.oauth1_token = oauth1
        garth.client.oauth2_token = oauth2
        domain = garth.client.domain or "garmin.com"
        self._client_state = None
        return self._build_success_response(domain)

    def _build_success_response(self, domain: str):
        """Build response with token information after successful auth."""
        oauth1 = garth.client.oauth1_token
        oauth2 = garth.client.oauth2_token

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

    def save_tokens(self, path: str = ".garth_tokens"):
        """Save current tokens to disk for later reuse."""
        garth.save(path)
        return {"status": "success", "message": f"Tokens saved to {path}"}

    def load_tokens(self, path: str = ".garth_tokens"):
        """Load tokens from disk."""
        garth.resume(path)
        domain = garth.client.domain or "garmin.com"
        return self._build_success_response(domain)
