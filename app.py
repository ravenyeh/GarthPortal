"""Flask app for local development - Garmin Connect auth with MFA support."""

import os
import traceback

from flask import Flask, jsonify, request, send_from_directory

from garmin_auth import GarminAuth

app = Flask(__name__)
app.secret_key = os.urandom(24)

auth_handler = GarminAuth()


@app.route("/")
def index():
    return send_from_directory("public", "index.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    domain = data.get("domain", "garmin.com").strip()

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    try:
        result = auth_handler.login(email, password, domain=domain)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 401


@app.route("/api/mfa", methods=["POST"])
def submit_mfa():
    data = request.get_json() or {}
    mfa_code = data.get("mfa_code", "").strip()

    if not mfa_code:
        return jsonify({"status": "error", "message": "MFA code is required."}), 400

    try:
        result = auth_handler.submit_mfa(mfa_code)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 401


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
