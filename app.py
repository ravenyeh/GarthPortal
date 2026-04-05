"""Flask web application for Garmin Connect authentication with MFA support."""

import os
import traceback

from flask import Flask, jsonify, render_template, request

from garmin_auth import GarminAuth

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Per-session auth handler (simple single-user setup)
auth_handler = GarminAuth()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
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
    data = request.get_json()
    mfa_code = data.get("mfa_code", "").strip()

    if not mfa_code:
        return jsonify({"status": "error", "message": "MFA code is required."}), 400

    try:
        result = auth_handler.submit_mfa(mfa_code)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 401


@app.route("/api/save-tokens", methods=["POST"])
def save_tokens():
    try:
        result = auth_handler.save_tokens()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/load-tokens", methods=["POST"])
def load_tokens():
    try:
        result = auth_handler.load_tokens()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
