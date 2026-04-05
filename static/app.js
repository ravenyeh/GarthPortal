document.addEventListener("DOMContentLoaded", () => {
    const loginSection = document.getElementById("login-section");
    const mfaSection = document.getElementById("mfa-section");
    const tokenSection = document.getElementById("token-section");
    const loadSection = document.getElementById("load-section");
    const statusBar = document.getElementById("status-bar");

    const loginForm = document.getElementById("login-form");
    const mfaForm = document.getElementById("mfa-form");
    const loginBtn = document.getElementById("login-btn");
    const mfaBtn = document.getElementById("mfa-btn");
    const backBtn = document.getElementById("back-btn");
    const saveBtn = document.getElementById("save-btn");
    const loadBtn = document.getElementById("load-btn");
    const logoutBtn = document.getElementById("logout-btn");

    // Status message helper
    let statusTimeout;
    function showStatus(message, type = "info") {
        clearTimeout(statusTimeout);
        statusBar.textContent = message;
        statusBar.className = `status-bar ${type}`;
        statusBar.classList.remove("hidden");
        statusTimeout = setTimeout(() => {
            statusBar.classList.add("hidden");
        }, 4000);
    }

    function setLoading(btn, loading) {
        if (loading) {
            btn.disabled = true;
            btn.dataset.originalText = btn.textContent;
            btn.innerHTML = '<span class="spinner"></span>Processing...';
        } else {
            btn.disabled = false;
            btn.textContent = btn.dataset.originalText || btn.textContent;
        }
    }

    // Show specific section
    function showSection(section) {
        loginSection.classList.add("hidden");
        mfaSection.classList.add("hidden");
        tokenSection.classList.add("hidden");
        loadSection.classList.add("hidden");

        if (section === "login") {
            loginSection.classList.remove("hidden");
            loadSection.classList.remove("hidden");
        } else if (section === "mfa") {
            mfaSection.classList.remove("hidden");
        } else if (section === "token") {
            tokenSection.classList.remove("hidden");
        }
    }

    // Display tokens
    function displayTokens(data) {
        const userInfo = document.getElementById("user-info");
        const parts = [];
        if (data.display_name) parts.push(`User: ${data.display_name}`);
        if (data.domain) parts.push(`Domain: ${data.domain}`);
        userInfo.textContent = parts.join(" | ") || "Authenticated";

        const tokens = data.tokens || {};

        if (tokens.oauth1) {
            document.getElementById("oauth1-token").value = tokens.oauth1.token || "";
            document.getElementById("oauth1-secret").value = tokens.oauth1.token_secret || "";
        }

        if (tokens.oauth2) {
            document.getElementById("oauth2-access").value = tokens.oauth2.access_token || "";
            document.getElementById("oauth2-refresh").value = tokens.oauth2.refresh_token || "";
            document.getElementById("oauth2-type").value = tokens.oauth2.token_type || "";
            document.getElementById("oauth2-expires").value = tokens.oauth2.expires_at
                ? new Date(tokens.oauth2.expires_at * 1000).toLocaleString()
                : "";
        }

        showSection("token");
    }

    // Login
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;
        const domain = document.getElementById("domain").value;

        if (!email || !password) {
            showStatus("Please fill in email and password.", "error");
            return;
        }

        setLoading(loginBtn, true);
        try {
            const res = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password, domain }),
            });
            const data = await res.json();

            if (data.status === "mfa_required") {
                showStatus("MFA verification required.", "info");
                showSection("mfa");
                document.getElementById("mfa-code").focus();
            } else if (data.status === "success") {
                showStatus("Login successful!", "success");
                displayTokens(data);
            } else {
                showStatus(data.message || "Login failed.", "error");
            }
        } catch (err) {
            showStatus("Network error. Please try again.", "error");
        } finally {
            setLoading(loginBtn, false);
        }
    });

    // MFA Submit
    mfaForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const mfaCode = document.getElementById("mfa-code").value.trim();

        if (!mfaCode) {
            showStatus("Please enter the verification code.", "error");
            return;
        }

        setLoading(mfaBtn, true);
        try {
            const res = await fetch("/api/mfa", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ mfa_code: mfaCode }),
            });
            const data = await res.json();

            if (data.status === "success") {
                showStatus("MFA verified! Tokens retrieved.", "success");
                displayTokens(data);
            } else {
                showStatus(data.message || "MFA verification failed.", "error");
            }
        } catch (err) {
            showStatus("Network error. Please try again.", "error");
        } finally {
            setLoading(mfaBtn, false);
        }
    });

    // Back to login
    backBtn.addEventListener("click", () => {
        document.getElementById("mfa-code").value = "";
        showSection("login");
    });

    // Save tokens
    saveBtn.addEventListener("click", async () => {
        setLoading(saveBtn, true);
        try {
            const res = await fetch("/api/save-tokens", { method: "POST" });
            const data = await res.json();
            showStatus(data.message || "Tokens saved.", data.status === "success" ? "success" : "error");
        } catch (err) {
            showStatus("Failed to save tokens.", "error");
        } finally {
            setLoading(saveBtn, false);
        }
    });

    // Load tokens
    loadBtn.addEventListener("click", async () => {
        setLoading(loadBtn, true);
        try {
            const res = await fetch("/api/load-tokens", { method: "POST" });
            const data = await res.json();

            if (data.status === "success") {
                showStatus("Tokens loaded successfully!", "success");
                displayTokens(data);
            } else {
                showStatus(data.message || "No saved tokens found.", "error");
            }
        } catch (err) {
            showStatus("Failed to load tokens.", "error");
        } finally {
            setLoading(loadBtn, false);
        }
    });

    // Logout
    logoutBtn.addEventListener("click", () => {
        document.getElementById("login-form").reset();
        document.getElementById("mfa-code").value = "";
        showSection("login");
        showStatus("Logged out.", "info");
    });

    // Copy buttons
    document.querySelectorAll(".btn-copy").forEach((btn) => {
        btn.addEventListener("click", () => {
            const target = document.getElementById(btn.dataset.target);
            const text = target.value;
            if (!text) return;

            navigator.clipboard.writeText(text).then(() => {
                const original = btn.textContent;
                btn.textContent = "Copied!";
                setTimeout(() => { btn.textContent = original; }, 1500);
            }).catch(() => {
                target.select();
                document.execCommand("copy");
                const original = btn.textContent;
                btn.textContent = "Copied!";
                setTimeout(() => { btn.textContent = original; }, 1500);
            });
        });
    });
});
