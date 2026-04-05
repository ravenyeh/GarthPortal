const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');

// ── Constants ──────────────────────────────────────────────────────
const SSO_ORIGIN = 'https://sso.garmin.com';
const SSO_EMBED = `${SSO_ORIGIN}/sso/embed`;
const SIGNIN_URL = `${SSO_ORIGIN}/sso/signin`;
const MFA_VERIFY_URL = `${SSO_ORIGIN}/sso/verifyMFA/loginEnterMfaCode`;
const GC_MODERN = 'https://connect.garmin.com/modern';
const GC_API = 'https://connectapi.garmin.com';
const OAUTH_URL = `${GC_API}/oauth-service/oauth`;
const OAUTH_CONSUMER_URL = 'https://thegarth.s3.amazonaws.com/oauth_consumer.json';

const CSRF_RE = /name="_csrf"\s+value="(.+?)"/;
const TICKET_RE = /ticket=([^"]+)"/;

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36';
const USER_AGENT_MOBILE = 'com.garmin.android.apps.connectmobile';

const MFA_ALGORITHM = 'aes-256-gcm';
const MFA_IV_LENGTH = 16;
const MFA_AUTH_TAG_LENGTH = 16;
const MFA_SESSION_EXPIRY_MS = 5 * 60 * 1000;

// ── Helper: extract Set-Cookie values ──────────────────────────────
function extractCookies(response) {
    const cookies = {};
    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
        for (const c of setCookie) {
            const nameValue = c.split(';')[0];
            const eq = nameValue.indexOf('=');
            if (eq > 0) {
                cookies[nameValue.substring(0, eq).trim()] = nameValue.substring(eq + 1).trim();
            }
        }
    }
    return cookies;
}

function cookieString(jar) {
    return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
}

// ── MFA encryption/decryption ──────────────────────────────────────
function getMFAKey() {
    const key = process.env.MFA_SECRET_KEY;
    if (!key || key.length < 32) {
        throw new Error('MFA_SECRET_KEY environment variable must be at least 32 characters');
    }
    return Buffer.from(key.slice(0, 32), 'utf-8');
}

function encryptMFASession(data) {
    const iv = crypto.randomBytes(MFA_IV_LENGTH);
    const cipher = crypto.createCipheriv(MFA_ALGORITHM, getMFAKey(), iv);
    const json = JSON.stringify(data);
    const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decryptMFASession(encrypted) {
    try {
        const buffer = Buffer.from(encrypted, 'base64');
        const iv = buffer.subarray(0, MFA_IV_LENGTH);
        const authTag = buffer.subarray(MFA_IV_LENGTH, MFA_IV_LENGTH + MFA_AUTH_TAG_LENGTH);
        const data = buffer.subarray(MFA_IV_LENGTH + MFA_AUTH_TAG_LENGTH);
        const decipher = crypto.createDecipheriv(MFA_ALGORITHM, getMFAKey(), iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
        return JSON.parse(decrypted);
    } catch {
        throw new Error('Invalid or corrupted MFA session');
    }
}

// ── OAuth helpers ──────────────────────────────────────────────────
function getOAuthClient(consumer) {
    return new OAuth({
        consumer: { key: consumer.key, secret: consumer.secret },
        signature_method: 'HMAC-SHA1',
        hash_function(base_string, key) {
            return crypto.createHmac('sha1', key).update(base_string).digest('base64');
        }
    });
}

async function fetchOAuthConsumer() {
    const res = await axios.get(OAUTH_CONSUMER_URL);
    return { key: res.data.consumer_key, secret: res.data.consumer_secret };
}

async function getOAuth1Token(ticket, cookies, consumer) {
    const oauth = getOAuthClient(consumer);
    const params = {
        ticket,
        'login-url': SSO_EMBED,
        'accepts-mfa-tokens': true
    };
    const url = `${OAUTH_URL}/preauthorized?${qs.stringify(params)}`;
    const requestData = { url, method: 'GET' };
    const authHeaders = oauth.toHeader(oauth.authorize(requestData));

    const res = await axios.get(url, {
        headers: {
            ...authHeaders,
            'User-Agent': USER_AGENT_MOBILE,
            Cookie: cookieString(cookies)
        }
    });
    const token = qs.parse(res.data);
    return { token, oauth };
}

async function exchangeOAuth2(oauth1, consumer) {
    const oauth = getOAuthClient(consumer);
    const token = { key: oauth1.token.oauth_token, secret: oauth1.token.oauth_token_secret };
    const baseUrl = `${OAUTH_URL}/exchange/user/2.0`;
    const requestData = { url: baseUrl, method: 'POST', data: null };
    const authData = oauth.authorize(requestData, token);
    const url = `${baseUrl}?${qs.stringify(authData)}`;

    const res = await axios.post(url, null, {
        headers: {
            'User-Agent': USER_AGENT_MOBILE,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });
    return res.data;
}

// ── MFA detection ──────────────────────────────────────────────────
function detectMFA(html) {
    if (!html) return false;
    return html.includes('mfa-code') ||
           html.includes('verifyMFA') ||
           html.includes('loginEnterMfaCode') ||
           html.includes('verification-code') ||
           html.includes('setupEnterMfaCode');
}

// ── Main handler ───────────────────────────────────────────────────
module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const { email, password, mfaSession, mfaCode } = req.body;

        // ── Step 2: MFA verification ───────────────────────────────
        if (mfaSession && mfaCode) {
            const session = decryptMFASession(mfaSession);

            if (Date.now() - session.timestamp > MFA_SESSION_EXPIRY_MS) {
                return res.status(401).json({
                    success: false,
                    error: '驗證碼已過期（5 分鐘），請重新登入',
                    sessionExpired: true
                });
            }

            // Restore cookies and submit MFA code
            const cookies = JSON.parse(session.cookies);
            const mfaUrl = `${MFA_VERIFY_URL}?${qs.stringify(session.signinParams)}`;

            const mfaRes = await axios.post(mfaUrl,
                qs.stringify({
                    'mfa-code': mfaCode,
                    embed: 'true',
                    _csrf: session.csrfToken,
                    fromPage: 'setupEnterMfaCode',
                    rememberMyBrowserChecked: 'true'
                }),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        Dnt: '1',
                        Origin: SSO_ORIGIN,
                        Referer: SIGNIN_URL,
                        'User-Agent': USER_AGENT,
                        Cookie: cookieString(cookies)
                    },
                    responseType: 'text'
                }
            );

            const mfaHtml = mfaRes.data || '';
            // Merge any new cookies
            Object.assign(cookies, extractCookies(mfaRes));

            // Check for success
            const titleMatch = /<title>([^<]*)<\/title>/.exec(mfaHtml);
            const title = titleMatch ? titleMatch[1] : '';
            if (title !== 'Success') {
                return res.status(401).json({
                    success: false,
                    error: '驗證碼錯誤，請重新輸入'
                });
            }

            // Extract ticket
            const ticketMatch = TICKET_RE.exec(mfaHtml);
            if (!ticketMatch) {
                return res.status(401).json({
                    success: false,
                    error: 'MFA 驗證後無法取得 ticket',
                    sessionExpired: true
                });
            }

            // Complete OAuth flow
            const consumer = await fetchOAuthConsumer();
            const oauth1 = await getOAuth1Token(ticketMatch[1], cookies, consumer);
            const oauth2 = await exchangeOAuth2(oauth1, consumer);

            return returnTokens(res, oauth1.token, oauth2);
        }

        // ── Step 1: Login with credentials ─────────────────────────
        if (!email || !password) {
            return res.status(400).json({ success: false, error: '請提供 Email 和密碼' });
        }

        let cookies = {};

        // 1a. Hit SSO embed to get initial cookies
        const step1Params = { clientId: 'GarminConnect', locale: 'en', service: GC_MODERN };
        const step1Url = `${SSO_EMBED}?${qs.stringify(step1Params)}`;
        const step1Res = await axios.get(step1Url, {
            headers: { 'User-Agent': USER_AGENT },
            responseType: 'text'
        });
        Object.assign(cookies, extractCookies(step1Res));

        // 1b. Get CSRF token from signin page
        const step2Params = { id: 'gauth-widget', embedWidget: true, locale: 'en', gauthHost: SSO_EMBED };
        const step2Url = `${SIGNIN_URL}?${qs.stringify(step2Params)}`;
        const step2Res = await axios.get(step2Url, {
            headers: {
                'User-Agent': USER_AGENT,
                Cookie: cookieString(cookies)
            },
            responseType: 'text'
        });
        Object.assign(cookies, extractCookies(step2Res));

        const csrfMatch = CSRF_RE.exec(step2Res.data);
        if (!csrfMatch) throw new Error('CSRF token not found');
        const csrfToken = csrfMatch[1];

        // 1c. POST credentials
        const signinParams = {
            id: 'gauth-widget',
            embedWidget: 'true',
            clientId: 'GarminConnect',
            locale: 'en',
            gauthHost: SSO_EMBED,
            service: SSO_EMBED,
            source: SSO_EMBED,
            redirectAfterAccountLoginUrl: SSO_EMBED,
            redirectAfterAccountCreationUrl: SSO_EMBED
        };
        const step3Url = `${SIGNIN_URL}?${qs.stringify(signinParams)}`;
        const step3Res = await axios.post(step3Url,
            qs.stringify({ username: email, password, embed: 'true', _csrf: csrfToken }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Dnt: '1',
                    Origin: SSO_ORIGIN,
                    Referer: SIGNIN_URL,
                    'User-Agent': USER_AGENT,
                    Cookie: cookieString(cookies)
                },
                responseType: 'text'
            }
        );
        Object.assign(cookies, extractCookies(step3Res));

        const html = step3Res.data || '';

        // Check MFA
        if (detectMFA(html)) {
            const mfaCsrfMatch = CSRF_RE.exec(html);
            const mfaCsrfToken = mfaCsrfMatch ? mfaCsrfMatch[1] : csrfToken;

            const mfaSessionData = {
                cookies: JSON.stringify(cookies),
                csrfToken: mfaCsrfToken,
                signinParams,
                timestamp: Date.now()
            };

            return res.status(200).json({
                success: false,
                needsMfa: true,
                mfaSession: encryptMFASession(mfaSessionData),
                message: '請輸入 Garmin 傳送的驗證碼'
            });
        }

        // Extract ticket
        const ticketMatch = TICKET_RE.exec(html);
        if (!ticketMatch) {
            throw new Error('login failed (Ticket not found), please check username and password');
        }

        // Complete OAuth flow
        const consumer = await fetchOAuthConsumer();
        const oauth1 = await getOAuth1Token(ticketMatch[1], cookies, consumer);
        const oauth2 = await exchangeOAuth2(oauth1, consumer);

        return returnTokens(res, oauth1.token, oauth2);

    } catch (error) {
        console.error('Garmin auth error:', error.message);

        let errorMessage = '登入失敗';
        if (error.message) {
            const msg = error.message.toLowerCase();
            if (msg.includes('429') || msg.includes('too many')) {
                errorMessage = '請求過於頻繁，請等待幾分鐘後再試';
            } else if (msg.includes('credentials') || msg.includes('password') || msg.includes('401') || msg.includes('ticket not found')) {
                errorMessage = 'Email 或密碼錯誤';
            } else if (msg.includes('csrf')) {
                errorMessage = 'Garmin SSO 頁面異常，請稍後再試';
            } else if (msg.includes('mfa_secret_key')) {
                errorMessage = '伺服器 MFA 設定錯誤';
            }
        }

        return res.status(401).json({ success: false, error: errorMessage });
    }
};

// ── Return tokens ──────────────────────────────────────────────────
function returnTokens(res, oauth1Token, oauth2Token) {
    const tokens = { oauth1: null, oauth2: null };

    if (oauth1Token) {
        tokens.oauth1 = { ...oauth1Token };
    }
    if (oauth2Token) {
        tokens.oauth2 = { ...oauth2Token };
    }

    return res.status(200).json({
        success: true,
        message: '登入成功！',
        tokens
    });
}
