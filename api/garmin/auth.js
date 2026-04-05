const { GarminConnect } = require('garmin-connect');

// Garmin auth endpoint with two-step MFA flow:
//   Step 1: POST { email, password } → may return { needsMfa, mfaSession }
//   Step 2: POST { mfaSession, mfaCode } → returns tokens
module.exports = async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const logs = [];
    const log = (msg) => {
        const ts = new Date().toISOString().slice(11, 23);
        logs.push(`[${ts}] ${msg}`);
        console.log(msg);
    };

    try {
        const { email, password, mfaSession, mfaCode, mfaSecretKey } = req.body;

        // Allow MFA_SECRET_KEY from request body (overrides env var)
        if (mfaSecretKey && mfaSecretKey.length >= 32) {
            process.env.MFA_SECRET_KEY = mfaSecretKey;
            log('MFA_SECRET_KEY set from request');
        } else if (mfaSecretKey) {
            return res.status(400).json({
                success: false,
                error: 'MFA Secret Key 必須至少 32 字元',
                debug: { logs }
            });
        }

        // Step 2: MFA verification
        if (mfaSession && mfaCode) {
            log('Step 2: MFA verification');
            const GC = new GarminConnect({ username: '', password: '' });

            try {
                log('Calling GC.verifyMFA()...');
                await GC.verifyMFA(mfaSession, mfaCode);
                log('MFA verified successfully');
            } catch (e) {
                log(`MFA error: ${e.message}`);
                const msg = e.message.toLowerCase();
                let errorMessage = 'MFA 驗證失敗';
                let sessionExpired = false;

                if (msg.includes('429') || msg.includes('too many')) {
                    errorMessage = '請求過於頻繁，請等待幾分鐘後再試';
                } else if (msg.includes('expired')) {
                    errorMessage = '驗證碼已過期（5 分鐘），請重新登入';
                    sessionExpired = true;
                } else if (msg.includes('invalid') && msg.includes('session')) {
                    errorMessage = 'Session 無效，請重新登入';
                    sessionExpired = true;
                } else if (msg.includes('mfa_secret_key')) {
                    errorMessage = '伺服器 MFA 設定錯誤';
                    sessionExpired = true;
                } else if (msg.includes('code') || msg.includes('invalid')) {
                    errorMessage = '驗證碼錯誤，請重新輸入';
                }

                return res.status(401).json({
                    success: false,
                    error: errorMessage,
                    debug: { rawError: e.message, logs },
                    sessionExpired
                });
            }

            return await returnTokens(GC, res, logs, log);
        }

        // Step 1: Login with credentials
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: '請提供 Email 和密碼',
                debug: { logs }
            });
        }

        log(`Step 1: Login for ${email}`);
        log('Creating GarminConnect instance...');

        const GC = new GarminConnect({
            username: email,
            password: password
        });

        log('GarminConnect instance created');
        log('Calling GC.login()...');

        const loginResult = await GC.login();

        log(`Login returned: ${typeof loginResult}`);
        log(`Login result keys: ${loginResult ? Object.keys(loginResult).join(', ') : 'null'}`);
        log(`needsMFA: ${loginResult?.needsMFA}`);

        // Check if MFA is required
        if (loginResult && loginResult.needsMFA) {
            log('MFA required, returning mfaSession');
            return res.status(200).json({
                success: false,
                needsMfa: true,
                mfaSession: loginResult.mfaSession,
                message: '請輸入 Garmin 傳送的驗證碼',
                debug: { logs }
            });
        }

        log('Login successful (no MFA needed)');
        return await returnTokens(GC, res, logs, log);

    } catch (error) {
        log(`ERROR: ${error.message}`);
        log(`Stack: ${error.stack?.split('\n').slice(0, 3).join(' | ')}`);

        let errorMessage = '登入失敗';

        if (error.message) {
            const msg = error.message.toLowerCase();
            if (msg.includes('mfa_secret_key')) {
                errorMessage = '伺服器缺少 MFA_SECRET_KEY 環境變數，請在 Vercel 設定';
            } else if (msg.includes('429') || msg.includes('too many')) {
                errorMessage = '請求過於頻繁，請等待幾分鐘後再試';
            } else if (msg.includes('credentials') || msg.includes('password') || msg.includes('401')) {
                errorMessage = 'Email 或密碼錯誤';
            } else if (msg.includes('captcha') || msg.includes('robot')) {
                errorMessage = 'Garmin 需要驗證碼，請稍後再試';
            } else if (msg.includes('blocked') || msg.includes('forbidden')) {
                errorMessage = 'Garmin 暫時封鎖此連線，請稍後再試';
            }
        }

        return res.status(401).json({
            success: false,
            error: errorMessage,
            debug: { rawError: error.message, stack: error.stack?.split('\n').slice(0, 5), logs }
        });
    }
};

// Return OAuth tokens and user profile
async function returnTokens(GC, res, logs, log) {
    log('Fetching tokens...');
    const oauth1Token = GC.client?.oauth1Token || null;
    const oauth2Token = GC.client?.oauth2Token || null;

    log(`OAuth1 token: ${oauth1Token ? 'present (' + Object.keys(oauth1Token).join(',') + ')' : 'null'}`);
    log(`OAuth2 token: ${oauth2Token ? 'present (' + Object.keys(oauth2Token).join(',') + ')' : 'null'}`);

    // Also try exportToken()
    let exportedTokens = null;
    try {
        exportedTokens = GC.exportToken();
        log(`exportToken keys: ${exportedTokens ? Object.keys(exportedTokens).join(',') : 'null'}`);
    } catch (e) {
        log(`exportToken failed: ${e.message}`);
    }

    // Get user profile
    let user = null;
    try {
        log('Fetching user profile...');
        const userProfile = await GC.getUserProfile();
        log(`User profile: ${userProfile?.displayName || 'unknown'}`);

        let socialProfile = null;
        if (userProfile.displayName) {
            try {
                const socialUrl = `https://connect.garmin.com/modern/proxy/userprofile-service/socialProfile/${userProfile.displayName}`;
                socialProfile = await GC.get(socialUrl);
            } catch (e) {
                log(`Social profile fetch failed: ${e.message}`);
            }
        }

        user = {
            displayName: userProfile.displayName || 'User',
            fullName: socialProfile?.fullName || socialProfile?.userProfileFullName || userProfile.fullName || null,
            profileImageUrl: socialProfile?.profileImageUrlSmall || userProfile.profileImageUrlSmall || null
        };
    } catch (e) {
        log(`User profile fetch failed: ${e.message}`);
    }

    log('Done!');

    // Build token response - include all available fields
    const tokens = {
        oauth1: null,
        oauth2: null
    };

    if (oauth1Token) {
        tokens.oauth1 = { ...oauth1Token };
    } else if (exportedTokens?.oauth1) {
        tokens.oauth1 = { ...exportedTokens.oauth1 };
    }

    if (oauth2Token) {
        tokens.oauth2 = { ...oauth2Token };
    } else if (exportedTokens?.oauth2) {
        tokens.oauth2 = { ...exportedTokens.oauth2 };
    }

    return res.status(200).json({
        success: true,
        message: '登入成功！',
        tokens,
        user,
        debug: { logs }
    });
}
