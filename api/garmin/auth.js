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

    try {
        const { email, password, mfaSession, mfaCode } = req.body;

        // Step 2: MFA verification
        if (mfaSession && mfaCode) {
            const GC = new GarminConnect({ username: '', password: '' });

            try {
                await GC.verifyMFA(mfaSession, mfaCode);
            } catch (e) {
                const msg = e.message.toLowerCase();
                let errorMessage = 'MFA 驗證失敗';
                let sessionExpired = false;

                if (msg.includes('expired')) {
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
                    sessionExpired
                });
            }

            // MFA verified, return tokens
            return await returnTokens(GC, res);
        }

        // Step 1: Login with credentials
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                error: '請提供 Email 和密碼'
            });
        }

        const GC = new GarminConnect({
            username: email,
            password: password
        });

        const loginResult = await GC.login();

        // Check if MFA is required
        if (loginResult && loginResult.needsMFA) {
            return res.status(200).json({
                success: false,
                needsMfa: true,
                mfaSession: loginResult.mfaSession,
                message: '請輸入 Garmin 傳送的驗證碼'
            });
        }

        // No MFA needed, return tokens directly
        return await returnTokens(GC, res);

    } catch (error) {
        console.error('Garmin auth error:', error.message);

        let errorMessage = '登入失敗';

        if (error.message) {
            const msg = error.message.toLowerCase();
            if (msg.includes('credentials') || msg.includes('password') || msg.includes('401')) {
                errorMessage = 'Email 或密碼錯誤';
            } else if (msg.includes('captcha') || msg.includes('robot')) {
                errorMessage = 'Garmin 需要驗證碼，請稍後再試';
            } else if (msg.includes('blocked') || msg.includes('forbidden')) {
                errorMessage = 'Garmin 暫時封鎖此連線，請稍後再試';
            }
        }

        return res.status(401).json({
            success: false,
            error: errorMessage
        });
    }
};

// Return OAuth tokens and user profile
async function returnTokens(GC, res) {
    const oauth1Token = GC.client?.oauth1Token || null;
    const oauth2Token = GC.client?.oauth2Token || null;

    // Get user profile
    let user = null;
    try {
        const userProfile = await GC.getUserProfile();

        let socialProfile = null;
        if (userProfile.displayName) {
            try {
                const socialUrl = `https://connect.garmin.com/modern/proxy/userprofile-service/socialProfile/${userProfile.displayName}`;
                socialProfile = await GC.get(socialUrl);
            } catch (e) {
                // Social profile fetch is optional
            }
        }

        user = {
            displayName: userProfile.displayName || 'User',
            fullName: socialProfile?.fullName || socialProfile?.userProfileFullName || userProfile.fullName || null,
            profileImageUrl: socialProfile?.profileImageUrlSmall || userProfile.profileImageUrlSmall || null
        };
    } catch (e) {
        // User profile fetch is optional
    }

    return res.status(200).json({
        success: true,
        message: '登入成功！',
        tokens: {
            oauth1: oauth1Token ? {
                oauth_token: oauth1Token.oauth_token || oauth1Token.oauthToken || null,
                oauth_token_secret: oauth1Token.oauth_token_secret || oauth1Token.oauthTokenSecret || null
            } : null,
            oauth2: oauth2Token ? {
                access_token: oauth2Token.access_token || oauth2Token.accessToken || null,
                refresh_token: oauth2Token.refresh_token || oauth2Token.refreshToken || null,
                token_type: oauth2Token.token_type || oauth2Token.tokenType || null,
                expires_at: oauth2Token.expires_at || oauth2Token.expiresAt || null
            } : null
        },
        user
    });
}
