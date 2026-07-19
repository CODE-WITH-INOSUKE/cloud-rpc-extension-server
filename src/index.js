const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.CLIENT_ID;
const REDIRECT_URI = process.env.REDIRECT_URI;
const OAUTH_SCOPE = 'identify sdk.social_layer_presence';

const sessions = new Map();

function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
    return crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
}

app.get('/auth/start', (req, res) => {
    const sessionId = req.query.session;
    if (!sessionId) {
        return res.status(400).send('Missing session parameter');
    }

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = crypto.randomUUID();

    sessions.set(sessionId, {
        codeVerifier,
        state,
        tokens: null,
        createdAt: Date.now(),
    });

    const url = new URL('https://discord.com/oauth2/authorize');
    url.searchParams.set('client_id', CLIENT_ID);
    url.searchParams.set('redirect_uri', REDIRECT_URI);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', OAUTH_SCOPE);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_method', 'S256');
    url.searchParams.set('state', state);

    res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        return res.status(400).send(`
            <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
                <h2>Authorization failed</h2>
                <p>${error}</p>
                <p>You can close this tab.</p>
            </body></html>
        `);
    }

    let sessionId = null;
    for (const [id, session] of sessions) {
        if (session.state === state) {
            sessionId = id;
            break;
        }
    }

    if (!sessionId) {
        return res.status(400).send(`
            <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
                <h2>Invalid or expired session</h2>
                <p>You can close this tab and try again from VS Code.</p>
            </body></html>
        `);
    }

    const session = sessions.get(sessionId);

    try {
        const tokenResp = await fetch('https://discord.com/api/v9/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: CLIENT_ID,
                grant_type: 'authorization_code',
                code,
                code_verifier: session.codeVerifier,
                redirect_uri: REDIRECT_URI,
            }),
        });

        if (!tokenResp.ok) {
            const text = await tokenResp.text();
            throw new Error(`Token exchange failed: ${tokenResp.status} - ${text}`);
        }

        const tokenData = await tokenResp.json();
        session.tokens = {
            ...tokenData,
            expiresAt: Date.now() + tokenData.expires_in * 1000,
        };

        res.send(`
            <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
                <h2>Authorized!</h2>
                <p>Discord OAuth RPC is now active.</p>
                <p>You can close this tab.</p>
            </body></html>
        `);
    } catch (err) {
        console.error('[auth/callback]', err.message);
        sessions.delete(sessionId);
        res.status(500).send(`
            <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
                <h2>Token exchange failed</h2>
                <p>You can close this tab and try again from VS Code.</p>
            </body></html>
        `);
    }
});

app.get('/auth/token/:sessionId', (req, res) => {
    const session = sessions.get(req.params.sessionId);

    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }

    if (!session.tokens) {
        return res.status(202).json({ status: 'pending' });
    }

    const tokens = session.tokens;
    sessions.delete(req.params.sessionId);
    res.json(tokens);
});

// Cleanup stale sessions every 10 minutes
setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
        if (now - session.createdAt > 10 * 60 * 1000) {
            sessions.delete(id);
        }
    }
}, 10 * 60 * 1000);

app.listen(PORT, () => {
    console.log(`[discord-oauth-rpc] server listening on port ${PORT}`);
});
