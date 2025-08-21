/**
 * Minimal serverless backend for Admin user management.
 *
 * Endpoints:
 *  POST /admin/create-user   { email, password, user_metadata? }
 *  GET  /admin/list-users
 *  POST /admin/delete-user   { id }
 *
 * Security:
 *  - Requires SUPABASE_SERVICE_ROLE_KEY on the server (never in frontend)
 *  - Verifies caller's Supabase session token and role=admin
 *
 * Can be deployed on Node serverless platforms (Vercel, Netlify, Cloudflare Workers* w/ adapter).
 */

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // keep secret

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
}

// Service client using service role key
const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
});

// Verifies caller's access token and admin role
async function requireAdmin(req, res, next) {
    try {
        const authHeader = req.headers['authorization'] || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Missing bearer token' });

        const { data: { user }, error } = await adminClient.auth.getUser(token);
        if (error || !user) return res.status(401).json({ error: 'Invalid token' });

        const role = user.user_metadata?.role;
        if (role !== 'admin') return res.status(403).json({ error: 'Admin only' });

        req.user = user;
        next();
    } catch (e) {
        return res.status(500).json({ error: 'Auth verification failed' });
    }
}

app.get('/admin/health', (_req, res) => res.json({ ok: true }));

app.post('/admin/create-user', requireAdmin, async (req, res) => {
    const { email, password, user_metadata } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const { data, error } = await adminClient.auth.admin.createUser({
        email,
        password,
        user_metadata: user_metadata || { role: 'user' },
        email_confirm: true
    });
    if (error) return res.status(400).json({ error: error.message });
    return res.json({ user: data.user });
});

app.get('/admin/list-users', requireAdmin, async (_req, res) => {
    // Paginate if needed: page, perPage
    const { data, error } = await adminClient.auth.admin.listUsers();
    if (error) return res.status(400).json({ error: error.message });
    return res.json({ users: data.users });
});

app.post('/admin/delete-user', requireAdmin, async (req, res) => {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ error: 'id required' });
    const { error } = await adminClient.auth.admin.deleteUser(id);
    if (error) return res.status(400).json({ error: error.message });
    return res.json({ success: true });
});

// Export for serverless (Vercel):
module.exports = app;

// If running standalone: node backend.js
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Admin API listening on :${PORT}`));
}


