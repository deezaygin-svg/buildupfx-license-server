// Lightweight license activation server for "Fvcking Build Up By DJ GIN".
//
// Zero external dependencies - uses only Node's built-in http, crypto, and sqlite modules.
// Run with: node server.mjs
//
// Required environment variables:
//   LICENSE_PRIVATE_SEED_HEX  - the 32-byte Ed25519 private seed (hex), from keypair.json.
//                               Keep this secret. Never commit it, never log it.
//   LICENSE_ADMIN_SECRET      - a long random string only you know, used to authorize
//                               /admin/issue and /admin/list calls.
// Optional:
//   PORT                      - defaults to 8787
//   DB_PATH                   - defaults to ./licenses.db
//   GUMROAD_PRODUCT_ID        - if set, unknown license keys are checked against Gumroad's
//                               license verification API before being rejected. Lets Gumroad
//                               generate + deliver keys at checkout with zero extra work here -
//                               see README.md "Selling on Gumroad".

import http from 'node:http';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8787;
const DB_PATH = process.env.DB_PATH || './licenses.db';
const ADMIN_SECRET = process.env.LICENSE_ADMIN_SECRET;
const PRIVATE_SEED_HEX = process.env.LICENSE_PRIVATE_SEED_HEX;
const GUMROAD_PRODUCT_ID = process.env.GUMROAD_PRODUCT_ID || '';
const DEFAULT_SEAT_LIMIT = 2;

if (!ADMIN_SECRET) {
    console.error('FATAL: LICENSE_ADMIN_SECRET is not set.');
    process.exit(1);
}
if (!PRIVATE_SEED_HEX || PRIVATE_SEED_HEX.length !== 64) {
    console.error('FATAL: LICENSE_PRIVATE_SEED_HEX is not set or not a 32-byte hex string.');
    process.exit(1);
}

// Reconstruct the Node KeyObject from the raw 32-byte Ed25519 seed. Node's JWK import requires
// the public component too (not just the seed), so instead we wrap the seed in the fixed RFC 8410
// PKCS8 DER template for Ed25519 private keys, which Node can load directly and derive the public
// key from itself. Verified against generate_keypair.mjs's output that this reproduces the exact
// same public key.
const PKCS8_ED25519_PREFIX_HEX = '302e020100300506032b657004220420';
function loadPrivateKeyFromSeed(seedHex) {
    const seed = Buffer.from(seedHex, 'hex');
    const der = Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX_HEX, 'hex'), seed]);
    return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
const signingKey = loadPrivateKeyFromSeed(PRIVATE_SEED_HEX);

function signCertificate(licenseKey, machineId, seat, issuedAt) {
    const message = Buffer.from(`${licenseKey}|${machineId}|${seat}|${issuedAt}`, 'utf8');
    const signature = crypto.sign(null, message, signingKey);
    return signature.toString('hex');
}

// --- Database ---
const db = new DatabaseSync(DB_PATH);
db.exec(`
    CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        email TEXT,
        seat_limit INTEGER NOT NULL DEFAULT ${DEFAULT_SEAT_LIMIT},
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS activations (
        license_key TEXT NOT NULL,
        machine_id TEXT NOT NULL,
        seat INTEGER NOT NULL,
        activated_at TEXT NOT NULL,
        PRIMARY KEY (license_key, machine_id)
    );
`);

function randomLicenseKey() {
    // 4 groups of 5 base32-ish (uppercase alnum, ambiguity-reduced) characters: XXXXX-XXXXX-XXXXX-XXXXX
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
    const groups = [];
    for (let g = 0; g < 4; g++) {
        let s = '';
        for (let i = 0; i < 5; i++)
            s += alphabet[crypto.randomInt(alphabet.length)];
        groups.push(s);
    }
    return groups.join('-');
}

// --- HTTP helpers ---
function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
}

function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let chunks = [];
        let size = 0;
        req.on('data', (c) => {
            size += c.length;
            if (size > 1_000_000) { reject(new Error('body too large')); req.destroy(); return; }
            chunks.push(c);
        });
        req.on('end', () => {
            try {
                const text = Buffer.concat(chunks).toString('utf8');
                resolve(text.length ? JSON.parse(text) : {});
            } catch (e) { reject(e); }
        });
        req.on('error', reject);
    });
}

function isAdmin(req) {
    return req.headers['x-admin-secret'] === ADMIN_SECRET;
}

// Checks a license key that isn't in our local DB against Gumroad's own license verification API
// (Gumroad generates + emails the key itself at checkout when "Generate a unique license key per
// sale" is enabled on the product - no admin/issue call or email sending needed on our side).
// Returns 'valid', 'revoked' (refunded/chargebacked/subscription ended), or 'invalid'.
async function checkGumroadLicense(licenseKey) {
    if (!GUMROAD_PRODUCT_ID) return 'invalid';

    try {
        const params = new URLSearchParams({
            product_id: GUMROAD_PRODUCT_ID,
            license_key: licenseKey,
            increment_uses_count: 'false',
        });
        const gres = await fetch('https://api.gumroad.com/v2/licenses/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params,
        });
        const data = await gres.json();
        if (!data.success) return 'invalid';

        const p = data.purchase || {};
        if (p.refunded || p.chargebacked || p.subscription_cancelled_at || p.subscription_failed_at)
            return 'revoked';

        return { status: 'valid', email: String(p.email || '') };
    } catch (err) {
        console.error('Gumroad verification request failed:', err);
        return 'invalid';
    }
}

// Looks up a license in our local DB, auto-provisioning it from Gumroad on first sight if it's
// not there yet. Every subsequent activate/deactivate call still goes through our own
// `activations` table for seat tracking - Gumroad is only consulted to answer "is this a real,
// unrefunded key for this product?"
async function resolveLicense(licenseKey) {
    const existing = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(licenseKey);
    if (existing) return existing;

    const gumroadResult = await checkGumroadLicense(licenseKey);
    if (gumroadResult === 'invalid') return null;
    if (gumroadResult === 'revoked') return { license_key: licenseKey, revoked: 1, seat_limit: DEFAULT_SEAT_LIMIT };

    db.prepare('INSERT INTO licenses (license_key, email, seat_limit, revoked, created_at) VALUES (?, ?, ?, 0, ?)')
      .run(licenseKey, gumroadResult.email, DEFAULT_SEAT_LIMIT, new Date().toISOString());
    return db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(licenseKey);
}

// --- Route handlers ---
async function handleActivate(req, res) {
    const body = await readJsonBody(req);
    const licenseKey = String(body.licenseKey || '').trim().toUpperCase();
    const machineId = String(body.machineId || '').trim();

    if (!licenseKey || !machineId) return sendJson(res, 400, { error: 'licenseKey and machineId are required' });

    const license = await resolveLicense(licenseKey);
    if (!license) return sendJson(res, 404, { error: 'invalid_license' });
    if (license.revoked) return sendJson(res, 403, { error: 'license_revoked' });

    // Idempotent: if this exact machine already has a seat on this key, just re-issue its cert.
    const existing = db.prepare('SELECT * FROM activations WHERE license_key = ? AND machine_id = ?').get(licenseKey, machineId);
    if (existing) {
        const issuedAt = Math.floor(Date.now() / 1000);
        const signature = signCertificate(licenseKey, machineId, existing.seat, issuedAt);
        return sendJson(res, 200, { licenseKey, machineId, seat: existing.seat, issuedAt, signature });
    }

    const countRow = db.prepare('SELECT COUNT(*) AS n FROM activations WHERE license_key = ?').get(licenseKey);
    if (countRow.n >= license.seat_limit) {
        return sendJson(res, 403, { error: 'seat_limit_reached', seatLimit: license.seat_limit });
    }

    const seat = countRow.n + 1;
    const activatedAt = new Date().toISOString();
    db.prepare('INSERT INTO activations (license_key, machine_id, seat, activated_at) VALUES (?, ?, ?, ?)')
      .run(licenseKey, machineId, seat, activatedAt);

    const issuedAt = Math.floor(Date.now() / 1000);
    const signature = signCertificate(licenseKey, machineId, seat, issuedAt);
    return sendJson(res, 200, { licenseKey, machineId, seat, issuedAt, signature });
}

async function handleDeactivate(req, res) {
    const body = await readJsonBody(req);
    const licenseKey = String(body.licenseKey || '').trim().toUpperCase();
    const machineId = String(body.machineId || '').trim();

    if (!licenseKey || !machineId) return sendJson(res, 400, { error: 'licenseKey and machineId are required' });

    const result = db.prepare('DELETE FROM activations WHERE license_key = ? AND machine_id = ?').run(licenseKey, machineId);
    if (result.changes === 0) return sendJson(res, 404, { error: 'activation_not_found' });
    return sendJson(res, 200, { ok: true });
}

async function handleAdminIssue(req, res) {
    if (!isAdmin(req)) return sendJson(res, 401, { error: 'unauthorized' });

    const body = await readJsonBody(req);
    const email = String(body.email || '').trim();
    const seatLimit = Number.isInteger(body.seatLimit) ? body.seatLimit : DEFAULT_SEAT_LIMIT;

    let licenseKey;
    for (let attempt = 0; attempt < 5; attempt++) {
        licenseKey = randomLicenseKey();
        const clash = db.prepare('SELECT 1 FROM licenses WHERE license_key = ?').get(licenseKey);
        if (!clash) break;
        licenseKey = null;
    }
    if (!licenseKey) return sendJson(res, 500, { error: 'key_generation_failed' });

    db.prepare('INSERT INTO licenses (license_key, email, seat_limit, revoked, created_at) VALUES (?, ?, ?, 0, ?)')
      .run(licenseKey, email, seatLimit, new Date().toISOString());

    return sendJson(res, 200, { licenseKey, email, seatLimit });
}

async function handleAdminList(req, res) {
    if (!isAdmin(req)) return sendJson(res, 401, { error: 'unauthorized' });
    const licenses = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
    const activations = db.prepare('SELECT * FROM activations').all();
    return sendJson(res, 200, { licenses, activations });
}

async function handleAdminRevoke(req, res) {
    if (!isAdmin(req)) return sendJson(res, 401, { error: 'unauthorized' });
    const body = await readJsonBody(req);
    const licenseKey = String(body.licenseKey || '').trim().toUpperCase();
    if (!licenseKey) return sendJson(res, 400, { error: 'licenseKey is required' });
    const result = db.prepare('UPDATE licenses SET revoked = 1 WHERE license_key = ?').run(licenseKey);
    if (result.changes === 0) return sendJson(res, 404, { error: 'not_found' });
    return sendJson(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);

        if (req.method === 'GET' && url.pathname === '/health')
            return sendJson(res, 200, { ok: true, time: new Date().toISOString() });

        if (req.method === 'POST' && url.pathname === '/activate')
            return await handleActivate(req, res);

        if (req.method === 'POST' && url.pathname === '/deactivate')
            return await handleDeactivate(req, res);

        if (req.method === 'POST' && url.pathname === '/admin/issue')
            return await handleAdminIssue(req, res);

        if (req.method === 'GET' && url.pathname === '/admin/list')
            return await handleAdminList(req, res);

        if (req.method === 'POST' && url.pathname === '/admin/revoke')
            return await handleAdminRevoke(req, res);

        return sendJson(res, 404, { error: 'not_found' });
    } catch (err) {
        console.error(err);
        return sendJson(res, 500, { error: 'internal_error' });
    }
});

server.listen(PORT, () => {
    console.log(`License server listening on port ${PORT} (db: ${DB_PATH})`);
});
