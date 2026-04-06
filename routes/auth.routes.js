// routes/auth.routes.js
// All authentication endpoints for the e-Fine SL auth microservice.

const express    = require('express');
const router     = express.Router();
const controller = require('../controllers/auth.controller');
const { verifyAdminAccess } = require('../middleware/verifyToken');

// ── PUBLIC ENDPOINTS (no auth required) ──────────────────────────────────────

// GET  /auth/public-key  — Flutter fetches RSA public key at app startup
router.get('/public-key', controller.getPublicKey);

// POST /auth/login  — Flutter sends { email, encryptedPassword }
router.post('/login', controller.login);

// POST /auth/logout — Flutter sends { sessionToken }
router.post('/logout', controller.logout);

// POST /auth/refresh — Flutter sends { refreshToken }, gets new accessToken
router.post('/refresh', controller.refresh);

// ── INTERNAL ENDPOINT (main backend only, protected by x-internal-secret) ────

// GET /auth/verify — Main backend calls this to validate every request
router.get('/verify', controller.verify);

// ── ADMIN ENDPOINTS (requires access token + internal secret) ─────────────────

// GET   /auth/config — View current token expiry settings
router.get('/config', verifyAdminAccess, controller.getConfig);

// PATCH /auth/config — Update token expiry settings (takes effect on next login)
router.patch('/config', verifyAdminAccess, controller.updateConfig);

module.exports = router;
