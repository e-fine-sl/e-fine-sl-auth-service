// utils/tokenService.js
// Generates and verifies all three token types.
// Expiry values are read from the database on every login call,
// so changing them in DB takes effect immediately - no server restart needed.

const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto   = require('crypto');
const TokenConfig = require('../models/tokenConfig.model');

// ── Token Config ──────────────────────────────────────────────────────────────

/**
 * Reads token expiry config from DB.
 * If no config document exists, creates a default one.
 * @returns {Object} token config document
 */
const getTokenConfig = async () => {
  let config = await TokenConfig.findOne();
  if (!config) {
    // Create defaults on first run
    config = await TokenConfig.create({
      access_token_expiry_minutes: 15,
      refresh_token_expiry_days:   7,
      session_token_expiry_days:   30,
    });
    console.log('[AUTH-SERVICE] Created default token_config document in DB');
  }
  return config;
};

// ── Access Token ──────────────────────────────────────────────────────────────

/**
 * Generates a short-lived JWT access token.
 * Payload: { userId, email, role }
 * @param {Object} payload - { userId, email, role }
 * @param {number} expiryMinutes - from DB config
 */
const generateAccessToken = (payload, expiryMinutes) => {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: `${expiryMinutes}m`,
    issuer: 'e-fine-sl-auth-service',
  });
};

/**
 * Verifies an access token and returns the decoded payload.
 * Returns null if invalid or expired.
 */
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, {
      issuer: 'e-fine-sl-auth-service',
    });
  } catch {
    return null;
  }
};

// ── Refresh Token ─────────────────────────────────────────────────────────────

/**
 * Generates a long-lived JWT refresh token.
 * @param {Object} payload - { userId, email, role }
 * @param {number} expiryDays - from DB config
 */
const generateRefreshToken = (payload, expiryDays) => {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: `${expiryDays}d`,
    issuer: 'e-fine-sl-auth-service',
  });
};

/**
 * Verifies a refresh token. Returns decoded payload or null.
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
      issuer: 'e-fine-sl-auth-service',
    });
  } catch {
    return null;
  }
};

// ── Session Token ─────────────────────────────────────────────────────────────

/**
 * Generates a random UUID session token.
 * This is NOT a JWT - it is a random identifier stored in DB.
 */
const generateSessionToken = () => uuidv4();

/**
 * Creates a SHA-256 hash of a refresh token for safe DB storage.
 * We never store the raw refresh JWT in DB.
 */
const hashToken = (token) =>
  crypto.createHash('sha256').update(token).digest('hex');

module.exports = {
  getTokenConfig,
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateSessionToken,
  hashToken,
};
