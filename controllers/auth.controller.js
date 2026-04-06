// controllers/auth.controller.js
// Core authentication logic for the e-Fine SL auth microservice.
// Handles: login, logout, token refresh, token verification, public key serving,
//          and token expiry configuration management.

const bcrypt       = require('bcryptjs');
const crypto       = require('crypto');
const { PoliceUser, DriverUser } = require('../models/user.model');
const Session      = require('../models/session.model');
const TokenConfig  = require('../models/tokenConfig.model');
const tokenService = require('../utils/tokenService');
const cryptoService = require('../utils/cryptoService');

// ── GET /auth/public-key ──────────────────────────────────────────────────────
// Returns the RSA public key PEM so Flutter can encrypt passwords before sending.
// This endpoint is PUBLIC - no auth required.
const getPublicKey = (req, res) => {
  try {
    const publicKeyPem = cryptoService.getPublicKeyPem();
    return res.status(200).json({
      success: true,
      publicKey: publicKeyPem,
    });
  } catch (error) {
    console.error('[AUTH/PUBLIC-KEY] Error:', error.message);
    return res.status(500).json({ success: false, message: 'Could not retrieve public key' });
  }
};

// ── POST /auth/login ──────────────────────────────────────────────────────────
// Accepts RSA-encrypted password, verifies against bcrypt hash, returns 3 tokens.
const login = async (req, res) => {
  try {
    const { email, encryptedPassword } = req.body;

    if (!email || !encryptedPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email and encryptedPassword are required',
      });
    }

    // Step 1: Decrypt the RSA-OAEP encrypted password using private key
    let plainPassword;
    try {
      plainPassword = cryptoService.decryptPassword(encryptedPassword);
    } catch (decryptErr) {
      console.error('[AUTH/LOGIN] RSA decryption failed:', decryptErr.message);
      return res.status(400).json({
        success: false,
        message: 'Invalid encrypted password format',
      });
    }

    // Step 2: Find user in Police or Driver collections (shared MongoDB)
    let user = null;
    let role = '';

    const officer = await PoliceUser.findOne({ email });
    if (officer) {
      user = officer;
      role = officer.role || 'officer';
    } else {
      const driver = await DriverUser.findOne({ email });
      if (driver) {
        user = driver;
        role = 'driver';
      }
    }

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Step 3: Verify decrypted password against bcrypt hash in DB
    const isMatch = await bcrypt.compare(plainPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Step 4: Read token configuration from DB (not hardcoded!)
    const tokenConfig = await tokenService.getTokenConfig();

    // Step 5: Build JWT payload
    const payload = {
      userId: user._id.toString(),
      email:  user.email,
      role:   role,
    };

    // Step 6: Generate all three tokens
    const accessToken   = tokenService.generateAccessToken(payload, tokenConfig.access_token_expiry_minutes);
    const refreshToken  = tokenService.generateRefreshToken(payload, tokenConfig.refresh_token_expiry_days);
    const sessionToken  = tokenService.generateSessionToken();

    // Step 7: Persist session record in DB
    const sessionExpiresAt = new Date();
    sessionExpiresAt.setDate(sessionExpiresAt.getDate() + tokenConfig.session_token_expiry_days);

    await Session.create({
      userId:           user._id.toString(),
      userRole:         role,
      sessionToken:     sessionToken,
      refreshTokenHash: tokenService.hashToken(refreshToken),
      deviceInfo:       req.headers['user-agent'] || 'Unknown Device',
      expiresAt:        sessionExpiresAt,
    });

    // Step 8: Return tokens + user profile data
    return res.status(200).json({
      success: true,
      accessToken,
      refreshToken,
      sessionToken,
      user: {
        userId:           user._id.toString(),
        name:             user.name,
        email:            user.email,
        role:             role,
        badgeNumber:      user.badgeNumber      || undefined,
        position:         user.position         || undefined,
        policeStation:    user.policeStation     || undefined,
        profileImage:     user.profileImage      || undefined,
        licenseFrontImage: user.licenseFrontImage || undefined,
        licenseBackImage:  user.licenseBackImage  || undefined,
        isVerified:       user.isVerified        || false,
        licenseNumber:    user.licenseNumber      || undefined,
        nic:              user.nic               || undefined,
        licenseStatus:    user.licenseStatus      || undefined,
        demeritPoints:    user.demeritPoints      || undefined,
        kycVerified:      user.kycVerified        || false,
      },
    });

  } catch (error) {
    console.error('[AUTH/LOGIN] Unexpected error:', error.message);
    return res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
};

// ── POST /auth/logout ─────────────────────────────────────────────────────────
// Revokes the session so the refresh token can no longer be used.
const logout = async (req, res) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({ success: false, message: 'sessionToken is required' });
    }

    const session = await Session.findOneAndUpdate(
      { sessionToken },
      { isRevoked: true },
    );

    if (!session) {
      // Already revoked or non-existent - treat as success
      return res.status(200).json({ success: true, message: 'Logged out successfully' });
    }

    console.log(`[AUTH/LOGOUT] Session revoked for userId: ${session.userId}`);
    return res.status(200).json({ success: true, message: 'Logged out successfully' });

  } catch (error) {
    console.error('[AUTH/LOGOUT] Error:', error.message);
    return res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
};

// ── POST /auth/refresh ────────────────────────────────────────────────────────
// Accepts a refresh token, validates it against DB, returns a new access token.
const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ success: false, message: 'refreshToken is required' });
    }

    // Step 1: Verify JWT signature and expiry
    const decoded = tokenService.verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }

    // Step 2: Look up session by refresh token hash
    const refreshHash = tokenService.hashToken(refreshToken);
    const session = await Session.findOne({ refreshTokenHash: refreshHash });

    if (!session) {
      return res.status(401).json({ success: false, message: 'Refresh token not found' });
    }

    // Step 3: Check revocation
    if (session.isRevoked) {
      return res.status(401).json({ success: false, message: 'Refresh token has been revoked' });
    }

    // Step 4: Check session expiry
    if (session.expiresAt < new Date()) {
      await Session.findByIdAndUpdate(session._id, { isRevoked: true });
      return res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.',
      });
    }

    // Step 5: Issue new access token
    const tokenConfig = await tokenService.getTokenConfig();
    const payload = {
      userId: decoded.userId,
      email:  decoded.email,
      role:   decoded.role,
    };
    const newAccessToken = tokenService.generateAccessToken(payload, tokenConfig.access_token_expiry_minutes);

    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
    });

  } catch (error) {
    console.error('[AUTH/REFRESH] Error:', error.message);
    return res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
};

// ── GET /auth/verify ──────────────────────────────────────────────────────────
// Called by the MAIN BACKEND middleware to validate every incoming API request.
// Protected by x-internal-secret header so only main backend can call it.
const verify = async (req, res) => {
  try {
    // Step 1: Validate internal secret (ensures only main backend calls this)
    const internalSecret = req.headers['x-internal-secret'];
    if (!internalSecret || internalSecret !== process.env.INTERNAL_SECRET) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    // Step 2: Extract access token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    // Step 3: Verify the access token JWT
    const decoded = tokenService.verifyAccessToken(token);
    if (!decoded) {
      return res.status(401).json({ success: false, message: 'Invalid or expired access token' });
    }

    // Step 4: Return user payload to main backend
    return res.status(200).json({
      success: true,
      user: {
        id:     decoded.userId,  // 'id' for backward compat with req.user.id
        userId: decoded.userId,
        email:  decoded.email,
        role:   decoded.role,
      },
    });

  } catch (error) {
    console.error('[AUTH/VERIFY] Error:', error.message);
    return res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
};

// ── GET /auth/config ──────────────────────────────────────────────────────────
// Returns current token expiry configuration. Admin use only.
const getConfig = async (req, res) => {
  try {
    const config = await tokenService.getTokenConfig();
    return res.status(200).json({ success: true, config });
  } catch (error) {
    console.error('[AUTH/CONFIG] Error:', error.message);
    return res.status(500).json({ success: false, message: 'Server Error' });
  }
};

// ── PATCH /auth/config ────────────────────────────────────────────────────────
// Updates token expiry times in DB. Takes effect on next login immediately.
const updateConfig = async (req, res) => {
  try {
    const {
      access_token_expiry_minutes,
      refresh_token_expiry_days,
      session_token_expiry_days,
    } = req.body;

    const update = { updated_at: new Date() };
    if (access_token_expiry_minutes) update.access_token_expiry_minutes = Number(access_token_expiry_minutes);
    if (refresh_token_expiry_days)   update.refresh_token_expiry_days   = Number(refresh_token_expiry_days);
    if (session_token_expiry_days)   update.session_token_expiry_days   = Number(session_token_expiry_days);

    let config = await TokenConfig.findOne();
    if (!config) {
      config = await TokenConfig.create(update);
    } else {
      config = await TokenConfig.findByIdAndUpdate(config._id, update, { new: true });
    }

    return res.status(200).json({
      success: true,
      message: 'Token configuration updated. Takes effect on next login.',
      config,
    });

  } catch (error) {
    console.error('[AUTH/CONFIG-UPDATE] Error:', error.message);
    return res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
};

module.exports = { getPublicKey, login, logout, refresh, verify, getConfig, updateConfig };
