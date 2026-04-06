// models/session.model.js
// Tracks every active login session.
// Allows: session list, remote logout, refresh token revocation.
const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId:           { type: String, required: true, index: true },
  userRole:         { type: String, required: true },

  // UUID session token stored in Flutter secure storage
  sessionToken:     { type: String, required: true, unique: true, index: true },

  // SHA-256 hash of the refresh JWT - used to validate & revoke refresh tokens
  refreshTokenHash: { type: String, required: true, index: true },

  // Device/browser info for "active sessions" display
  deviceInfo:       { type: String, default: 'Unknown' },

  createdAt:        { type: Date, default: Date.now },
  expiresAt:        { type: Date, required: true },

  // Set to true on logout or revocation
  isRevoked:        { type: Boolean, default: false },
});

// Auto-delete expired sessions from DB after 30 days past expiry
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 2592000 });

module.exports = mongoose.model('Session', sessionSchema, 'auth_sessions');
