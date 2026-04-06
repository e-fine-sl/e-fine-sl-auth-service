// models/tokenConfig.model.js
// Stores token expiry configuration in the database.
// Admin can update these values via PATCH /auth/config
// without restarting the server - they take effect on next login.
const mongoose = require('mongoose');

const tokenConfigSchema = new mongoose.Schema({
  access_token_expiry_minutes: { type: Number, default: 15 },
  refresh_token_expiry_days:   { type: Number, default: 7  },
  session_token_expiry_days:   { type: Number, default: 30 },
  updated_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model('TokenConfig', tokenConfigSchema, 'token_config');
