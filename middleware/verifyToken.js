// middleware/verifyToken.js
// Internal middleware for auth-service's own protected admin endpoints
// (GET /auth/config, PATCH /auth/config).
// Validates the access token AND checks the internal secret header.

const tokenService = require('../utils/tokenService');

/**
 * Verifies that the request comes from an authorized admin.
 * Checks: x-internal-secret header + valid access token with admin/super_admin role.
 */
const verifyAdminAccess = (req, res, next) => {
  // 1. Check internal secret (prevents public access)
  const internalSecret = req.headers['x-internal-secret'];
  if (!internalSecret || internalSecret !== process.env.INTERNAL_SECRET) {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Invalid or missing internal secret',
    });
  }

  // 2. Check access token
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No access token provided' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = tokenService.verifyAccessToken(token);

  if (!decoded) {
    return res.status(401).json({ success: false, message: 'Invalid or expired access token' });
  }

  // 3. Role check
  const adminRoles = ['admin', 'super_admin', 'admin_officer'];
  if (!adminRoles.includes(decoded.role)) {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Admin access required',
    });
  }

  req.user = decoded;
  next();
};

module.exports = { verifyAdminAccess };
