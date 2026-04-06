// server.js — Entry point for e-Fine SL Auth Microservice
// Run standalone on PORT 4000 (or $env:PORT on Render)

const express   = require('express');
const dotenv    = require('dotenv');
const cors      = require('cors');
const connectDB = require('./config/db');

dotenv.config();
connectDB();

const app = express();

// Allow cross-origin requests from the Flutter app and main backend
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    service: 'e-Fine SL Auth Microservice',
    version: '1.0.0',
    status:  'running',
    time:    new Date().toISOString(),
  });
});

// ── Auth Routes ───────────────────────────────────────────────────────────────
app.use('/auth', require('./routes/auth.routes'));

// ── 404 Handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  console.warn(`[AUTH-SERVICE] 404 — ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// ── Global Error Handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[AUTH-SERVICE] Unhandled error:', err.message);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// ── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[AUTH-SERVICE] Running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  console.log(`[AUTH-SERVICE] Health: http://localhost:${PORT}/`);
  console.log(`[AUTH-SERVICE] Public Key: http://localhost:${PORT}/auth/public-key`);
});
