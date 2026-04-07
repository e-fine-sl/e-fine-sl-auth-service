# e-Fine SL Auth Microservice

## Overview / Value of this Microservice
This is a standalone authentication microservice decoupled from the main Node.js backend. Its primary value and responsibilities are:
- **Decoupled Security Layer**: Centralizes all user authentication, token generation, and password verification logic separate from core business features.
- **Three-Token Security System**: Issues and manages Short-lived Access Tokens, Long-lived Refresh Tokens, and an opaque stateful Session Token.
- **Asymmetric Encryption**: Seamlessly distributes an RSA Public Key to the Flutter mobile application, allowing clients to encrypt raw passwords over the network before transmission.
- **Dynamic Token Profiles**: Retrieves and manages token expiration times using a database-driven `Config` collection, allowing admins to edit security policies dynamically.
- **Inter-service Verification**: Provides a fast and secure internal `/auth/verify` endpoint for the main backend to validate incoming requested tokens before processing routes.

## Directory Structure & File Format

```text
auth-service/
├── .env                # Environment variables (DB URI, JWT Secrets, RSA Keys)
├── server.js           # Entry point and Express application configuration
├── package.json        # Dependencies (Express, jsonwebtoken, bcryptjs, mongoose, etc.)
├── config/             # Configuration modules
│   └── db.js           # MongoDB connection logic
├── controllers/        # Route logic and business rules
│   └── auth.controller.js # Core implementation rules for login, refresh, verify etc.
├── middleware/         # Express middlewares
│   └── verifyToken.js  # Validates Admin tokens and x-internal-secret for microservices
├── models/             # Mongoose database schemas
│   ├── Config.js       # Models settings for Token Expiry profiles
│   ├── Session.js      # Models active user sessions and refresh-tokens
│   └── User.js         # Models the remote User collection (handles password comparison)
├── routes/             # Express routing configurations
│   └── auth.routes.js  # Maps HTTP endpoints to distinct controller functions
└── utils/              # Helper utilities
    └── cryptoUtils.js  # RSA decryption logic leveraging node-forge
```

## Functions and Endpoints

### Public Endpoints (Client / Flutter app)
- **`GET /auth/public-key`**: Provides the RSA Public Key. The mobile client queries this during boot to encrypt passwords.
- **`POST /auth/login`**: Authenticates a user. Expects `{ email, encryptedPassword }`. Uses node-forge to decrypt the payload on the backend, then `bcrypt` to compare against DB. Returns the Access, Refresh, and Session tokens.
- **`POST /auth/refresh`**: Generates a new short-lived token without requiring re-login. Expects `{ refreshToken }`. 
- **`POST /auth/logout`**: Tears down the user's active session. Expects `{ sessionToken }`.

### Internal Inter-Service Endpoint (Main Backend)
- **`GET /auth/verify`**: Restricted by `x-internal-secret` and `authorization` headers. The main backend delegates JWT verification requests here by transmitting client Access tokens directly. It returns `{ isValid, user }` verifying scope privileges securely.

### Admin Configuration Endpoints
- **`GET /auth/config`**: Requires Admin Access Token + Inter-service secret. Retrieves current global system token expiry settings from DB.
- **`PATCH /auth/config`**: Requires Admin Access Token + Inter-service secret. Edits/Patch token expiry configuration parameters. Changes take effect on subsequent logins.

## Running the Service Locally

```bash
# First, ensure required environment variables (.env) are populated.

# 1. Install dependencies
npm install

# 2. Run in Development Mode with Nodemon
npm run dev

# 3. View Local running instance details
# Typically defaults to: http://localhost:4000/
```

## Deployment (Render)

To deploy this microservice on Render, follow these steps:

1. **Push to GitHub**: Make sure the `auth-service` code is pushed to your GitHub repository.
2. **Create Web Service**: Open Render Dashboard, click **New +** and select **Web Service**.
3. **Connect Repository**: Choose the GitHub repository containing your project.
4. **Configure Settings**:
   - **Root Directory**: If `auth-service` is inside a larger repository (monorepo), type `auth-service` here. If it is its own repository, leave it blank (`.`).
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. **Environment Variables**: Scroll down to the Environment Variables section and add all the keys from your local `.env` file (e.g., `MONGO_URI`, `JWT_ACCESS_SECRET`, `RSA_PRIVATE_KEY_BASE64`, `INTERNAL_API_SECRET`). You do not need to add the `PORT` variable as Render manages it automatically.
6. **Deploy**: Click **Create Web Service** to start the build and deployment process.
