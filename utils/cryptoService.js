// utils/cryptoService.js
// RSA decryption using node-forge.
// The Flutter app encrypts passwords with the RSA PUBLIC key (OAEP-SHA1).
// This service decrypts them using the RSA PRIVATE key stored in .env.
// Public key is also served to Flutter via GET /auth/public-key.

const forge = require('node-forge');

/**
 * Decrypts an RSA-OAEP (SHA-1) encrypted, base64-encoded password.
 * @param {string} encryptedBase64 - base64 string received from Flutter
 * @returns {string} - the original plain-text password
 * @throws if decryption fails (wrong key, tampered data, etc.)
 */
const decryptPassword = (encryptedBase64) => {
  const privateKeyPem = process.env.RSA_PRIVATE_KEY;
  if (!privateKeyPem) {
    throw new Error('RSA_PRIVATE_KEY not set in environment variables');
  }

  // Restore newlines if the key was stored with literal \n in .env
  const formattedKey = privateKeyPem.replace(/\\n/g, '\n');

  const privateKey = forge.pki.privateKeyFromPem(formattedKey);

  // Decode base64 to binary string (forge format)
  const encryptedBytes = forge.util.decode64(encryptedBase64);

  // Decrypt using OAEP padding (matches pointycastle OAEPEncoding on Flutter side)
  const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP');

  return decrypted;
};

/**
 * Returns the RSA public key PEM string to serve to Flutter clients.
 * Flutter fetches this at startup via GET /auth/public-key.
 */
const getPublicKeyPem = () => {
  const privateKeyPem = process.env.RSA_PRIVATE_KEY;
  if (!privateKeyPem) {
    throw new Error('RSA_PRIVATE_KEY not set in environment variables');
  }

  const formattedKey = privateKeyPem.replace(/\\n/g, '\n');
  const privateKey = forge.pki.privateKeyFromPem(formattedKey);

  // Derive the public key from the private key
  const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
  return forge.pki.publicKeyToPem(publicKey);
};

module.exports = { decryptPassword, getPublicKeyPem };
