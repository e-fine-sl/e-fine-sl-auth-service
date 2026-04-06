// models/user.model.js
// Minimal "read-only" models pointing at the EXISTING Police & Driver 
// collections in the shared MongoDB Atlas database.
// Auth-service ONLY reads email + password + role for authentication.
// It never writes to these collections.
const mongoose = require('mongoose');

// ----- Police (collection: 'polices') -----
const policeAuthSchema = new mongoose.Schema({
  name:          String,
  email:         String,
  badgeNumber:   String,
  password:      String,
  role:          String,
  position:      String,
  policeStation: String,
  profileImage:  String,
  nic:           String,
}, { collection: 'polices', timestamps: true });

// ----- Driver (collection: 'drivers') -----
const driverAuthSchema = new mongoose.Schema({
  name:               String,
  email:              String,
  password:           String,
  role:               String,
  licenseNumber:      String,
  nic:                String,
  isVerified:         Boolean,
  kycVerified:        Boolean,
  profileImage:       String,
  licenseFrontImage:  String,
  licenseBackImage:   String,
  licenseStatus:      String,
  demeritPoints:      Number,
}, { collection: 'drivers', timestamps: true });

const PoliceUser = mongoose.model('PoliceUser', policeAuthSchema);
const DriverUser = mongoose.model('DriverUser', driverAuthSchema);

module.exports = { PoliceUser, DriverUser };
