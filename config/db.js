// config/db.js - MongoDB Atlas connection for auth-service
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`[AUTH-SERVICE] MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`[AUTH-SERVICE] MongoDB connection error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
