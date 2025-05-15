// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,    
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now    // maps to created_at TIMESTAMP DEFAULT now()
  },
  phoneNumber: {
    type: String        // varchar in PG
  },
  faceDescriptor: {
    type: [Number],     // array of floats
    default: []
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  photoUrl: {
    type: String
  },
  verifyCode: {
    type: String
  },
  codeExpiresAt: {
    type: Date
  }
}, {
  // Optionally have .createdAt/.updatedAt automatically:
  timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' }
});

// Create an index on codeExpiresAt if you want auto‐cleanup

module.exports = mongoose.model('User', userSchema);
