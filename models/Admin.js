// models/Admin.js
const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
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
}, {
  timestamps: { createdAt: 'createdAt', updatedAt: false }
  // we only care about createdAt, so we disable updatedAt here
});

module.exports = mongoose.model('Admin', adminSchema);
