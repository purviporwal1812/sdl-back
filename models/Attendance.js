// models/Attendance.js
const mongoose = require('mongoose');
const attendanceSchema = new mongoose.Schema({
  user:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:      { type: String, required: true },
  rollNumber:{ type: String, required: true },
  latitude:  { type: Number, required: true },
  longitude: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Attendance', attendanceSchema);
