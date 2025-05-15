// models/Room.js
const mongoose = require('mongoose');
const roomSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  minLat:    { type: Number, required: true },
  maxLat:    { type: Number, required: true },
  minLon:    { type: Number, required: true },
  maxLon:    { type: Number, required: true },
  selected:  { type: Boolean, default: false }
}, { timestamps: true });
module.exports = mongoose.model('Room', roomSchema);
