require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const faceapi = require("face-api.js");
const path = require("path");
const transporter = require('./mailer');
const http = require("http");
const { Server } = require("socket.io");

// Start server
const app = express();
const PORT = process.env.PORT || 5000;
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});
io.on("connection", (socket) => {
  console.log("⚡️ New client connected:", socket.id);

  // Optionally, you can listen for custom events from client:
  // socket.on("joinRoom", (roomId) => { socket.join(roomId); });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

console.log("[CONFIG] Loading environment variables...");
console.log("[CONFIG] MONGO_URI =", process.env.MONGO_URI);
console.log("[CONFIG] CLIENT_URL =", process.env.CLIENT_URL);
console.log("[CONFIG] BACKEND_URL =", process.env.BACKEND_URL);
console.log("[CONFIG] FRONTEND_URL =", process.env.FRONTEND_URL);
// Verify SMTP connectivity
transporter.verify((err, success) => {
  if (err) console.error("[MAILER] SMTP connection failed:", err.stack || err);
  else console.log("[MAILER] SMTP ready to send messages");
});


mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('[DB] Connected to MongoDB'))
  .catch(err => console.error('[DB] MongoDB connection error:', err));

// Load models
const User = require("./models/User");
const Admin = require("./models/Admin");
const Room = require("./models/Room");
const Attendance = require("./models/Attendance");

// Passport setup
const initializePassport = require("./passportConfig");
initializePassport(passport);
const initializePassportAdmin = require("./passportConfigAdmin");
initializePassportAdmin(passport);



// Middlewares
const corsOptions = {
  origin: process.env.NODE_ENV === "production"
    ? [process.env.CLIENT_URL, process.env.FRONTEND_URL]
    : ["http://localhost:5173"],
  credentials: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
}; 

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));


app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// Trust proxy
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 60 * 60
  }),
  cookie: {
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Rate limiter for marking attendance
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1,
  keyGenerator: (req) => req.user?.id || req.ip,
  message: "You have already marked your attendance for this hour."
});

// Health check
app.get('/', (req, res) => {
  console.log('[HEALTH] GET /');
  res.send('Backend running');
});
const multer  = require("multer");
const fs      = require("fs");

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
  console.log("[MULTER] Created uploads directory:", uploadDir);
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // e.g. user-12345-1633024800000.jpg
    const ext = path.extname(file.originalname);
    const name = `user-${req.user.id}-${Date.now()}${ext}`;
    cb(null, name);
  }
});

const fileFilter = (req, file, cb) => {
  // accept only images
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed."), false);
  }
};

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files are allowed."), false);
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});
// Serve the uploads folder statically
app.use("/uploads", express.static(uploadDir));


// --- API ROUTES ---


// USER LOGIN (face + password)

app.post('/users/login', async (req, res) => {
  const { email, password, face_descriptor } = req.body;
  if (!face_descriptor) return res.status(400).json({ message: "Face descriptor is required." });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found." });
    if (!user.isVerified) return res.status(403).json({ message: "Please verify your email first." });
    if (!user.faceDescriptor.length) return res.status(400).json({ message: "No face descriptor found." });

    const distance = faceapi.euclideanDistance(user.faceDescriptor, face_descriptor);
    if (distance < 0.6) {
      req.logIn(user, err => {
        if (err) return res.status(500).json({ message: "Internal Server Error" });
        req.session.save(err => {
          if (err) return res.status(500).json({ message: "Session save failed." });
          res.json({ message: "Login successful", user: { id: user._id, email: user.email } });
        });
      });
    } else {
      res.status(400).json({ message: "Face recognition failed." });
    }
  } catch (err) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post('/users/register', async (req, res) => {
  const { email, password, phoneNumber, face_descriptor } = req.body;
  try {
    if (await User.exists({ email })) return res.status(400).json({ message: "Email already in use." });
    const hashed = await bcrypt.hash(password, 10);
    const code = Math.floor(100000 + Math.random()*900000).toString();
      const user = new User({
        email,
        password: hashed,
        phoneNumber,
        faceDescriptor: Array.isArray(face_descriptor) ? face_descriptor : [],
        verifyCode: code,
        codeExpiresAt: Date.now() + 3600000
      });    await user.save();
   await transporter.sendMail({
  from: `"Attendance‑Tracker" <${process.env.SMTP_USER}>`,
  to: email,
  subject: "🔒 Your Attendance‑Tracker Verification Code",
  html: `
    <div style="
      max-width:600px;
      margin:0 auto;
      font-family:Arial, sans-serif;
      color:#333;
      border:1px solid #ececec;
      border-radius:8px;
      overflow:hidden;
    ">
      <!-- Header -->
      <div style="
        background-color:#4A90E2;
        padding:20px;
        text-align:center;
      ">
        <h1 style="color:#fff; margin:0; font-size:24px;">Attendance‑Tracker</h1>
      </div>

      <!-- Body -->
      <div style="padding:30px; text-align:center;">
        <p style="font-size:16px; margin-bottom:30px;">
          Hello <strong>${email}</strong>,<br/>
          Your one‑time verification code is:
        </p>

        <!-- Code box -->
        <div style="
          display:inline-block;
          padding:20px 30px;
          font-size:32px;
          letter-spacing:4px;
          background-color:#F5F7FA;
          border:2px dashed #4A90E2;
          border-radius:4px;
          margin-bottom:30px;
        ">
          ${code}
        </div>

        <p style="font-size:14px; color:#666; margin-bottom:0;">
          This code will expire in <strong>60 minutes</strong>.<br/>
          If you did not request this, you can safely ignore this email.
        </p>
      </div>

      <!-- Footer -->
      <div style="
        background-color:#f4f4f4;
        padding:15px 30px;
        font-size:12px;
        color:#999;
        text-align:center;
      ">
        © ${new Date().getFullYear()} Attendance‑Tracker. All rights reserved.
      </div>
    </div>
  `
});
    res.status(201).json({ message: "Registration successful. Check your email." });
  } catch (err) {
    res.status(500).json({ message: "Failed to register user." });
  }
});

// RESEND VERIFICATION
app.post('/users/resend-verification', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found." });
    if (user.isVerified) return res.status(400).json({ message: "Already verified." });

    const code = Math.floor(100000 + Math.random()*900000).toString();
    user.verifyCode = code;
    user.codeExpiresAt = Date.now() + 3600000;
    await user.save();

    await transporter.sendMail({
      from: `"Your App" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your new verification code",
      html: `<p>Your new verification code is:</p><h2>${code}</h2><p>Expires in 1 hour.</p>`
    });
    res.json({ message: "Verification code sent." });
  } catch (err) {
    res.status(500).json({ message: "Failed to resend." });
  }
});


// VERIFY CODE
app.post('/users/verify-code', async (req, res) => {
  const { email, code } = req.body;
  try {
    const user = await User.findOne({ email, verifyCode: code });
    if (!user) return res.status(400).json({ message: "Invalid verification code." });
    if (user.codeExpiresAt < Date.now()) return res.status(400).json({ message: "Verification code expired." });

    user.isVerified = true;
    user.verifyCode = null;
    user.codeExpiresAt = null;
    await user.save();

    req.logIn(user, err => {
      if (err) return res.status(500).json({ message: "Login after verification failed." });
      req.session.save(err => {
        if (err) return res.status(500).json({ message: "Session save failed." });
        res.json({ message: "Email verified and logged in.", user: { id: user._id, email: user.email } });
      });
    });
  } catch (err) {
    res.status(500).json({ message: "Verification failed." });
  }
});
// ADMIN LOGIN
app.post('/admin/login', (req, res, next) => {
  passport.authenticate('admin-local', (err, admin, info) => {
    if (err) return next(err);
    if (!admin) return res.status(400).json({ message: info.message });
    req.logIn(admin, err => {
      if (err) return next(err);
      res.json({ message: 'Login successful', admin });
    });
  })(req, res, next);
});

// ADMIN: list & select rooms
app.get('/admin/rooms', async (req, res) => {
  try { const rooms = await Room.find(); res.json(rooms); }
  catch (err) { res.status(500).send('Failed to fetch rooms.'); }
});
app.post("/admin/select-room", async (req, res) => {
  console.log("[BACKEND] POST /admin/select-room RECEIVED. Body:", req.body);

  const { roomId } = req.body;
  if (!roomId) {
    console.warn("[BACKEND] Missing roomId in request");
    return res.status(400).send("Missing roomId");
  }

  try {
    // 1) Deselect any currently‐selected rooms
    const deselectResult = await Room.updateMany(
      { selected: true },
      { selected: false }
    );
    console.log(
      `[BACKEND] updateMany deselect result: { n: ${deselectResult.n}, nModified: ${deselectResult.nModified} }`
    );

    // 2) Mark the requested room as selected
    const updatedRoom = await Room.findByIdAndUpdate(
      roomId,
      { selected: true },
      { new: true }
    );
    if (!updatedRoom) {
      console.error(`[BACKEND] No room found with ID ${roomId}`);
      return res.status(404).send("Room not found");
    }
    console.log(`[BACKEND] Room ${roomId} marked as selected:`, updatedRoom);

    return res.send("Room selected successfully");
  } catch (err) {
    console.error("[BACKEND] Error in /admin/select-room:", err);
    return res.status(500).send("Failed to select room. Please try again.");
  }
});
// MARK ATTENDANCE
app.post('/mark-attendance', limiter, async (req, res) => {
  const { name, rollNumber, lat, lon } = req.body;
  const latitude = parseFloat(lat);
  const longitude = parseFloat(lon);

  try {
    const room = await Room.findOne({ selected: true });
    if (!room) return res.status(400).send('No room selected by the admin.');

    if (
      latitude >= room.minLat && latitude <= room.maxLat &&
      longitude >= room.minLon && longitude <= room.maxLon
    ) {
      const record = await Attendance.create({ 
        user: req.user._id, 
        name, 
        rollNumber, 
        latitude, 
        longitude 
      });

      // Emit the new attendance object to all connected clients (e.g., admin dashboard)
      io.emit("newAttendance", {
        id: record._id,
        name: record.name,
        rollNumber: record.rollNumber,
        latitude: record.latitude,
        longitude: record.longitude,
        createdAt: record.createdAt
      });

      return res.send(`Attendance marked successfully for: ${name}`);
    } else {
      return res.status(400).send('You are not in the selected room.');
    }
  } catch (err) {
    return res.status(500).send('Failed to mark attendance. Please try again.');
  }
});

app.get("/admin/dashboard", async (req, res) => {
  console.log("[BACKEND] GET /admin/dashboard");
  try {
    const rooms = await Room.find();
    console.log(`[BACKEND] Fetched ${rooms.length} rooms`);
    return res.json(rooms);
  } catch (err) {
    console.error("[BACKEND] Error fetching /admin/dashboard:", err);
    return res.status(500).send("Failed to fetch rooms.");
  }
});

app.post("/admin/dashboard", async (req, res) => {
  console.log("[BACKEND] POST /admin/dashboard RECEIVED. Body:", req.body);
  const { name, minLat, maxLat, minLon, maxLon } = req.body;

  if (
    !name ||
    minLat === undefined ||
    maxLat === undefined ||
    minLon === undefined ||
    maxLon === undefined
  ) {
    console.warn("[BACKEND] Missing field(s) in add-room payload");
    return res.status(400).send("All fields are required");
  }

  try {
    const room = new Room({ name, minLat, maxLat, minLon, maxLon });
    await room.save();
    console.log("[BACKEND] New room saved:", room);
    return res.json(room);
  } catch (err) {
    console.error("[BACKEND] Error saving new room:", err);
    return res.status(500).send("Failed to add room. Please try again.");
  }
});
// USER LOGOUT
app.post('/users/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.clearCookie('connect.sid', { path: '/' });
      res.json({ message: 'Logout successful' });
    });
  });
});
// GET user profile
app.get('/users/profile', (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  res.json({ email: req.user.email, phoneNumber: req.user.phoneNumber, photoUrl: req.user.photoUrl });
});

// GET attendance history
app.get('/users/attendance-history', async (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  try {
    const records = await Attendance.find({ user: req.user._id }).sort('-createdAt');
    res.json(records);
  } catch (err) { next(err); }
});

// POST profile photo upload
app.post('/users/profile/photo', upload.single('photo'), async (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  try {
    const url = `/uploads/${req.file.filename}`;
    req.user.photoUrl = url;
    await req.user.save();
    res.json({ photoUrl: url });
  } catch (err) { next(err); }
});
// Error handler
app.use((err, req, res, next) => {
  console.error('[FATAL]', err.stack);
  res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

// Start listening on HTTP
server.listen(PORT, () => {
  console.log(`Server + WebSocket running on port ${PORT}`);
});
