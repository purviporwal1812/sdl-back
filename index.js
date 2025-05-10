require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const passport = require("passport");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const faceapi = require("face-api.js");
const path = require("path");
const crypto = require('crypto');
const transporter = require('./mailer');



// Load and log environment
console.log("[CONFIG] Loading environment variables...");
console.log("[CONFIG] POSTGRES_URL =", process.env.POSTGRES_URL);
console.log("[CONFIG] CLIENT_URL =", process.env.CLIENT_URL);
console.log("[CONFIG] BACKEND_URL =", process.env.BACKEND_URL);
console.log("[CONFIG] FRONTEND_URL =", process.env.FRONTEND_URL);

// Verify SMTP connectivity
transporter.verify((err, success) => {
  if (err) console.error("[MAILER] SMTP connection failed:", err.stack || err);
  else console.log("[MAILER] SMTP ready to send messages");
});
const app = express();
const PORT = process.env.PORT || 5000;

// PG pool
const pool = new Pool({ 
  connectionString: process.env.POSTGRES_URL 
});

// Passport setup
const initializePassport = require("./passportConfig");
initializePassport(passport);
const initializePassportAdmin = require("./passportConfigAdmin");
initializePassportAdmin(passport);



// Middlewares
app.use(cors({
  origin: [process.env.CLIENT_URL, process.env.FRONTEND_URL],
  credentials: true 
  }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// Trust proxy
app.set('trust proxy', 1);

app.use(session({
  store: new PgSession({ pool }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  sameSite: 'none',
  cookie: {
    secure: true,
    maxAge: 1000 * 60 * 60, // 1 hour
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Rate limiter for marking attendance
const limiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 1, message: "You have already marked your attendance for this hour." });

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

const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB limit

// Serve the uploads folder statically
app.use("/uploads", express.static(uploadDir));


// --- API ROUTES ---


// USER LOGIN (face + password)

app.post("/users/login", async (req, res, next) => {
  console.log('[LOGIN] Request body:', req.body);
  const { email, password, face_descriptor } = req.body;

  if (!face_descriptor) {
    console.warn('[LOGIN] Missing face_descriptor');
    return res.status(400).json({ message: "Face descriptor is required." });
  }
  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    if (!user) {
      console.warn('[LOGIN] User not found for email:', email);
      return res.status(400).json({ message: "User not found." });
    }
    if (!user.is_verified) {
      console.warn('[LOGIN] Attempt to login before verification for:', email);
      return res.status(403).json({ message: "Please verify your email before logging in." });
    }
    if (!user.face_descriptor) {
      console.warn('[LOGIN] No face_descriptor stored for user:', email);
      return res.status(400).json({ message: "No face descriptor found for user." });
    }

    const storedDescriptor = user.face_descriptor;
    const distance = faceapi.euclideanDistance(storedDescriptor, face_descriptor);
    console.log('[LOGIN] Face recognition distance:', distance);

    if (distance < 0.6) {
      req.logIn(user, (err) => {
        if (err) {
          console.error('[LOGIN] Error during login:', err.stack || err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        console.log('[LOGIN] Success for user:', email);
        return res.json({
          message: "Login successful",
          user: { id: user.id, email: user.email }
        });
      });
    } else {
      console.warn('[LOGIN] Face recognition failed for:', email);
      return res.status(400).json({ message: "Face recognition failed." });
    }
  } catch (err) {
    console.error('[LOGIN] Error during login:', err.stack || err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// USER REGISTER
app.post("/users/register", async (req, res) => {
  console.log('[REGISTER] Request body:', req.body);
  const { email, password, phone_number, face_descriptor } = req.body;
  try {
    // 1. Check existing
    const exists = await pool.query("SELECT 1 FROM users WHERE email=$1", [email]);
    if (exists.rows.length) {
      console.warn('[REGISTER] Email already in use:', email);
      return res.status(400).json({ message: "Email already in use." });
    }

    // 2. Hash password
    const hashed = await bcrypt.hash(password, 10);
    console.log('[REGISTER] Password hashed for:', email);

    // 3. Generate verification token
    const token = crypto.randomBytes(32).toString("hex");
    console.log('[REGISTER] Verification token generated');

    // 4. Prepare face_descriptor
    const fd = face_descriptor ? JSON.stringify(face_descriptor) : null;
    console.log('[REGISTER] face_descriptor prepared:', fd ? 'present' : 'null');

    // 5. Insert user
    console.log('[REGISTER] Inserting user into DB:', email, phone_number, fd);
    await pool.query(
      `INSERT INTO users 
         (email, password, phone_number, face_descriptor, verify_token)
       VALUES ($1,$2,$3,$4,$5)`,
      [email, hashed, phone_number, fd, token]
    );
    console.log('[REGISTER] User inserted into DB:', email);

    // 6. Send verification email
    const verifyLink = `${process.env.BACKEND_URL}/verify-email?token=${token}`;
    try {
      await transporter.sendMail({
        from: `"Your App" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Please verify your email",
        html: `
          <p>Thanks for registering! Click below to verify your email address:</p>
          <a href="${verifyLink}">Verify Email</a>
          <p>If you didn’t sign up, you can ignore this.</p>
        `
      });
      console.log('[REGISTER] Verification email sent to:', email);
    } catch (emailErr) {
      console.error('[REGISTER] Error sending verification email:', emailErr.stack || emailErr);
      return res.status(500).json({ message: "Failed to send verification email." });
    }

    res.status(201).json({ message: "Registration successful. Check your email to verify." });
  } catch (err) {
    console.error('[REGISTER] Registration error:', err.stack || err);
    res.status(500).json({ message: "Failed to register user." });
  }
});
// ── Add this immediately after your other /users routes, but before your
//     “catch‑all” error handler and before app.listen(...)
app.get('/users/verify-session', (req, res) => {
  console.log('[VERIFY-SESSION] user:', req.user?.email);
  if (req.isAuthenticated && req.isAuthenticated()) {
    return res.sendStatus(200);
  } else {
    return res.sendStatus(401);
  }
});
// EMAIL VERIFICATION
app.get("/verify-email", async (req, res, next) => {
  try {
    const rawToken = req.query.token;
    if (!rawToken) {
      console.warn("[VERIFY-EMAIL] No token in query");
      return res.status(400).send("Missing token.");
    }

    // Trim any stray whitespace or URL‑encoding artifacts
    const token = String(rawToken).trim();
    console.log("[VERIFY-EMAIL] Incoming token:", token);

    // 1) Lookup user by token and log what we found
    const { rowCount, rows } = await pool.query(
      "SELECT id, verify_token FROM users WHERE verify_token = $1",
      [token]
    );
    if (rowCount === 0) {
      console.warn("[VERIFY-EMAIL] No matching token in DB for:", token);
      return res.status(400).send("Invalid or expired link.");
    }
    const { id: userId, verify_token: dbToken } = rows[0];
    console.log("[VERIFY-EMAIL] DB token matches:", dbToken);

    // 2) Mark verified and null out the token
    await pool.query(
      `UPDATE users
         SET is_verified = TRUE, verify_token = NULL
       WHERE id = $1`,
      [userId]
    );
    console.log("[VERIFY-EMAIL] User marked verified in DB, userId =", userId);

    // 3) Pull back the full user record
    const userRes = await pool.query(
      "SELECT id, email, face_descriptor, phone_number FROM users WHERE id = $1",
      [userId]
    );
    const user = userRes.rows[0];
    console.log("[VERIFY-EMAIL] Re-fetched user record:", user.email);

    // 4) Log them in and redirect
// inside your POST /users/login, replace req.logIn callback with:
req.logIn(user, err => {
  if (err) return res.status(500).json({ message: "Internal Server Error" });

  // explicitly save the session before sending response
  req.session.save(saveErr => {
    if (saveErr) {
      console.error("[LOGIN] Session save error:", saveErr);
      return res.status(500).json({ message: "Session save failed." });
    }
    console.log("[LOGIN] Session saved, sending response");
    res.json({
      message: "Login successful",
      user: { id: user.id, email: user.email }
    });
  });
});

  } catch (err) {
    console.error("[VERIFY-EMAIL] caught exception:", err);
    next(err);
  }
});


// RESEND VERIFICATION EMAIL
app.post("/users/resend-verification", async (req, res) => {
  console.log('[RESEND] Request body:', req.body);
  const { email } = req.body;
  try {
    const { rows } = await pool.query(
      "SELECT id, is_verified FROM users WHERE email = $1",
      [email]
    );
    if (!rows.length) {
      console.warn('[RESEND] User not found:', email);
      return res.status(404).json({ message: "User not found." });
    }
    if (rows[0].is_verified) {
      console.warn('[RESEND] Already verified:', email);
      return res.status(400).json({ message: "Already verified." });
    }
    const token = crypto.randomBytes(32).toString("hex");
    await pool.query(
      "UPDATE users SET verify_token = $1 WHERE id = $2",
      [token, rows[0].id]
    );
    console.log('[RESEND] New verification token saved for:', email);

    const link = `${process.env.BACKEND_URL}/verify-email?token=${token}`;
    try {
      await transporter.sendMail({
        from: `"Your App" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Please verify your email",
        html: `<p>Click to verify:</p><a href="${link}">Verify Email</a>`
      });
      console.log('[RESEND] Verification email resent to:', email);
    } catch (emailErr) {
      console.error('[RESEND] Error resending email:', emailErr.stack || emailErr);
      return res.status(500).json({ message: "Failed to resend." });
    }
    res.json({ message: "Verification email sent." });
  } catch (err) {
    console.error('[RESEND] Resend error:', err.stack || err);
    res.status(500).json({ message: "Failed to resend." });
  }
});



// ADMIN LOGIN
app.post("/admin/login", (req, res, next) => {
  console.log('[ADMIN] Login attempt:', req.body.email);
  passport.authenticate("admin-local", (err, admin, info) => {
    if (err) {
      console.error('[ADMIN] Auth error:', err.stack || err);
      return next(err);
    }
    if (!admin) {
      console.warn('[ADMIN] Auth failed:', info.message);
      return res.status(400).json({ message: info.message });
    }
    req.logIn(admin, (err) => {
      if (err) {
        console.error('[ADMIN] Login error:', err.stack || err);
        return next(err);
      }
      console.log('[ADMIN] Login successful:', admin.email);
      res.json({ message: "Login successful", admin });
    });
  })(req, res, next);
});

// ADMIN: list & select rooms
app.get("/admin/rooms", async (req, res) => {
  console.log('[ADMIN] GET /admin/rooms');
  try {
    const rooms = await pool.query("SELECT * FROM room");
    res.json(rooms.rows);
  } catch (err) {
    console.error('[ADMIN] Error fetching rooms:', err.stack || err);
    res.status(500).send("Failed to fetch rooms.");
  }
});
app.post("/admin/select-room", async (req, res) => {
  console.log('[ADMIN] POST /admin/select-room:', req.body);
  const { roomId } = req.body;
  try {
    await pool.query("UPDATE room SET selected = FALSE WHERE selected = TRUE");
    await pool.query("UPDATE room SET selected = TRUE WHERE id = $1", [roomId]);
    console.log('[ADMIN] Room selected:', roomId);
    res.send("Room selected successfully");
  } catch (err) {
    console.error('[ADMIN] Error selecting room:', err.stack || err);
    res.status(500).send("Failed to select room. Please try again.");
  }
});

// MARK ATTENDANCE
app.post("/mark-attendance", limiter, async (req, res) => {
  console.log('[ATTEND] Request body:', req.body);
  const { name, rollNumber, lat, lon } = req.body;
  const latitude = parseFloat(lat);
  const longitude = parseFloat(lon);
  try {
    const sel = await pool.query("SELECT * FROM room WHERE selected = TRUE");
    if (!sel.rows.length) {
      console.warn('[ATTEND] No room selected by admin');
      return res.status(400).send("No room selected by the admin.");
    }
    const room = sel.rows[0];
    if (
      latitude >= room.minlat && latitude <= room.maxlat &&
      longitude >= room.minlon && longitude <= room.maxlon
    ) {
      await pool.query(
        "INSERT INTO attendance (name, rollNumber, latitude, longitude) VALUES ($1,$2,$3,$4)",
        [name, rollNumber, latitude, longitude]
      );
      console.log('[ATTEND] Attendance marked for:', name);
      res.send(`Attendance marked successfully for: ${name}`);
    } else {
      console.warn('[ATTEND] User out of bounds:', name, latitude, longitude);
      res.status(400).send("You are not in the selected room.");
    }
  } catch (err) {
    console.error('[ATTEND] Error marking attendance:', err.stack || err);
    res.status(500).send("Failed to mark attendance. Please try again.");
  }
});

// ADMIN DASHBOARD (rooms CRUD)
app.get("/admin/dashboard", async (req, res) => {
  console.log('[ADMIN] GET /admin/dashboard');
  try {
    const rooms = await pool.query("SELECT * FROM room");
    res.json(rooms.rows);
  } catch (err) {
    console.error('[ADMIN] Error fetching dashboard rooms:', err.stack || err);
    res.status(500).send("Failed to fetch rooms.");
  }
});
app.post("/admin/dashboard", async (req, res) => {
  console.log('[ADMIN] POST /admin/dashboard:', req.body);
  const { name, minlat, maxlat, minlon, maxlon } = req.body;
  if (!name || !minlat || !maxlat || !minlon || !maxlon) {
    console.warn('[ADMIN] Missing fields in new room creation');
    return res.status(400).send("All fields are required");
  }
  try {
    const result = await pool.query(
      "INSERT INTO room (name,minlat,maxlat,minlon,maxlon,selected) VALUES ($1,$2,$3,$4,$5,FALSE) RETURNING *",
      [name, parseFloat(minlat), parseFloat(maxlat), parseFloat(minlon), parseFloat(maxlon)]
    );
    console.log('[ADMIN] Room created:', result.rows[0]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('[ADMIN] Error adding room:', err.stack || err);
    res.status(500).send("Failed to add room. Please try again.");
  }
});
// after all routes:
app.use((err, req, res, next) => {
  console.error('[FATAL]', err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
});
// USER LOGOUT
app.post("/users/logout", (req, res, next) => {
  console.log("[LOGOUT] Logging out user:", req.user?.email);

  // Passport 0.6+ uses asynchronous logout
  req.logout(err => {
    if (err) {
      console.error("[LOGOUT] req.logout error:", err.stack || err);
      return next(err);
    }

    // Destroy the session on the store
    req.session.destroy(err => {
      if (err) {
        console.error("[LOGOUT] Session destroy error:", err.stack || err);
        return next(err);
      }

      // Clear the cookie on client
      res.clearCookie("connect.sid", { path: "/" });
      console.log("[LOGOUT] Successfully logged out");
      res.json({ message: "Logout successful" });
    });
  });
});
// GET user profile
app.get('/users/profile', (req, res) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  // Only return the fields you need
  res.json({
    email:       req.user.email,
    phone_number:req.user.phone_number,
    photoUrl:    req.user.photo_url  // make sure you store this in users table
  });
});

// GET attendance history
app.get('/users/attendance-history', async (req, res, next) => {
  if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
  try {
    const { rows } = await pool.query(
      `SELECT id, name, rollnumber, latitude, longitude, created_at
         FROM attendance
        WHERE user_id = $1
     ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// POST profile photo upload
app.post('/users/profile/photo',
  upload.single('photo'),           // e.g. using multer
  async (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
    if (!req.file)  return res.status(400).json({ message: 'No file uploaded' });

    try {
      // e.g. save to disk or cloud storage, then:
      const url = `/uploads/${req.file.filename}`;
      await pool.query('UPDATE users SET photo_url = $1 WHERE id = $2', [url, req.user.id]);
      res.json({ photoUrl: url });
    } catch (err) {
      next(err);
    }
  }
);

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
