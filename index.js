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
const corsOptions = {
  origin: process.env.NODE_ENV === "production"
    ? [process.env.CLIENT_URL, process.env.FRONTEND_URL]
    : "*",
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
  store: new PgSession({ pool }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  cookie: {
    secure: process.env.NODE_ENV === "production",
     sameSite: process.env.NODE_ENV === "production"   // 'none' is implied when credentials:true
      ? "none"
      : "lax",
    maxAge: 1000 * 60 * 60, // 1 hour
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

app.post("/users/login", async (req, res) => {
  console.log("[LOGIN] ➥ Entered login handler");
  console.log("[LOGIN] ➥ Payload:", req.body);

  const { email, password, face_descriptor } = req.body;
  if (!face_descriptor) {
    console.warn("[LOGIN] ✖ Missing face_descriptor");
    return res.status(400).json({ message: "Face descriptor is required." });
  }

  try {
    console.log("[LOGIN] ➥ Fetching user by email:", email);
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!rows.length) {
      console.warn("[LOGIN] ✖ No user found for:", email);
      return res.status(400).json({ message: "User not found." });
    }

    const user = rows[0];
    console.log("[LOGIN] ✔ User fetched:", { id: user.id, is_verified: user.is_verified });

    if (!user.is_verified) {
      console.warn("[LOGIN] ✖ Email not verified for:", email);
      return res.status(403).json({ message: "Please verify your email first." });
    }

    if (!user.face_descriptor) {
      console.warn("[LOGIN] ✖ No stored face_descriptor for user:", user.id);
      return res.status(400).json({ message: "No face descriptor found." });
    }

    console.log("[LOGIN] ➥ Comparing face descriptors");
    const storedDescriptor = user.face_descriptor;
    if (!storedDescriptor) {
      return res.status(400).json({ message: "No face descriptor found for user." });
    }    const distance = faceapi.euclideanDistance(storedDescriptor, face_descriptor);
    console.log("[LOGIN] ✔ Face-distance:", distance);

    if (distance < 0.6) {
      console.log("[LOGIN] ➥ Face match succeeded, logging in user", user.id);
      req.logIn(user, (err) => {
        if (err) {
          console.error("[LOGIN] ✖ req.logIn error:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error("[LOGIN] ✖ Session save error:", saveErr);
            return res.status(500).json({ message: "Session save failed." });
          }
          console.log("[LOGIN] ✔ Login successful for user", user.id);
          res.json({ message: "Login successful", user: { id: user.id, email: user.email } });
        });
      });
    } else {
      console.warn("[LOGIN] ✖ Face match failed for user", user.id);
      res.status(400).json({ message: "Face recognition failed." });
    }
  } catch (err) {
    console.error("[LOGIN] ✖ Unexpected error:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});


// USER REGISTER (with verification code)
app.post("/users/register", async (req, res) => {
  console.log("[REGISTER] ➥ Entered register handler");
  console.log("[REGISTER] ➥ Payload:", req.body);

  const { email, password, phone_number, face_descriptor } = req.body;
  try {
    // 1. Check existing
    console.log("[REGISTER] ➥ Checking if", email, "already exists");
    const exists = await pool.query("SELECT 1 FROM users WHERE email=$1", [email]);
    console.log("[REGISTER] ➥ Existing rows:", exists.rows.length);

    if (exists.rows.length) {
      console.warn("[REGISTER] ✖ Email already in use:", email);
      return res.status(400).json({ message: "Email already in use." });
    }

    // 2. Hash password
    console.log("[REGISTER] ➥ Hashing password for:", email);
    const hashed = await bcrypt.hash(password, 10);
    console.log("[REGISTER] ✔ Password hashed");

    // 3. Generate code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    console.log("[REGISTER] ➥ Generated code:", code);

    // 4. Prepare face_descriptor
    const fd = face_descriptor ? JSON.stringify(face_descriptor) : null;
    console.log("[REGISTER] ➥ face_descriptor present?", Boolean(fd));

    // 5. Insert into DB
    console.log("[REGISTER] ➥ Inserting new user record");
    await pool.query(
      `INSERT INTO users 
         (email, password, phone_number, face_descriptor, verify_code, code_expires_at)
       VALUES ($1,$2,$3,$4,$5, NOW() + interval '1 hour')`,
      [email, hashed, phone_number, fd, code]
    );
    console.log("[REGISTER] ✔ User inserted with verification code");

    // 6. Send email
    console.log("[REGISTER] ➥ Sending email via transporter");
    await transporter.sendMail({
      from: `"Your App" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your verification code",
      html: `<p>Your code is <h2>${code}</h2></p>`
    });
    console.log("[REGISTER] ✔ Verification email sent to", email);

    res.status(201).json({ message: "Registration successful. Check your email." });
  } catch (err) {
    console.error("[REGISTER] ✖ Error:", err);
    res.status(500).json({ message: "Failed to register user." });
  }
});

// RESEND VERIFICATION CODE
app.post("/users/resend-verification", async (req, res) => {
  console.log("[RESEND] ➥ Entered resend-verification handler");
  console.log("[RESEND] ➥ Payload:", req.body);

  const { email } = req.body;
  try {
    console.log("[RESEND] ➥ Checking user:", email);
    const { rows } = await pool.query(
      "SELECT id, is_verified FROM users WHERE email = $1",
      [email]
    );
    console.log("[RESEND] ➥ Rows found:", rows.length);

    if (!rows.length) {
      console.warn("[RESEND] ✖ User not found:", email);
      return res.status(404).json({ message: "User not found." });
    }
    if (rows[0].is_verified) {
      console.warn("[RESEND] ✖ Already verified:", email);
      return res.status(400).json({ message: "Already verified." });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    console.log("[RESEND] ➥ Generated new code:", code);

    await pool.query(
      `UPDATE users 
         SET verify_code = $1, code_expires_at = NOW() + interval '1 hour'
       WHERE id = $2`,
      [code, rows[0].id]
    );
    console.log("[RESEND] ✔ Saved new code for user ID:", rows[0].id);

    await transporter.sendMail({
      from: `"Your App" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your new verification code",
      html: `<p>Your new verification code is:</p><h2>${code}</h2><p>Expires in 1 hour.</p>`
    });
    console.log("[RESEND] ✔ Email sent to:", email);

    res.json({ message: "Verification code sent." });
  } catch (err) {
    console.error("[RESEND] ✖ Error:", err);
    res.status(500).json({ message: "Failed to resend." });
  }
});


// NEW: VERIFY CODE ENDPOINT
app.post("/users/verify-code", async (req, res) => {
  console.log("[VERIFY-CODE] ➥ Entered verify-code handler");
  console.log("[VERIFY-CODE] ➥ Payload:", req.body);

  const { email, code } = req.body;
  try {
    console.log("[VERIFY-CODE] ➥ Looking up user with code:", code);
    const { rows } = await pool.query(
      `SELECT id, code_expires_at 
         FROM users 
        WHERE email = $1 
          AND verify_code = $2`,
      [email, code]
    );
    console.log("[VERIFY-CODE] ➥ Rows found:", rows.length);

    if (!rows.length) {
      console.warn("[VERIFY-CODE] ✖ No matching code for:", email);
      return res.status(400).json({ message: "Invalid verification code." });
    }

    const user = rows[0];
    console.log("[VERIFY-CODE] ✔ Found user ID:", user.id, "expires at:", user.code_expires_at);

    if (new Date(user.code_expires_at) < new Date()) {
      console.warn("[VERIFY-CODE] ✖ Code expired for user ID:", user.id);
      return res.status(400).json({ message: "Verification code expired." });
    }

    console.log("[VERIFY-CODE] ➥ Marking user verified and clearing code");
    await pool.query(
      `UPDATE users 
          SET is_verified = TRUE, 
              verify_code = NULL, 
              code_expires_at = NULL 
        WHERE id = $1`,
      [user.id]
    );
    console.log("[VERIFY-CODE] ✔ Updated user ID", user.id, "to verified");

    console.log("[VERIFY-CODE] ➥ Fetching user data for session login");
    const { rows: userRows } = await pool.query(
      `SELECT id, email, phone_number, face_descriptor 
         FROM users 
        WHERE id = $1`,
      [user.id]
    );
    const verifiedUser = userRows[0];
    console.log("[VERIFY-CODE] ✔ Retrieved user for session:", verifiedUser);

    console.log("[VERIFY-CODE] ➥ Calling req.logIn()");
    req.logIn(verifiedUser, (err) => {
      if (err) {
        console.error("[VERIFY-CODE] ✖ req.logIn error:", err);
        return res.status(500).json({ message: "Login after verification failed." });
      }
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("[VERIFY-CODE] ✖ Session save error:", saveErr);
          return res.status(500).json({ message: "Session save failed." });
        }
        console.log("[VERIFY-CODE] ✔ Verification complete, user logged in:", verifiedUser.id);
        res.json({
          message: "Email verified and logged in.",
          user: { id: verifiedUser.id, email: verifiedUser.email }
        });
      });
    });

  } catch (err) {
    console.error("[VERIFY-CODE] ✖ Unexpected error:", err);
    res.status(500).json({ message: "Verification failed." });
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
