// index.js
const express = require("express");
const { Pool } = require("pg");
const passport = require("passport");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const faceapi = require("face-api.js"); // Adjust import if needed
const path = require("path");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
});
// Passport setup
const initializePassport = require("./passportConfig");
initializePassport(passport);
const initializePassportAdmin = require("./passportConfigAdmin");
initializePassportAdmin(passport);

// CORS + body parsing + sessions
app.use(cors({
  origin: "https://attendance-tracker-one.vercel.app",
  credentials: true,
}));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set('trust proxy', 1);

app.use(session({
  store: new PgSession({ pool }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    maxAge: 1000 * 60 * 60, // 1 hour
  }
}));


app.use(passport.initialize());
app.use(passport.session());

// Rate limiter for attendance
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1,
  message: "You have already marked your attendance for this hour.",
});
console.log(
  '→ Google OAuth:',
  'ID=', process.env.GOOGLE_CLIENT_ID,
  'SECRET=', process.env.GOOGLE_CLIENT_SECRET ? '••••' : undefined,
  'CALLBACK=', process.env.OAUTH_CALLBACK_URL
);
// ——— Utility: Euclidean distance ———
function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}
// ——— Face‑verify endpoint ———
app.post('/users/face-verify', async (req, res) => {
  if (!req.user) return res.status(401).send('Not authenticated');
  const { face_descriptor } = req.body;
  if (!Array.isArray(face_descriptor)) return res.status(400).send('No face data');

  try {
    const { rows } = await pool.query(
      'SELECT face_descriptor FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!rows.length || !rows[0].face_descriptor) {
      return res.status(400).send('No face on record');
    }

    const stored = rows[0].face_descriptor;
    const distance = euclideanDistance(stored, face_descriptor);
    console.log('Face distance:', distance);

    return distance < 0.6
      ? res.sendStatus(200)
      : res.status(403).send('Face mismatch');
  } catch (err) {
    console.error('[Face-verification]', err);
    return res.sendStatus(500);
  }
});

const initializeOAuth = require('./passportOauthConfig');
initializeOAuth(passport);

// ——— Google OAuth routes ———
// 1) kick-off
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
// 2) callback
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login?error=oauth' }),
  (req, res) => {
    // now authenticated by Google, next step: face‑verify
    res.redirect('https://attendance-tracker-one.vercel.app/face-verify');
  }
);




// --- API ROUTES ---

// Health check
app.get("/", (req, res) => {
  res.send("Backend running");
});

// USER LOGIN (face + password)
app.post("/users/login", async (req, res, next) => {
  const { email, password, face_descriptor } = req.body;
  if (!face_descriptor) {
    return res.status(400).json({ message: "Face descriptor is required." });
  }
  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    if (!user) return res.status(400).json({ message: "User not found." });

    const storedDescriptor = user.face_descriptor;
    if (!storedDescriptor) {
      return res.status(400).json({ message: "No face descriptor found for user." });
    }

    const distance = faceapi.euclideanDistance(storedDescriptor, face_descriptor);
    console.log("Face recognition distance:", distance);

    if (distance < 0.6) {
      req.logIn(user, (err) => {
        if (err) {
          console.error("Error during login:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        // include theme in payload
        return res.json({
          message: "Login successful",
          user: {
            id: user.id,
            email: user.email,
            theme: user.theme
          }
        });
      });
    } else {
      return res.status(400).json({ message: "Face recognition failed." });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// USER REGISTER
app.post("/users/register", async (req, res) => {
  const { email, password, phone_number, face_descriptor } = req.body;
  try {
    const existing = await pool.query("SELECT 1 FROM users WHERE email = $1", [email]);
    if (existing.rows.length) {
      return res.status(400).json({ message: "User with this email already exists." });
    }
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (email, password, phone_number, face_descriptor) VALUES ($1, $2, $3, $4)",
      [email, hashed, phone_number, JSON.stringify(face_descriptor)]
    );
    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Failed to register user. Please try again." });
  }
});

// THEME ENDPOINTS
app.get("/users/theme", (req, res) => {
  if (!req.user) return res.status(401).json({ message: "Not authenticated" });
  res.json({ theme: req.user.theme });
});

app.post("/users/theme", async (req, res) => {
  if (!req.user) return res.status(401).json({ message: "Not authenticated" });
  const { theme } = req.body;
  if (!["light", "dark"].includes(theme)) {
    return res.status(400).json({ message: "Invalid theme" });
  }
  try {
    await pool.query("UPDATE users SET theme = $1 WHERE id = $2", [theme, req.user.id]);
    req.user.theme = theme;
    res.json({ theme });
  } catch (err) {
    console.error("Error updating theme", err);
    res.status(500).json({ message: "Could not save theme" });
  }
});

// ADMIN LOGIN
app.post("/admin/login", (req, res, next) => {
  passport.authenticate("admin-local", (err, admin, info) => {
    if (err) return next(err);
    if (!admin) return res.status(400).json({ message: info.message });
    req.logIn(admin, (err) => {
      if (err) return next(err);
      res.json({ message: "Login successful", admin });
    });
  })(req, res, next);
});

// ADMIN: list & select rooms
app.get("/admin/rooms", async (req, res) => {
  try {
    const rooms = await pool.query("SELECT * FROM room");
    res.json(rooms.rows);
  } catch (err) {
    console.error("Error fetching rooms", err);
    res.status(500).send("Failed to fetch rooms.");
  }
});
app.post("/admin/select-room", async (req, res) => {
  const { roomId } = req.body;
  try {
    await pool.query("UPDATE room SET selected = FALSE WHERE selected = TRUE");
    await pool.query("UPDATE room SET selected = TRUE WHERE id = $1", [roomId]);
    res.send("Room selected successfully");
  } catch (err) {
    console.error("Error selecting room", err);
    res.status(500).send("Failed to select room. Please try again.");
  }
});

// MARK ATTENDANCE
app.post("/mark-attendance", limiter, async (req, res) => {
  const { name, rollNumber, lat, lon } = req.body;
  const latitude = parseFloat(lat);
  const longitude = parseFloat(lon);
  try {
    const sel = await pool.query("SELECT * FROM room WHERE selected = TRUE");
    if (sel.rows.length === 0) {
      return res.status(400).send("No room selected by the admin.");
    }
    const room = sel.rows[0];
    if (
      latitude >= room.minlat &&
      latitude <= room.maxlat &&
      longitude >= room.minlon &&
      longitude <= room.maxlon
    ) {
      await pool.query(
        "INSERT INTO attendance (name, rollNumber, latitude, longitude) VALUES ($1,$2,$3,$4)",
        [name, rollNumber, latitude, longitude]
      );
      res.send(`Attendance marked successfully for: ${name}`);
    } else {
      res.status(400).send("You are not in the selected room.");
    }
  } catch (err) {
    console.error("Error marking attendance", err);
    res.status(500).send("Failed to mark attendance. Please try again.");
  }
});

// ADMIN DASHBOARD (rooms CRUD)
app.get("/admin/dashboard", async (req, res) => {
  try {
    const rooms = await pool.query("SELECT * FROM room");
    res.json(rooms.rows);
  } catch (err) {
    console.error("Error fetching rooms", err);
    res.status(500).send("Failed to fetch rooms.");
  }
});
app.post("/admin/dashboard", async (req, res) => {
  const { name, minlat, maxlat, minlon, maxlon } = req.body;
  if (!name || !minlat || !maxlat || !minlon || !maxlon) {
    return res.status(400).send("All fields are required");
  }
  try {
    const result = await pool.query(
      "INSERT INTO room (name,minlat,maxlat,minlon,maxlon,selected) VALUES ($1,$2,$3,$4,$5,FALSE) RETURNING *",
      [name, parseFloat(minlat), parseFloat(maxlat), parseFloat(minlon), parseFloat(maxlon)]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error adding room", err);
    res.status(500).send("Failed to add room. Please try again.");
  }
});

// --- STATIC FILE SERVE + CATCH-ALL (must come last) ---
const clientDist = path.join(__dirname, "../sdl-front/dist");

// serve all of the real static assets
app.use(express.static(clientDist));

// for any other GET request (i.e. your client‑side routes), send back index.html
app.get("/*", (req, res) => {
  res.sendFile(path.join(clientDist, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});