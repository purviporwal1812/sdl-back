const express = require("express");
const { Pool } = require("pg");
const passport = require("passport");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const webauthn = require('@webauthn/server');
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
});

const initializePassport = require("./passportConfig");
initializePassport(passport);

const initializePassportAdmin = require("./passportConfigAdmin");
initializePassportAdmin(passport);

app.use(cors({
  origin: "https://attendance-tracker-one.vercel.app",
  credentials: true,
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    store: new PgSession({
      pool: pool,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, 
      maxAge: 1000 * 60 * 60 
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, 
  max: 1,
  message: "You have already marked your attendance for this hour.",
});

app.get("/", (req, res) => {
  res.send("Backend running");
});

// Initialize WebAuthn
const webAuthn = new webauthn.WebAuthn({
  origin: 'https://attendance-tracker-one.vercel.app', // Your application's origin
  rp: {
    name: 'Attendance Tracker',
    id: 'attendance-tracker-one.vercel.app',
  },
});

// Endpoint to request a registration challenge
app.post('/webauthn/register/request', async (req, res) => {
  const { email } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  
  if (user.rows.length > 0) {
    return res.status(400).send('User already exists');
  }

  const challenge = webAuthn.createChallenge(email);
  // Store the challenge in your session or database (simplified here)
  req.session.challenge = challenge;

  res.json(challenge);
});

// Endpoint to handle registration response
app.post('/webauthn/register/response', async (req, res) => {
  const { credential } = req.body;

  // Verify the registration credential and store it
  const user = await pool.query("SELECT * FROM users WHERE email = $1", [credential.id]);
  
  if (user.rows.length === 0) {
    return res.status(400).send('User not found');
  }

  // Store the user's public key credential
  await pool.query(
    "UPDATE users SET credentials = $1 WHERE email = $2",
    [JSON.stringify(credential), credential.id]
  );

  res.json({ message: 'Registration successful' });
});

// Endpoint to request a login challenge
app.post('/webauthn/login/request', async (req, res) => {
  const { email } = req.body;
  const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  
  if (user.rows.length === 0) {
    return res.status(400).send('User not found');
  }

  const challenge = webAuthn.createChallenge(email);
  req.session.challenge = challenge; // Store challenge

  res.json({ challenge, credential: user.rows[0].credentials }); // Send stored credentials for verification
});

// Endpoint to handle login response
app.post('/webauthn/login/response', async (req, res) => {
  const { credential } = req.body;

  // Verify the credential
  const isValid = webAuthn.verifyChallenge(credential);
  
  if (!isValid) {
    return res.status(401).send('Authentication failed');
  }

  // Log the user in (handle session management here)
  req.session.user = credential.id; // Simplified login session

  res.json({ message: 'Login successful', user: credential });
});


app.post("/users/register", async (req, res) => {
  console.log(req.body);
  const { email, password , phone_number } = req.body;

  try {
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "User with this email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (email, password,phone_number) VALUES ($1, $2,$3)",
      [email, hashedPassword,phone_number]
    );

    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Failed to register user. Please try again." });
  }
});
app.get("/users/login", (req, res) => {
  res.send("login running");
});
app.post("/users/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error("Error during authentication:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
    if (!user) {
      console.log("Authentication failed:", info.message); 
      return res.status(400).json({ message: info.message });
    }

    req.logIn(user, (err) => {
      if (err) {
        console.error("Error during login:", err);
        return res.status(500).json({ message: "Internal Server Error" });
      }
      return res.json({ message: "Login successful", user });
    });
  })(req, res, next);
});

app.post("/admin/login", (req, res, next) => {
  passport.authenticate("admin-local", (err, admin, info) => {
    if (err) return next(err);
    if (!admin) return res.status(400).json({ message: info.message });

    req.logIn(admin, (err) => {
      if (err) return next(err);
      return res.json({ message: "Login successful", admin });
    });
  })(req, res, next);
});

app.get("/admin/rooms", async (req, res) => {
  try {
    const roomsResult = await pool.query("SELECT * FROM room");
    res.json(roomsResult.rows);
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

app.post("/mark-attendance", limiter, async (req, res) => {
  const { name, rollNumber, lat, lon } = req.body;
  const latitude = parseFloat(lat);
  const longitude = parseFloat(lon);

  try {
    const selectedRoomResult = await pool.query("SELECT * FROM room WHERE selected = TRUE");
    if (selectedRoomResult.rows.length === 0) {
      return res.status(400).send("No room has been selected by the admin.");
    }

    const selectedRoom = selectedRoomResult.rows[0];
    if (
      latitude >= selectedRoom.minlat &&
      latitude <= selectedRoom.maxlat &&
      longitude >= selectedRoom.minlon &&
      longitude <= selectedRoom.maxlon
    ) {
      await pool.query(
        `INSERT INTO attendance (name, rollNumber, latitude, longitude) VALUES ($1, $2, $3, $4)`,
        [name, rollNumber, latitude, longitude]
      );
      res.send(`Attendance marked successfully for : ${name}`);
    } else {
      res.status(400).send("Failed to mark attendance. You are not in the selected room.");
    }
  } catch (err) {
    console.error("Error marking attendance", err.stack);
    res.status(500).send("Failed to mark attendance. Please try again.");
  }
});

app.get("/admin/dashboard" , async (req, res) => {
    try {
      const roomsResult = await pool.query("SELECT * FROM room");
      res.json(roomsResult.rows);
    } catch (err) {
      console.error("Error fetching rooms", err.stack);
      res.status(500).send("Failed to fetch rooms.");
    }
  })

app.post("/admin/dashboard" , async (req, res) => {
    const { name, minlat, maxlat, minlon, maxlon } = req.body;

    if (!name || !minlat || !maxlat || !minlon || !maxlon) {
      return res.status(400).send("All fields are required");
    }

    try {
      const newRoom = await pool.query(
        "INSERT INTO room (name, minlat, maxlat, minlon, maxlon, selected) VALUES ($1, $2, $3, $4, $5, FALSE) RETURNING *",
        [name, parseFloat(minlat), parseFloat(maxlat), parseFloat(minlon), parseFloat(maxlon)]
      );
      res.json(newRoom.rows[0]); 
    } catch (err) {
      console.error("Error adding room", err.stack);
      res.status(500).send("Failed to add room. Please try again.");
    }
  });

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
