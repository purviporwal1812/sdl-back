const express = require("express");
const { Pool } = require("pg");
const passport = require("passport");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");

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

app.post("/users/login", async (req, res, next) => {
  const { email, password, face_descriptor } = req.body;

  // Log incoming request data
  console.log("Login attempt:", { email, face_descriptor });

  try {
    // Check if the user exists
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    if (!user) {
      console.log("User not found:", email);
      return res.status(400).json({ message: "User not found." });
    }

    // Validate password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      console.log("Password does not match for user:", email);
      return res.status(400).json({ message: "Invalid credentials." });
    }

    // If face_descriptor is provided, compare it with the stored descriptor
    if (face_descriptor) {
      const storedDescriptor = JSON.parse(user.face_descriptor); // Parse the stored descriptor
      const distance = faceapi.euclideanDistance(storedDescriptor, face_descriptor);

      // Log distance for debugging
      console.log("Face recognition distance:", distance);

      // If the distance is below a certain threshold, the faces match
      if (distance < 0.6) {
        req.logIn(user, (err) => {
          if (err) {
            console.error("Error during login:", err);
            return res.status(500).json({ message: "Internal Server Error" });
          }
          return res.json({ message: "Login successful", user });
        });
      } else {
        console.log("Face recognition failed for user:", email);
        return res.status(400).json({ message: "Face recognition failed." });
      }
    } else {
      // If no face_descriptor, just log in the user
      req.logIn(user, (err) => {
        if (err) {
          console.error("Error during login:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        return res.json({ message: "Login successful", user });
      });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});



app.get("/users/login", (req, res) => {
  res.send("login running");
});
app.post("/users/login", async (req, res, next) => {
  const { email, password, face_descriptor } = req.body;

  try {
    // Check if the user exists
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    if (!user) {
      return res.status(400).json({ message: "User not found." });
    }

    // Initialize variables to determine if authentication succeeded
    let isFaceRecognitionSuccessful = false;
    let isPasswordAuthenticationSuccessful = false;

    // If face_descriptor is provided, compare it with the stored descriptor
    if (face_descriptor) {
      const storedDescriptor = JSON.parse(user.face_descriptor); // Parse the stored descriptor
      const distance = faceapi.euclideanDistance(storedDescriptor, face_descriptor);

      // If the distance is below a certain threshold, the faces match
      if (distance < 0.6) {
        isFaceRecognitionSuccessful = true;
      }
    }

    // If face recognition was successful or if face_descriptor is not provided, check password authentication
    if (isFaceRecognitionSuccessful) {
      passport.authenticate("local", (err, authenticatedUser, info) => {
        if (err) {
          console.error("Error during authentication:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        if (!authenticatedUser) {
          console.log("Authentication failed:", info.message);
          return res.status(400).json({ message: info.message });
        }

        req.logIn(authenticatedUser, (err) => {
          if (err) {
            console.error("Error during login:", err);
            return res.status(500).json({ message: "Internal Server Error" });
          }
          return res.json({ message: "Login successful", user: authenticatedUser });
        });
      })(req, res, next);
    } else {
      return res.status(400).json({ message: "Face recognition failed." });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
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
