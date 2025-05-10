// passportConfig.js
require("dotenv").config();
const LocalStrategy = require("passport-local").Strategy;
const { Pool }       = require("pg");
const bcrypt         = require("bcrypt");

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
});

pool.on("connect", () => console.log("[Passport][DB] Connected to Postgres"));
pool.on("error", err => console.error("[Passport][DB] Unexpected error:", err));

function initialize(passport) {
  // --- 1. Authentication ---
  const authenticateUser = async (email, password, done) => {
    try {
      console.log("[Passport][Auth] Attempting login for:", email);
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE email = $1",
        [email]
      );

      if (rows.length === 0) {
        console.warn("[Passport][Auth] No user found with email:", email);
        return done(null, false, { message: "No user with that email" });
      }

      const user = rows[0];
      const isValidPassword = await bcrypt.compare(password, user.password);

      if (isValidPassword) {
        console.log("[Passport][Auth] Password valid for:", email);
        return done(null, user);
      } else {
        console.warn("[Passport][Auth] Incorrect password for:", email);
        return done(null, false, { message: "Incorrect password" });
      }
    } catch (err) {
      console.error("[Passport][Auth] Error during authentication:", err.stack || err);
      return done(err);
    }
  };

  passport.use(new LocalStrategy({ usernameField: "email" }, authenticateUser));

  // --- 2. Serialize user into the session ---
  passport.serializeUser((user, done) => {
    console.log("[Passport][Serialize] User ID:", user.id);
    done(null, user.id);
  });

  // --- 3. Deserialize user from the session ---
  passport.deserializeUser(async (id, done) => {
    try {
      console.log("[Passport][Deserialize] Fetching user ID:", id);
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE id = $1",
        [id]
      );

      if (rows.length > 0) {
        console.log("[Passport][Deserialize] User found:", rows[0].email);
        done(null, rows[0]);
      } else {
        console.warn("[Passport][Deserialize] No user found for ID:", id);
        // Graceful fallback: not an error, just no session user
        done(null, false);
      }
    } catch (err) {
      console.error("[Passport][Deserialize] Error during deserialization:", err.stack || err);
      done(err);
    }
  });
}

module.exports = initialize;
