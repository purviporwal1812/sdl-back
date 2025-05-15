// passportConfig.js
require("dotenv").config();
const LocalStrategy = require("passport-local").Strategy;
const bcrypt        = require("bcrypt");
const User          = require("./models/User");

function initialize(passport) {
  // 1. Authentication
  const authenticateUser = async (email, password, done) => {
    try {
      console.log("[Passport][Auth] Attempting login for:", email);
      const user = await User.findOne({ email: email.toLowerCase().trim() });

      if (!user) {
        console.warn("[Passport][Auth] No user found with email:", email);
        return done(null, false, { message: "No user with that email" });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        console.warn("[Passport][Auth] Incorrect password for:", email);
        return done(null, false, { message: "Incorrect password" });
      }

      console.log("[Passport][Auth] Password valid for:", email);
      return done(null, user);

    } catch (err) {
      console.error("[Passport][Auth] Error during authentication:", err);
      return done(err);
    }
  };

  passport.use(new LocalStrategy({ usernameField: "email" }, authenticateUser));

  // 2. Serialize user into session
  passport.serializeUser((user, done) => {
    console.log("[Passport][Serialize] User ID:", user._id);
    done(null, user._id);
  });

  // 3. Deserialize user from session
  passport.deserializeUser(async (id, done) => {
    try {
      console.log("[Passport][Deserialize] Fetching user ID:", id);
      const user = await User.findById(id).lean();

      if (user) {
        console.log("[Passport][Deserialize] User found:", user.email);
        done(null, user);
      } else {
        console.warn("[Passport][Deserialize] No user found for ID:", id);
        done(null, false);
      }
    } catch (err) {
      console.error("[Passport][Deserialize] Error during deserialization:", err);
      done(err);
    }
  });
}

module.exports = initialize;
