// passportConfigAdmin.js
require("dotenv").config();
const LocalStrategy = require("passport-local").Strategy;
const bcrypt        = require("bcrypt");
const Admin         = require("./models/Admin");

function initialize(passport) {
  // 1. Authentication
  const authenticateAdmin = async (email, password, done) => {
    try {
      console.log("[Passport][AdminAuth] Attempting login for:", email);
      const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
      if (!admin) {
        console.warn("[Passport][AdminAuth] No admin found with email:", email);
        return done(null, false, { message: "No admin with that email" });
      }

      // If you store hashed passwords:
      const isValid = await bcrypt.compare(password, admin.password);
      if (!isValid) {
        console.warn("[Passport][AdminAuth] Incorrect password for:", email);
        return done(null, false, { message: "Incorrect password" });
      }

      console.log("[Passport][AdminAuth] Authentication successful for:", email);
      return done(null, admin);

    } catch (err) {
      console.error("[Passport][AdminAuth] Error during authentication:", err);
      return done(err);
    }
  };

  passport.use("admin-local",
    new LocalStrategy({ usernameField: "email" }, authenticateAdmin)
  );

  // 2. Serialize admin into the session
  passport.serializeUser((admin, done) => {
    console.log("[Passport][AdminSerialize] Admin ID:", admin._id);
    done(null, admin._id);
  });

  // 3. Deserialize admin from the session
  passport.deserializeUser(async (id, done) => {
    try {
      console.log("[Passport][AdminDeserialize] Fetching admin ID:", id);
      const admin = await Admin.findById(id).lean();
      if (!admin) {
        console.warn("[Passport][AdminDeserialize] Admin not found for ID:", id);
        return done(null, false);
      }
      console.log("[Passport][AdminDeserialize] Admin loaded:", admin.email);
      done(null, admin);
    } catch (err) {
      console.error("[Passport][AdminDeserialize] Error during deserialization:", err);
      done(err);
    }
  });
}

module.exports = initialize;
