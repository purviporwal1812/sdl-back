const LocalStrategy = require("passport-local").Strategy;
const { Pool } = require("pg");

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 10, // Maximum number of connections in the pool (adjust as needed)
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 2000,
});

function initialize(passport) {
  const authenticateAdmin = async (email, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM admin WHERE email = $1", [email]);
      if (rows.length > 0) {
        const admin = rows[0];
        if (password === admin.password) {
          return done(null, admin);
        } else {
          return done(null, false, { message: "Incorrect password" });
        }
      } else {
        return done(null, false, { message: "No admin with that email" });
      }
    } catch (err) {
      console.error("Error during authentication:", err);
      return done(err);
    }
  };

  passport.use("admin-local", new LocalStrategy({ usernameField: "email" }, authenticateAdmin));

  passport.serializeUser((admin, done) => {
    done(null, admin.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM admin WHERE id = $1", [id]);
      if (rows.length > 0) {
        done(null, rows[0]);
      } else {
        done(new Error("Admin not found"));
      }
    } catch (err) {
      console.error("Error during deserialization:", err);
      done(err);
    }
  });
}

module.exports = initialize;
