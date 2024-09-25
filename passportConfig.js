
const LocalStrategy = require("passport-local").Strategy;
const { Pool } = require("pg");
const bcrypt = require("bcrypt"); 

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

function initialize(passport) {
  const authenticateUser = async (email, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      
      if (rows.length > 0) {
        const user = rows[0];

        const isValidPassword = await bcrypt.compare(password, user.password);

        if (isValidPassword) {
          return done(null, user); 
        } else {
          return done(null, false, { message: "Incorrect password" }); // Invalid password
        }
      } else {
        return done(null, false, { message: "No user with that email" }); // User not found
      }
    } catch (err) {
      console.error("Error during authentication:", err);
      return done(err); 
    }
  };

  passport.use(new LocalStrategy({ usernameField: "email" }, authenticateUser));

  passport.serializeUser((user, done) => {
    done(null, user.id); 
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
      
      if (rows.length > 0) {
        done(null, rows[0]); 
      } else {
        done(new Error("User not found")); 
      }
    } catch (err) {
      console.error("Error during deserialization:", err);
      done(err); 
    }
  });
}

module.exports = initialize;
