// passportOauthConfig.js
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.POSTGRES_URL });

function initializeOAuth(passport) {
  // Existing serialize/deserialize
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
      rows.length ? done(null, rows[0]) : done(new Error('User not found'));
    } catch (err) {
      done(err);
    }
  });

  // Google Strategy
  passport.use(new GoogleStrategy({
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  process.env.OAUTH_CALLBACK_URL,
      scope:       ['profile','email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // 1) Try find existing user by OAuth ID
        const providerId = profile.id;
        const provider = 'google';
        const email = profile.emails[0].value;
        
        let result = await pool.query(
          'SELECT * FROM users WHERE oauth_provider=$1 AND oauth_id=$2',
          [provider, providerId]
        );
        
        if (result.rows.length) {
          return done(null, result.rows[0]);
        }
        
        // 2) Else, optionally link by email if user registered via local/signup
        result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
        if (result.rows.length) {
          // update this user to include oauth fields
          const user = result.rows[0];
          await pool.query(
            'UPDATE users SET oauth_provider=$1, oauth_id=$2 WHERE id=$3',
            [provider, providerId, user.id]
          );
          user.oauth_provider = provider;
          user.oauth_id = providerId;
          return done(null, user);
        }
        
        // 3) Or create brand-new user
        const insertRes = await pool.query(
          `INSERT INTO users
           (email, oauth_provider, oauth_id, theme)
           VALUES ($1,$2,$3,'light')
           RETURNING *`,
          [email, provider, providerId]
        );
        done(null, insertRes.rows[0]);
      } catch (err) {
        done(err, false, { message: 'Google OAuth failed' });
      }
    }
  ));
}

module.exports = initializeOAuth;
