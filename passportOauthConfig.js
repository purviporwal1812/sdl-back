require('dotenv').config();
const { Pool } = require('pg');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const pool = new Pool({ connectionString: process.env.POSTGRES_URL });

module.exports = function initializeOAuth(passport) {
  // serialize & deserialize
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
      if (!rows.length) return done(new Error('User not found'));
      done(null, rows[0]);
    } catch (err) {
      done(err);
    }
  });

  // Google strategy
  passport.use(new GoogleStrategy({
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  process.env.OAUTH_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const provider = 'google';
        const providerId = profile.id;
        const email = profile.emails[0].value;

        // 1) existing OAuth user
        let { rows } = await pool.query(
          'SELECT * FROM users WHERE oauth_provider=$1 AND oauth_id=$2',
          [provider, providerId]
        );
        if (rows.length) return done(null, rows[0]);

        // 2) link by email if they signed up locally
        ({ rows } = await pool.query(
          'SELECT * FROM users WHERE email=$1',
          [email]
        ));
        if (rows.length) {
          const user = rows[0];
          await pool.query(
            `UPDATE users
               SET oauth_provider=$1, oauth_id=$2
             WHERE id=$3`,
            [provider, providerId, user.id]
          );
          user.oauth_provider = provider;
          user.oauth_id = providerId;
          return done(null, user);
        }

        // 3) brand‑new user
        const insert = await pool.query(
          `INSERT INTO users (email, oauth_provider, oauth_id, theme)
           VALUES ($1,$2,$3,'light') RETURNING *`,
          [email, provider, providerId]
        );
        done(null, insert.rows[0]);

      } catch (err) {
        console.error('[Google OAuth] verify error:', err);
        done(err, false, { message: 'Internal error; check logs' });
      }
    }
  ));
};
