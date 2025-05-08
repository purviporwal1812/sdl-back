require('dotenv').config();
const { Pool } = require('pg');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Ensure your POSTGRES_URL is set
if (!process.env.POSTGRES_URL) {
  console.error('❌ POSTGRES_URL not set in .env');
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.POSTGRES_URL });
pool.on('error', err => console.error('Postgres pool error', err));

module.exports = function initializeOAuth(passport) {
  // — serialize / deserialize —
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
      if (!rows.length) {
        console.error('[OAuth] deserializeUser: no user', id);
        return done(new Error('User not found'));
      }
      done(null, rows[0]);
    } catch (err) {
      console.error('[OAuth] deserializeUser error:', err);
      done(err);
    }
  });

  // — Google Strategy —
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.OAUTH_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        console.log('[OAuth] verify callback, profile.id=', profile.id);
        try {
          const provider = 'google';
          const providerId = profile.id;
          const email = profile.emails[0].value;

          // 1) existing OAuth user?
          let { rows } = await pool.query(
            'SELECT * FROM users WHERE oauth_provider=$1 AND oauth_id=$2',
            [provider, providerId]
          );
          if (rows.length) {
            console.log('[OAuth] found OAuth user:', rows[0].id);
            return done(null, rows[0]);
          }

          // 2) link by email?
          ({ rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]));
          if (rows.length) {
            const user = rows[0];
            console.log('[OAuth] linking Google to user:', user.id);
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

          // 3) brand‑new user ⇒ generate & hash a random password
          console.log('[OAuth] creating new user for email:', email);
          const randomPw = crypto.randomBytes(12).toString('hex');
          const hashedPw = await bcrypt.hash(randomPw, 10);

          const insert = await pool.query(
            `INSERT INTO users 
               (email, password, oauth_provider, oauth_id, theme) 
             VALUES ($1,$2,$3,$4,'light') 
             RETURNING *`,
            [email, hashedPw, provider, providerId]
          );
          return done(null, insert.rows[0]);
        } catch (err) {
          console.error('[OAuth] verify error:', err);
          return done(err, false, { message: 'Internal error; check logs' });
        }
      }
    )
  );
};
