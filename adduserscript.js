const { Pool } = require('pg');
const bcrypt = require('bcrypt');

// Database config (adjust if needed)
const dbConfig = {
  user: 'dani',
  host: 'localhost',
  database: 'incidentDb',
  password: 'dani1234',
  port: 5432,
};

const pool = new Pool(dbConfig);

async function addUser(username, password) {
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    console.log('User added:', result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      console.error('Username already exists.');
    } else {
      console.error('Error adding user:', err);
    }
  } finally {
    await pool.end();
  }
}

// Change these values as needed
addUser('dani', '1234');