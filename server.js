const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const Redis = require('ioredis'); // Import ioredis

const app = express();
const port = 3000;

app.use(bodyParser.json());

// --- PostgreSQL Configuration ---
const pool = new Pool({
  user: 'your_db_user',        // Replace with your PostgreSQL username
  host: 'localhost',            // Replace with your PostgreSQL host
  database: 'your_db_name',     // Replace with your PostgreSQL database name
  password: 'your_db_password', // Replace with your PostgreSQL password
  port: 5432,                   // Default PostgreSQL port
});

// Helper function to execute database queries
const query = async (text, params) => {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
};

// --- Redis Configuration ---
// Connect to Redis. Adjust host and port if your Redis server is elsewhere.
const redisClient = new Redis({
  host: 'localhost', // Replace with your Redis host
  port: 6379,        // Default Redis port
});

// Handle Redis connection errors
redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
  // In a production environment, you might want more robust error handling
  // e.g., logging to a monitoring system, or attempting to reconnect.
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

// Cache expiration time in seconds (e.g., 60 seconds)
const CACHE_EXPIRATION_SECONDS = 60;

// --- Authentication ---

// Route for user registration (for testing purposes - in a real app, be careful with this)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') { // unique_violation
      return res.status(409).json({ error: 'Username already exists.' });
    }
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Route for user login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const result = await query('SELECT id, username, password_hash FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (passwordMatch) {
      // In a real application, you would generate a JWT here
      res.json({ message: 'Login successful', userId: user.id, username: user.username });
    } else {
      res.status(401).json({ error: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Middleware to protect routes (simple authentication check)
const authenticate = async (req, res, next) => {
  const { authorization } = req.headers;
  if (!authorization || !authorization.startsWith('Basic ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const encoded = authorization.split(' ')[1];
  try {
    const decoded = Buffer.from(encoded, 'base64').toString().split(':');
    const username = decoded[0];
    const password = decoded[1];

    const result = await query('SELECT password_hash FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (passwordMatch) {
      req.user = { username }; // Attach user info to the request if needed
      next();
    } else {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ error: 'Authentication failed.' });
  }
};

// --- CRUD Operations for Incidents with Caching ---

// GET all incidents (requires authentication)
app.get('/incidents', authenticate, async (req, res) => {
  const cacheKey = 'all_incidents';
  try {
    // Try to get data from Redis cache
    const cachedIncidents = await redisClient.get(cacheKey);
    if (cachedIncidents) {
      console.log('Serving incidents from Redis cache');
      return res.json(JSON.parse(cachedIncidents));
    }

    // If not in cache, fetch from PostgreSQL
    console.log('Fetching incidents from PostgreSQL');
    const result = await query('SELECT * FROM incidents ORDER BY date DESC');
    const incidents = result.rows;

    // Store in Redis cache
    await redisClient.setex(cacheKey, CACHE_EXPIRATION_SECONDS, JSON.stringify(incidents));

    res.json(incidents);
  } catch (error) {
    console.error('Error fetching incidents (with caching):', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET a single incident by ID (requires authentication)
app.get('/incidents/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const cacheKey = `incident:${id}`;
  try {
    // Try to get data from Redis cache
    const cachedIncident = await redisClient.get(cacheKey);
    if (cachedIncident) {
      console.log(`Serving incident ${id} from Redis cache`);
      return res.json(JSON.parse(cachedIncident));
    }

    // If not in cache, fetch from PostgreSQL
    console.log(`Fetching incident ${id} from PostgreSQL`);
    const result = await query('SELECT * FROM incidents WHERE id = $1', [id]);
    if (result.rows.length > 0) {
      const incident = result.rows[0];
      // Store in Redis cache
      await redisClient.setex(cacheKey, CACHE_EXPIRATION_SECONDS, JSON.stringify(incident));
      res.json(incident);
    } else {
      res.status(404).json({ message: 'Incident not found.' });
    }
  } catch (error) {
    console.error(`Error fetching incident with ID ${id} (with caching):`, error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST a new incident (requires authentication)
app.post('/incidents', authenticate, async (req, res) => {
  const { title, reporter, type, description, resource_id } = req.body;
  if (!title) {
    return res.status(400).json({ error: 'Title is required.' });
  }
  try {
    const result = await query(
      'INSERT INTO incidents (title, reporter, type, description, resource_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, reporter, type, description, resource_id]
    );
    const newIncident = result.rows[0];

    // Invalidate relevant caches after a write operation
    await redisClient.del('all_incidents'); // Invalidate the list of all incidents
    await redisClient.del(`incident:${newIncident.id}`); // Invalidate cache for this specific incident

    res.status(201).json(newIncident);
  } catch (error) {
    console.error('Error creating incident (with caching invalidation):', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT (update) an existing incident (requires authentication)
app.put('/incidents/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, reporter, type, description, resource_id } = req.body;
  try {
    const result = await query(
      'UPDATE incidents SET title = $1, reporter = $2, type = $3, description = $4, resource_id = $5, updated_at = NOW() WHERE id = $6 RETURNING *',
      [title, reporter, type, description, resource_id, id]
    );
    if (result.rows.length > 0) {
      const updatedIncident = result.rows[0];

      // Invalidate relevant caches after a write operation
      await redisClient.del('all_incidents'); // Invalidate the list of all incidents
      await redisClient.del(`incident:${id}`); // Invalidate cache for this specific incident

      res.json(updatedIncident);
    } else {
      res.status(404).json({ message: 'Incident not found.' });
    }
  } catch (error) {
    console.error(`Error updating incident with ID ${id} (with caching invalidation):`, error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE an incident (requires authentication)
app.delete('/incidents/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await query('DELETE FROM incidents WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount > 0) {
      // Invalidate relevant caches after a write operation
      await redisClient.del('all_incidents'); // Invalidate the list of all incidents
      await redisClient.del(`incident:${id}`); // Invalidate cache for the deleted incident

      res.json({ message: `Incident with ID ${id} deleted.` });
    } else {
      res.status(404).json({ message: 'Incident not found.' });
    }
  } catch (error) {
    console.error(`Error deleting incident with ID ${id} (with caching invalidation):`, error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
