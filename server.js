const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Add CORS headers middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'http://localhost:8080');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.type('application/json');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(bodyParser.json());

// --- Configuration ---
let dbConfig;
if (process.env.DATABASE_URL) {
  dbConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false // Required for some cloud providers like Heroku
    }
  };
} else {
  dbConfig = {
    user: process.env.POSTGRES_USER || 'dani',
    host: process.env.POSTGRES_HOST || 'localhost',
    database: process.env.POSTGRES_DB || 'incidentDb',
    password: process.env.POSTGRES_PASSWORD || 'dani1234',
    port: process.env.POSTGRES_PORT || 5432,
  };
}

let redisClient;
if (process.env.APP_REDIS_CONNECTION_STRING) {
  redisClient = new Redis(process.env.APP_REDIS_CONNECTION_STRING);
} else {
  const redisConfig = {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
  };
  redisClient = new Redis(redisConfig);
}

const JWT_SECRET = process.env.SESSION_SECRET || 'your-secret-key'; // Replace with a strong, secret key

// PostgreSQL connection pool
const pool = new Pool(dbConfig);

// Test PostgreSQL connection
(async () => {
  let client;
  try {
    client = await pool.connect();
    console.log('Successfully connected to PostgreSQL database!');
  } catch (err) {
    console.error('Failed to connect to PostgreSQL database:', err);
    // Optionally, you might want to exit the process if the DB connection fails at startup
    // process.exit(1);
  } finally {
    if (client) {
      client.release();
    }
  }
})();

// Helper function to execute database queries
const query = async (text, params) => {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
};

// Redis client
// const redisClient = new Redis(redisConfig); // This line is now replaced by the conditional logic above

redisClient.on('error', (err) => {
  
  console.error('TEST TEST TEST Redis Client Error:' + redisClient, err);
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

const CACHE_EXPIRATION_SECONDS = 60;

// --- Authentication ---

// Function to generate a JWT
const generateToken = (userId, username) => {
  return jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour
};

// Route for user registration
app.post('/api/register', async (req, res) => {
  console.log("Requested registration:", req.ip);
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
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Route for user login
app.post('/api/login', async (req, res) => {
  console.log("Requested login:", req.ip);
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
      const token = generateToken(user.id, user.username);
      res.json({ message: 'Login successful', token: token });
    } else {
      res.status(401).json({ error: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    req.user = user;
    next();
  });
};

// --- CRUD Operations for Incidents with Caching and Token Authentication ---

// GET all incidents (requires token authentication)
app.get('/api/incidents', authenticateToken, async (req, res) => {
  console.log("Requested incidents:", req.ip);
  const cacheKey = 'all_incidents';
  try {
    const cachedIncidents = await redisClient.get(cacheKey);
    if (cachedIncidents) {
      console.log('Serving incidents from Redis cache');
      return res.json(JSON.parse(cachedIncidents));
    }

    console.log('Fetching incidents from PostgreSQL');
    const result = await query('SELECT * FROM incidents ORDER BY date DESC');
    const incidents = result.rows;

    await redisClient.setex(cacheKey, CACHE_EXPIRATION_SECONDS, JSON.stringify(incidents));

    res.json(incidents);
  } catch (error) {
    console.error('Error fetching incidents (with caching):', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET a single incident by ID (requires token authentication)
app.get('/api/incidents/:id', authenticateToken, async (req, res) => {
  console.log("Requested incident with id:", req.ip);
  const { id } = req.params;
  const cacheKey = `incident:${id}`;
  try {
    const cachedIncident = await redisClient.get(cacheKey);
    if (cachedIncident) {
      console.log(`Serving incident ${id} from Redis cache`);
      return res.json(JSON.parse(cachedIncident));
    }

    console.log(`Fetching incident ${id} from PostgreSQL`);
    const result = await query('SELECT * FROM incidents WHERE id = $1', [id]);
    if (result.rows.length > 0) {
      const incident = result.rows[0];
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

// POST a new incident (requires token authentication)
app.post('/api/incidents', authenticateToken, async (req, res) => {
  console.log("Requested incident creation:", req.ip);
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

    await redisClient.del('all_incidents');
    await redisClient.del(`incident:${newIncident.id}`);

    res.status(201).json(newIncident);
  } catch (error) {
    console.error('Error creating incident (with caching invalidation):', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// PUT (update) an existing incident (requires token authentication)
app.put('/api/incidents/:id', authenticateToken, async (req, res) => {
  console.log("Requested incident update:", req.ip);
  const { id } = req.params;
  const { title, reporter, type, description, resource_id } = req.body;
  try {
    const result = await query(
      'UPDATE incidents SET title = $1, reporter = $2, type = $3, description = $4, resource_id = $5, updated_at = NOW() WHERE id = $6 RETURNING *',
      [title, reporter, type, description, resource_id, id]
    );
    if (result.rows.length > 0) {
      const updatedIncident = result.rows[0];

      await redisClient.del('all_incidents');
      await redisClient.del(`incident:${id}`);

      res.json(updatedIncident);
    } else {
      res.status(404).json({ message: 'Incident not found.' });
    }
  } catch (error) {
    console.error(`Error updating incident with ID ${id} (with caching invalidation):`, error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE an incident (requires token authentication)
app.delete('/api/incidents/:id', authenticateToken, async (req, res) => {
  console.log("Requested incident deletion:", req.ip);
  const { id } = req.params;
  console.log(req.url);
  try {
    const result = await query('DELETE FROM incidents WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount > 0) {
      await redisClient.del('all_incidents');
      await redisClient.del(`incident:${id}`);

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