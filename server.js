
// Backend: server.js using Node.js + Express + MySQL

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const SECRET = 'your_jwt_secret';

app.use(cors());
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL connected');
});

// Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Auth routes
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) return res.status(401).send('Invalid credentials');
    const valid = await bcrypt.compare(password, results[0].password_hash);
    if (!valid) return res.status(401).send('Invalid credentials');
    const token = jwt.sign({ id: results[0].id }, SECRET);
    res.json({ token });
  });
});

// Customer routes
app.get('/customers', authenticateToken, (req, res) => {
  db.query('SELECT * FROM customers', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.post('/customers', authenticateToken, (req, res) => {
  const { name, email } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).send('Invalid email');
  db.query('INSERT INTO customers (name, email) VALUES (?, ?)', [name, email], (err, result) => {
    if (err) return res.status(500).send(err);
    res.sendStatus(201);
  });
});

app.put('/customers/:id', authenticateToken, (req, res) => {
  const { name, email } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).send('Invalid email');
  db.query('UPDATE customers SET name = ?, email = ? WHERE id = ?', [name, email, req.params.id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.sendStatus(200);
  });
});

app.delete('/customers/:id', authenticateToken, (req, res) => {
  db.query('DELETE FROM customers WHERE id = ?', [req.params.id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.sendStatus(200);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
