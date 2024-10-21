const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = 'supersecretkey';

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Phd123@p#',
  database: 'task_management'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL Database');
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login.html');
  
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.redirect('/login.html');
    req.userId = decoded.id;
    next();
  });
}

// User Registration
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  
  db.query(query, [username, email, hashedPassword], (err) => {
    if (err) throw err;
    res.redirect('/login.html');
  });
});

// User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const query = 'SELECT * FROM users WHERE email = ?';
  
  db.query(query, [email], (err, results) => {
    if (err) throw err;
    if (results.length === 0) return res.redirect('/login.html?error=1');

    const user = results[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.redirect('/login.html?error=1');

    const token = jwt.sign({ id: user.user_id }, SECRET_KEY, { expiresIn: 86400 });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard.html');
  });
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login.html');
});

// Get all tasks for the logged-in user
app.get('/tasks', verifyToken, (req, res) => {
  const query = 'SELECT * FROM tasks WHERE user_id = ?';
  db.query(query, [req.userId], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// Create a new task
app.post('/tasks/create', verifyToken, (req, res) => {
  const { title, description, due_date, status } = req.body;
  const query = 'INSERT INTO tasks (title, description, due_date, status, user_id) VALUES (?, ?, ?, ?, ?)';
  
  db.query(query, [title, description, due_date, status, req.userId], (err) => {
    if (err) throw err;
    res.redirect('/dashboard.html');
  });
});

// Update a task
app.post('/tasks/update/:id', verifyToken, (req, res) => {
  const { title, description, due_date, status } = req.body;
  const query = 'UPDATE tasks SET title = ?, description = ?, due_date = ?, status = ? WHERE task_id = ? AND user_id = ?';
  
  db.query(query, [title, description, due_date, status, req.params.id, req.userId], (err) => {
    if (err) throw err;
    res.redirect('/dashboard.html');
  });
});

// Delete a task
app.post('/tasks/delete/:id', verifyToken, (req, res) => {
  const query = 'DELETE FROM tasks WHERE task_id = ? AND user_id = ?';
  
  db.query(query, [req.params.id, req.userId], (err) => {
    if (err) throw err;
    res.redirect('/dashboard.html');
  });
});

// Start server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
