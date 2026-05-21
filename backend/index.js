const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ─── DATABASE CONNECTION ───────────────────────────
const db = mysql.createPool({
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: 'root123',
  database: 'ecommerce_db',
  waitForConnections: true,
  connectionLimit: 10,
});
db.getConnection((err, connection) => {
  if (err) {
    console.log('Database connection failed:', err);
    return;
  }
  console.log('MySQL connected successfully!');
  connection.release();
});

// ─── MIDDLEWARE (check if user is logged in) ───────
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1] || req.headers['authorization'];
  if (!token) return res.json({ message: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// ─── HOME ROUTE ────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ message: 'E-Commerce API is running!' });
});

// ─── AUTH ROUTES ───────────────────────────────────

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
  db.query(sql, [name, email, hashedPassword, role || 'user'], (err, result) => {
    if (err) return res.json({ message: 'Email already exists' });
    res.json({ message: 'User registered successfully' });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length === 0) return res.json({ message: 'User not found' });
    const match = await bcrypt.compare(password, results[0].password);
    if (!match) return res.json({ message: 'Wrong password' });
    const token = jwt.sign(
      { id: results[0].id, role: results[0].role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({ message: 'Login successful', token, role: results[0].role, name: results[0].name });
  });
});

// ─── PRODUCT ROUTES ────────────────────────────────

// Get all products
app.get('/api/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    res.json(results);
  });
});

// Get single product
app.get('/api/products/:id', (req, res) => {
  db.query('SELECT * FROM products WHERE id = ?', [req.params.id], (err, results) => {
    res.json(results[0]);
  });
});

// Add product (admin only)
app.post('/api/products', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.json({ message: 'Access denied' });
  const { name, description, price, stock, image_url } = req.body;
  const sql = 'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)';
  db.query(sql, [name, description, price, stock, image_url], (err, result) => {
    res.json({ message: 'Product added successfully' });
  });
});

// Edit product (admin only)
app.put('/api/products/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.json({ message: 'Access denied' });
  const { name, description, price, stock, image_url } = req.body;
  const sql = 'UPDATE products SET name=?, description=?, price=?, stock=?, image_url=? WHERE id=?';
  db.query(sql, [name, description, price, stock, image_url, req.params.id], (err, result) => {
    res.json({ message: 'Product updated successfully' });
  });
});

// Delete product (admin only)
app.delete('/api/products/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.json({ message: 'Access denied' });
  db.query('DELETE FROM products WHERE id = ?', [req.params.id], (err, result) => {
    res.json({ message: 'Product deleted successfully' });
  });
});

// ─── ORDER ROUTES ──────────────────────────────────

// Place order
app.post('/api/orders', verifyToken, (req, res) => {
  const { items, total } = req.body;
  const sql = 'INSERT INTO orders (user_id, total) VALUES (?, ?)';
  db.query(sql, [req.user.id, total], (err, result) => {
    const orderId = result.insertId;
    items.forEach(item => {
      db.query(
        'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderId, item.product_id, item.quantity, item.price]
      );
    });
    res.json({ message: 'Order placed successfully' });
  });
});

// Get user orders
app.get('/api/orders', verifyToken, (req, res) => {
  const sql = req.user.role === 'admin'
    ? 'SELECT * FROM orders'
    : 'SELECT * FROM orders WHERE user_id = ?';
  const params = req.user.role === 'admin' ? [] : [req.user.id];
  db.query(sql, params, (err, results) => {
    res.json(results);
  });
});

// ─── START SERVER ──────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});