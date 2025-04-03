import express from 'express';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const router = express.Router();

// Signup
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!email || !username || !password) {
      return res.status(400).send('All fields are required!');
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('Email already exists!');
    }
    const user = new User({ username, email, password, role });
    await user.save();
    res.status(201).send('User registered successfully!');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Invalid credentials!');
    }
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Role validation
router.get('/role', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(403).send('No token provided!');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({ role: decoded.role });
  } catch (err) {
    res.status(401).send('Invalid token!');
  }
});


export default router;