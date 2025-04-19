require('dotenv').config();  // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const validator = require('email-validator'); // For email validation

const app = express();
const port = 3000;

// MongoDB connection string from environment variable
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// User Schema
const userSchema = new mongoose.Schema({
  fullname: String,
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String
});

// Create a User model
const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: true
}));

// Serve the Signup page
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Handle the Signup Form Submission
app.post('/signup', async (req, res) => {
  const { fullname, username, email, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.send('<h2>Passwords do not match. <a href="/signup">Try again</a></h2>');
  }

  if (!validator.validate(email)) {
    return res.send('<h2>Invalid email format. <a href="/signup">Try again</a></h2>');
  }

  if (password.length < 6) {
    return res.send('<h2>Password is too weak. It should be at least 6 characters. <a href="/signup">Try again</a></h2>');
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.send('<h2>User already exists. <a href="/signup">Try again</a></h2>');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      fullname,
      username,
      email,
      password: hashedPassword
    });

    await newUser.save();
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.send('<h2>Error occurred during signup. Please try again.</h2>');
  }
});

// Serve the Login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle Login Form Submission
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.send('<h2>User not found. <a href="/login">Try again</a></h2>');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.send('<h2>Incorrect password. <a href="/login">Try again</a></h2>');
    }

    req.session.loggedIn = true;
    req.session.username = user.username;

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.send('<h2>Error occurred during login. Please try again.</h2>');
  }
});

// Serve Home Page (Dashboard)
app.get('/', (req, res) => {
  if (req.session.loggedIn) {
    res.send(`<h1>Welcome ${req.session.username}!</h1><a href="/logout">Logout</a>`);
  } else {
    res.redirect('/login');
  }
});

// Handle Logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.send('<h2>Error during logout.</h2>');
    }
    res.redirect('/login');
  });
});

// ✅ Start server (for other devices too!)
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running at http://0.0.0.0:${port}`);
});
