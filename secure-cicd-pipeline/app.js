const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const hpp = require('hpp');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Set security HTTP headers
app.use(helmet());

// Enable CORS with secure options
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
}));

// Limit requests from same IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(hpp());

// Simple route
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Welcome to the Secure API'
  });
});

// Example of a secure route with input validation
app.post('/api/data', [
  body('name').trim().isLength({ min: 3 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('message').trim().isLength({ min: 5, max: 500 }).escape()
], (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // Process the validated data
  const { name, email, message } = req.body;
  
  // In a real app, you would store this data securely
  console.log(`Received message from ${name} (${email}): ${message}`);
  
  res.status(201).json({
    status: 'success',
    message: 'Data received successfully'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!'
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;
