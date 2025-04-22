// Required packages
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect('mongodb://127.0.0.1:27017/online-banking', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  accountNumber: { type: String, unique: true, default: () => Math.floor(1000000000 + Math.random() * 9000000000).toString() },
  balance: { type: Number, default: 1000 },
  role: { type: String, default: 'user' },
  mfaCode: String,
  mfaExpires: Date
});
const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  amount: Number,
  date: { type: Date, default: Date.now },
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// Password policy function
function validatePassword(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return regex.test(password);
}

// JWT middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const authorizeRole = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).json({ message: 'Access denied' });
  next();
};

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'magedelgawish54@gmail.com',
    pass: 'fqqlitojvhocquai'  // use an App Password here
  },
  tls: {
    rejectUnauthorized: false  // Allow self-signed certs (for development)
  }
});


// Register route
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!validatePassword(password)) return res.status(400).json({ message: 'Password does not meet criteria' });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = new User({ name, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'Registered successfully' });
  } catch (err) {
    res.status(400).json({ message: 'Registration error' });
  }
});

// Login route
// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Generate MFA code
  const code = Math.floor(100000 + Math.random() * 900000);
  user.mfaCode = code;
  user.mfaExpires = new Date(Date.now() + 10 * 60 * 1000);
  await user.save();

  // Try sending MFA code via email
  try {
    const info = await transporter.sendMail({
      from: '"Online Banking" <magedelgawish54@gmail.com>',
      to: email,
      subject: '🔐 Your MFA Code for Online Banking',
      text: `Hello ${user.name},\n\nYour Multi-Factor Authentication (MFA) code is: ${code}\n\nThis code is valid for 10 minutes.\n\nIf you did not attempt to log in, please ignore this message.\n\n- Online Banking Team`
    });

    // Log preview URL and code for debugging
    console.log(`📧 MFA code sent to ${email}: ${code}`);
    console.log('📬 Email preview URL:', nodemailer.getTestMessageUrl?.(info) || 'Production mode');

    res.json({ message: 'MFA code sent to your email.' });
  } catch (error) {
    console.error('❌ Failed to send MFA email:', error);
    res.status(500).json({ message: 'Failed to send MFA code. Please try again later.' });
  }
});

// MFA Verification
app.post('/api/verify-mfa', async (req, res) => {
  const { email, code } = req.body;
  const user = await User.findOne({ email });
  if (!user || user.mfaCode !== code || user.mfaExpires < new Date()) {
    return res.status(400).json({ message: 'Invalid or expired MFA code' });
  }
  const token = jwt.sign({ email: user.email, name: user.name, role: user.role, accountNumber: user.accountNumber }, 'secret_key', { expiresIn: '1h' });
  res.json({ token, name: user.name, accountNumber: user.accountNumber });
});

// Transfer money
app.post('/api/transfer', authenticateToken, async (req, res) => {
  const { recipient, amount } = req.body;
  const sender = await User.findOne({ email: req.user.email });
  const receiver = await User.findOne({ accountNumber: recipient });

  if (!receiver) return res.status(404).json({ message: 'Recipient not found' });
  if (sender.balance < amount) return res.status(400).json({ message: 'Insufficient funds' });

  sender.balance -= amount;
  receiver.balance += amount;
  await sender.save();
  await receiver.save();

  const transaction = new Transaction({ sender: sender.accountNumber, recipient, amount });
  await transaction.save();

  res.json({ message: 'Transfer successful' });
});

// Get balance
app.get('/api/balance', authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email });
  res.json({ balance: user.balance });
});

// Get transaction history
app.get('/api/transactions', authenticateToken, async (req, res) => {
  const transactions = await Transaction.find({ sender: req.user.accountNumber });
  res.json(transactions);
});

// Contact route
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;
  console.log(`📩 Contact from ${name} (${email}): ${message}`);
  res.json({ message: 'Message received' });
});

// Google OAuth (placeholder)
const googleClient = new OAuth2Client('YOUR_GOOGLE_CLIENT_ID');
app.post('/api/google-login', async (req, res) => {
  const { token } = req.body;
  const ticket = await googleClient.verifyIdToken({ idToken: token, audience: 'YOUR_GOOGLE_CLIENT_ID' });
  const payload = ticket.getPayload();
  const email = payload.email;
  let user = await User.findOne({ email });
  if (!user) {
    user = new User({ email, name: payload.name });
    await user.save();
  }
  const jwtToken = jwt.sign({ email, name: user.name, role: user.role, accountNumber: user.accountNumber }, 'secret_key', { expiresIn: '1h' });
  res.json({ token: jwtToken });
});

// Home route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(3000, () => console.log('🚀 Server running at http://localhost:3000'));