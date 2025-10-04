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
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const expressValidator = require('express-validator');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: 'Too many login attempts, please try again later.',
  skipSuccessfulRequests: true,
});

app.use(limiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? ['https://yourdomain.com'] : true,
  credentials: true
}));
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
  savingsBalance: { type: Number, default: 0 },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  mfaCode: String,
  mfaExpires: Date,
  // Enhanced 2FA
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  // Security features
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  lastActivity: { type: Date, default: Date.now },
  passwordResetToken: String,
  passwordResetExpires: Date,
  // Account management
  accountType: { type: String, default: 'checking', enum: ['checking', 'savings', 'business'] },
  isActive: { type: Boolean, default: true },
  // Profile
  phone: String,
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  dateOfBirth: Date,
  // Audit
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  amount: Number,
  date: { type: Date, default: Date.now },
  type: { 
    type: String, 
    enum: ['transfer', 'deposit', 'withdrawal', 'payment', 'refund', 'fee'], 
    default: 'transfer' 
  },
  category: { 
    type: String, 
    enum: ['food', 'transportation', 'entertainment', 'utilities', 'healthcare', 'shopping', 'education', 'travel', 'other'],
    default: 'other'
  },
  description: String,
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'completed' 
  },
  reference: String,
  fee: { type: Number, default: 0 },
  // For deposits/withdrawals
  method: { 
    type: String, 
    enum: ['bank_transfer', 'cash', 'check', 'card', 'online'], 
    default: 'online' 
  }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// Input validation functions
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePhone(phone) {
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  return phoneRegex.test(phone.replace(/\s/g, ''));
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
}

function validateAmount(amount) {
  return !isNaN(amount) && amount > 0 && amount <= 1000000; // Max $1M per transaction
}

// Password policy function
function validatePassword(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return regex.test(password);
}

// Detailed password validation function
function getPasswordValidationDetails(password) {
  const issues = [];
  
  if (password.length < 8) {
    issues.push('at least 8 characters');
  }
  if (!/[a-z]/.test(password)) {
    issues.push('at least one lowercase letter (a-z)');
  }
  if (!/[A-Z]/.test(password)) {
    issues.push('at least one uppercase letter (A-Z)');
  }
  if (!/\d/.test(password)) {
    issues.push('at least one number (0-9)');
  }
  if (!/[@$!%*?&]/.test(password)) {
    issues.push('at least one special character (@$!%*?&)');
  }
  
  return issues;
}

// Security helper functions
function isAccountLocked(user) {
  return !!(user.lockUntil && user.lockUntil > Date.now());
}

function incrementLoginAttempts(user) {
  // If we have a previous lock that has expired, restart at 1
  if (user.lockUntil && user.lockUntil < Date.now()) {
    return user.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (user.loginAttempts + 1 >= 5 && !isAccountLocked(user)) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return user.updateOne(updates);
}

function resetLoginAttempts(user) {
  return user.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 },
    $set: { lastActivity: new Date() }
  });
}

function generatePasswordResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[0] === 'Bearer' 
    ? authHeader.split(' ')[1] 
    : authHeader;
    
  console.log('🔑 Auth header:', authHeader);
  console.log('🔑 Token extracted:', token);
  
  if (!token) {
    console.log('❌ No token provided');
    return res.sendStatus(401);
  }
  
  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) {
      console.log('❌ Token verification failed:', err.message);
      return res.sendStatus(403);
    }
    console.log('✅ Token verified for user:', user.email);
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
  
  // Validate password and provide detailed feedback
  if (!validatePassword(password)) {
    const issues = getPasswordValidationDetails(password);
    return res.status(400).json({ 
      message: `Password does not meet criteria. Missing: ${issues.join(', ')}` 
    });
  }
  
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = new User({ name, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'Registered successfully' });
  } catch (err) {
    if (err.code === 11000) {
      res.status(400).json({ message: 'Email already exists' });
    } else {
      res.status(400).json({ message: 'Registration error' });
    }
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Check if account is locked
  if (isAccountLocked(user)) {
    const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / (1000 * 60));
    return res.status(423).json({ 
      message: `Account locked due to too many failed attempts. Try again in ${lockTimeRemaining} minutes.` 
    });
  }

  // Check password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  
  if (!isPasswordValid) {
    await incrementLoginAttempts(user);
    const attemptsLeft = 5 - (user.loginAttempts + 1);
    
    if (attemptsLeft > 0) {
      return res.status(401).json({ 
        message: `Invalid credentials. ${attemptsLeft} attempts remaining.` 
      });
    } else {
      return res.status(423).json({ 
        message: 'Account locked due to too many failed attempts. Try again in 2 hours.' 
      });
    }
  }

  // Reset login attempts on successful password check
  await resetLoginAttempts(user);

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
  const { recipient, amount, category = 'other', description = 'Transfer' } = req.body;
  
  if (!validateAmount(amount)) {
    return res.status(400).json({ message: 'Invalid amount' });
  }
  
  try {
    const sender = await User.findOne({ email: req.user.email });
    const receiver = await User.findOne({ accountNumber: recipient });

    if (!receiver) return res.status(404).json({ message: 'Recipient not found' });
    if (sender.balance < amount) return res.status(400).json({ message: 'Insufficient funds' });

    sender.balance -= amount;
    receiver.balance += amount;
    await sender.save();
    await receiver.save();

    const transaction = new Transaction({ 
      sender: sender.accountNumber, 
      recipient, 
      amount: parseFloat(amount),
      type: 'transfer',
      category: sanitizeInput(category),
      description: sanitizeInput(description),
      status: 'completed'
    });
    await transaction.save();

    res.json({ 
      message: 'Transfer successful',
      newBalance: sender.balance,
      transaction: transaction
    });
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ message: 'Transfer failed' });
  }
});

// Get balance
app.get('/api/balance', authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email });
  res.json({ balance: user.balance });
});

// Get transaction history
app.get('/api/transactions', authenticateToken, async (req, res) => {
  const { category, type, limit = 50, page = 1 } = req.query;
  const user = await User.findOne({ email: req.user.email });
  
  let query = { 
    $or: [
      { sender: user.accountNumber },
      { recipient: user.accountNumber }
    ]
  };
  
  if (category) query.category = category;
  if (type) query.type = type;
  
  const transactions = await Transaction.find(query)
    .sort({ date: -1 })
    .limit(parseInt(limit))
    .skip((parseInt(page) - 1) * parseInt(limit));
    
  res.json(transactions);
});

// Get transaction categories
app.get('/api/transaction-categories', authenticateToken, (req, res) => {
  const categories = [
    { value: 'food', label: '🍔 Food & Dining', color: '#FF6B6B' },
    { value: 'transportation', label: '🚗 Transportation', color: '#4ECDC4' },
    { value: 'entertainment', label: '🎬 Entertainment', color: '#45B7D1' },
    { value: 'utilities', label: '⚡ Utilities', color: '#96CEB4' },
    { value: 'healthcare', label: '🏥 Healthcare', color: '#FFEAA7' },
    { value: 'shopping', label: '🛍️ Shopping', color: '#DDA0DD' },
    { value: 'education', label: '📚 Education', color: '#98D8C8' },
    { value: 'travel', label: '✈️ Travel', color: '#F7DC6F' },
    { value: 'other', label: '📦 Other', color: '#BB8FCE' }
  ];
  res.json(categories);
});

// Deposit money
app.post('/api/deposit', authenticateToken, async (req, res) => {
  console.log('💰 Deposit request received:', req.body);
  console.log('👤 User from token:', req.user);
  
  const { amount, method = 'online', description = 'Deposit' } = req.body;
  
  if (!amount || isNaN(amount)) {
    console.log('❌ Invalid amount:', amount);
    return res.status(400).json({ message: 'Invalid amount provided' });
  }
  
  if (!validateAmount(amount)) {
    console.log('❌ Amount validation failed:', amount);
    return res.status(400).json({ message: 'Invalid amount - must be between $0.01 and $1,000,000' });
  }
  
  try {
    const user = await User.findOne({ email: req.user.email });
    console.log('👤 User found:', user ? 'Yes' : 'No');
    
    if (!user) {
      console.log('❌ User not found for email:', req.user.email);
      return res.status(404).json({ message: 'User not found' });
    }
    
    console.log('💰 Current balance:', user.balance);
    console.log('💰 Deposit amount:', parseFloat(amount));
    
    user.balance += parseFloat(amount);
    await user.save();
    
    console.log('💰 New balance:', user.balance);
    
    const transaction = new Transaction({
      sender: 'SYSTEM',
      recipient: user.accountNumber,
      amount: parseFloat(amount),
      type: 'deposit',
      description: sanitizeInput(description),
      method: method,
      status: 'completed'
    });
    await transaction.save();
    
    console.log('✅ Transaction saved:', transaction);
    
    res.json({ 
      message: 'Deposit successful', 
      newBalance: user.balance,
      transaction: transaction
    });
  } catch (error) {
    console.error('❌ Deposit error details:', error);
    res.status(500).json({ 
      message: 'Deposit failed', 
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Withdraw money
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  const { amount, method = 'online', description = 'Withdrawal' } = req.body;
  
  if (!validateAmount(amount)) {
    return res.status(400).json({ message: 'Invalid amount' });
  }
  
  try {
    const user = await User.findOne({ email: req.user.email });
    
    if (user.balance < parseFloat(amount)) {
      return res.status(400).json({ message: 'Insufficient funds' });
    }
    
    user.balance -= parseFloat(amount);
    await user.save();
    
    const transaction = new Transaction({
      sender: user.accountNumber,
      recipient: 'SYSTEM',
      amount: parseFloat(amount),
      type: 'withdrawal',
      description: sanitizeInput(description),
      method: method,
      status: 'completed'
    });
    await transaction.save();
    
    res.json({ 
      message: 'Withdrawal successful', 
      newBalance: user.balance,
      transaction: transaction
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ message: 'Withdrawal failed' });
  }
});

// Get account summary
app.get('/api/account-summary', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    
    // Get recent transactions
    const recentTransactions = await Transaction.find({
      $or: [
        { sender: user.accountNumber },
        { recipient: user.accountNumber }
      ]
    }).sort({ date: -1 }).limit(5);
    
    // Get spending by category (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const spendingByCategory = await Transaction.aggregate([
      {
        $match: {
          sender: user.accountNumber,
          date: { $gte: thirtyDaysAgo },
          type: { $in: ['transfer', 'payment'] }
        }
      },
      {
        $group: {
          _id: '$category',
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    res.json({
      balance: user.balance,
      savingsBalance: user.savingsBalance,
      accountNumber: user.accountNumber,
      accountType: user.accountType,
      recentTransactions,
      spendingByCategory
    });
  } catch (error) {
    console.error('Account summary error:', error);
    res.status(500).json({ message: 'Failed to get account summary' });
  }
});

// Forgot Password route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Email not found' });
    }

    // Generate reset token
    const resetToken = generatePasswordResetToken();
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await user.save();

    // Send reset email
    const resetUrl = `http://localhost:3000/reset-password.html?token=${resetToken}`;
    
    await transporter.sendMail({
      from: '"Online Banking" <magedelgawish54@gmail.com>',
      to: email,
      subject: '🔐 Password Reset - Online Banking',
      html: `
        <h2>Password Reset Request</h2>
        <p>Hello ${user.name},</p>
        <p>You requested a password reset for your Online Banking account.</p>
        <p>Click the button below to reset your password:</p>
        <a href="${resetUrl}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a>
        <p>Or copy and paste this link: ${resetUrl}</p>
        <p><strong>This link expires in 15 minutes.</strong></p>
        <p>If you didn't request this, please ignore this email.</p>
        <p>- Online Banking Team</p>
      `
    });

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ message: 'Error sending reset email' });
  }
});

// Reset Password route
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  
  try {
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Validate new password
    if (!validatePassword(password)) {
      const issues = getPasswordValidationDetails(password);
      return res.status(400).json({ 
        message: `Password does not meet criteria. Missing: ${issues.join(', ')}` 
      });
    }

    // Update password and clear reset token
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Contact route
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;
  console.log(`📩 Contact from ${name} (${email}): ${message}`);
  res.json({ message: 'Message received' });
});

// Admin routes
app.get('/api/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const users = await User.find({}, 'name email accountNumber balance accountType isActive createdAt lastActivity')
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.get('/api/admin/transactions', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { limit = 100, page = 1, type, status } = req.query;
    let query = {};
    
    if (type) query.type = type;
    if (status) query.status = status;
    
    const transactions = await Transaction.find(query)
      .sort({ date: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));
      
    res.json(transactions);
  } catch (error) {
    console.error('Admin transactions error:', error);
    res.status(500).json({ message: 'Failed to fetch transactions' });
  }
});

app.get('/api/admin/stats', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const totalTransactions = await Transaction.countDocuments();
    const totalVolume = await Transaction.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const recentUsers = await User.find({}, 'name email createdAt')
      .sort({ createdAt: -1 })
      .limit(5);
      
    res.json({
      totalUsers,
      activeUsers,
      totalTransactions,
      totalVolume: totalVolume[0]?.total || 0,
      recentUsers
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
});

app.put('/api/admin/users/:id/toggle-status', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    user.isActive = !user.isActive;
    await user.save();
    
    res.json({ 
      message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`,
      user: { id: user._id, isActive: user.isActive }
    });
  } catch (error) {
    console.error('Toggle user status error:', error);
    res.status(500).json({ message: 'Failed to toggle user status' });
  }
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