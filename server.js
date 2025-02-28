const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Serve static files from "public"
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/online-banking', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ Failed to connect to MongoDB:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  accountNumber: { type: String, unique: true },
  balance: { type: Number, default: 1000 },
});

const User = mongoose.model('User', userSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  amount: Number,
  date: { type: Date, default: Date.now },
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    req.user = user;
    next();
  });
};

// ✅ Register API
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      accountNumber: Math.random().toString().slice(2, 12),
    });
    await user.save();
    res.json({ message: '✅ User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: '❌ Server error.' });
  }
});

// ✅ Login API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: '1h' });
      res.json({ token, name: user.name, accountNumber: user.accountNumber, balance: user.balance });
    } else {
      res.status(401).json({ message: '❌ Invalid credentials.' });
    }
  } catch (err) {
    res.status(500).json({ message: '❌ Server error.' });
  }
});

// ✅ Get Balance API (Requires Authentication)
app.get('/api/balance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    res.json({ balance: user.balance });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Transfer Money API (Requires Authentication)
app.post('/api/transfer', authenticateToken, async (req, res) => {
  const { recipient, amount } = req.body;

  if (!recipient || !amount || amount <= 0) {
    return res.status(400).json({ message: 'Recipient and valid amount are required.' });
  }

  try {
    const senderUser = await User.findById(req.user.id);
    const recipientUser = await User.findOne({ accountNumber: recipient });

    if (!senderUser || !recipientUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (senderUser.accountNumber === recipientUser.accountNumber) {
      return res.status(400).json({ message: '❌ Cannot transfer money to yourself.' });
    }

    if (senderUser.balance < amount) {
      return res.status(400).json({ message: '❌ Insufficient balance.' });
    }

    // Process transfer
    senderUser.balance -= amount;
    recipientUser.balance += amount;
    await senderUser.save();
    await recipientUser.save();

    // Save transaction record
    const transaction = new Transaction({ sender: senderUser.accountNumber, recipient, amount });
    await transaction.save();

    res.json({
      message: '✅ Transfer successful.',
      updatedBalance: senderUser.balance, // Return updated balance
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Get Transaction History API (Requires Authentication)
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const transactions = await Transaction.find({
      $or: [{ sender: user.accountNumber }, { recipient: user.accountNumber }],
    }).sort({ date: -1 });

    res.json(transactions);
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Serve Dashboard Page
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start Server
app.listen(5000, () => {
  console.log('🚀 Server running on http://localhost:5000');
});
