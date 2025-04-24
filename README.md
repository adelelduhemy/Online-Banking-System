---

## 📋 **Project Description**  
A **secure, responsive, and feature-rich online banking system** built using **Node.js, Express.js, MongoDB, and Vanilla JavaScript**. This system allows users to **register**, **log in with multi-factor authentication**, **view balances**, **transfer money**, and **track transactions**—all securely with **JWT-based authorization**.

---

## 🌟 **Key Features**  

✔ **User Registration & Secure Login (JWT + Bcrypt)**  
✔ **Multi-Factor Authentication (MFA) via Email**  
✔ **Real-time Balance Checking**  
✔ **Money Transfers Between Users (Account Numbers)**  
✔ **Transaction History Stored in MongoDB**  
✔ **Contact Form with Confirmation Feedback**  
✔ **Mobile-Friendly Responsive UI**  
✔ **Google OAuth Integration (Placeholder Ready)**  

---

## 🛠 **Requirements**  

- [Node.js](https://nodejs.org/) (v14+ recommended)  
- [MongoDB](https://www.mongodb.com/) (Local or Atlas)  
- Gmail with [App Passwords](https://myaccount.google.com/apppasswords) for MFA  
- A modern browser (Chrome, Edge, Firefox, etc.)

---

## 📦 **Installation**  

### 🔹 **Clone the Repository**
```bash
git clone https://github.com/MagedElgawish230/online-banking-system.git  
cd online-banking-system
```

### 🔹 **Install Dependencies**
```bash
npm install
```

### 🔹 **Start MongoDB (if local)**
```bash
mongod
```

### 🔹 **Run the Server**
```bash
node server.js
```

### 🔹 **Open in Browser**
Visit: [http://localhost:3000](http://localhost:3000)

---

## 🚀 **How to Use**  

1. 🔐 Register a new user with a strong password  
2. 📧 Receive MFA code by email after login  
3. 🔑 Verify MFA code and get access to dashboard  
4. 💰 Check current balance and transfer money  
5. 📜 View transaction history  
6. 📬 Submit questions via the contact form  

---

## 📁 **Project Structure**  

```
online-banking-system/
│
├── public/               # Static Frontend Files
│   ├── index.html        # Home
│   ├── login.html        # Login with MFA
│   ├── register.html     # User registration
│   ├── dashboard.html    # Transfer & balance
│   ├── contact.html      # Contact form
│   ├── style.css         # CSS styles
│   └── script.js         # Client-side JS
│
├── server.js             # Express.js Backend
├── package.json          # Project Metadata & Dependencies
├── .gitignore            # Git Ignored Files
└── README.md             # Project Documentation
```

---

## ⚙ **Configuration**

In `server.js`, modify:

### 🔹 MongoDB Connection:
```js
mongoose.connect('mongodb://127.0.0.1:27017/online-banking');
```

### 🔹 Gmail & App Password for MFA:
```js
auth: {
  user: 'your-email@gmail.com',
  pass: 'your-app-password'
}
```

### 🔹 JWT Secret:
```js
jwt.sign({ id: user._id }, 'your_secret_key', { expiresIn: '1h' });
```

---

## 📊 **API Endpoints**

| Method | Endpoint            | Description                        |
|--------|---------------------|------------------------------------|
| POST   | `/api/register`     | Register new user                  |
| POST   | `/api/login`        | Log in and receive MFA code        |
| POST   | `/api/verify-mfa`   | Validate MFA and receive JWT       |
| GET    | `/api/balance`      | Fetch current account balance      |
| POST   | `/api/transfer`     | Send money to another account      |
| GET    | `/api/transactions` | Get user's transaction history     |
| POST   | `/api/contact`      | Submit contact/support message     |

---

## 💡 **Future Improvements**

- 🔐 TOTP support (e.g., Google Authenticator)  
- 📱 Mobile app version (React Native)  
- 🧮 Admin dashboard  
- 📈 Graphs & analytics for spending  
- 📄 PDF bank statements  
- 🌐 Multi-language support

---

## 📫 **Support**

For issues or suggestions, open an [Issue](https://github.com/MagedElgawish230/online-banking-system/issues) or reach out via LinkedIn.

---

## 📄 **License**

This project is licensed under the [MIT License](LICENSE).

---

