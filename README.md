# **📋 Project Description**  
A **secure and efficient** online banking system built with **Node.js, Express.js, and MongoDB**. This project allows users to **register, log in, transfer money, check balances, and track transactions securely** with **JWT authentication**.

---

## **🌟 Features**  
✔ **User Authentication (JWT Token Security)**  
✔ **Secure Money Transfers Between Users**  
✔ **Real-time Balance Updates**  
✔ **Transaction History Tracking (Stored in MongoDB)**  
✔ **Contact Form with Database Storage**  
✔ **Responsive UI (Mobile-Friendly)**  

---

## **🛠 Requirements**  
- **Node.js (v14+)**  
- **MongoDB (Local or Cloud)**  

---

## **📦 Installation**  

### **🔹 Clone the Repository**  
```sh
git clone https://github.com/MagedElgawish230/online-banking-system.git  
cd online-banking-system  
```

### **🔹 Install Dependencies**  
```sh
npm install
```

### **🔹 Start MongoDB Locally**  
```sh
mongod
```

### **🔹 Run the Backend**  
```sh
node server.js
```

### **🔹 Open in Browser**  
Visit: **`http://localhost:5000`**

---

## **🚀 Usage**  

- **Register a New Account**
- **Log In with Credentials**
- **View Account Balance**
- **Transfer Money to Other Users**
- **Check Transaction History**
- **Submit a Contact Form**

---

## **📁 File Structure**  

```
online-banking-system/
│
├── public/            # Frontend Files (HTML, CSS, JS)
│   ├── index.html     # Main Home Page
│   ├── login.html     # User Login Page
│   ├── register.html  # User Registration Page
│   ├── dashboard.html # User Dashboard (Balance & Transfers)
│   ├── contact.html   # Contact Form Page
│   ├── styles.css     # Global Stylesheet
│   ├── script.js      # Client-side JS Functions
│
├── server.js          # Main Backend Server File
├── package.json       # Project Dependencies
├── README.md          # Project Documentation
└── .gitignore         # Files to Ignore in Git
```

---

## **⚙ Configuration**  
Modify these values in `server.js` if needed:

- **Database Connection:**
  ```js
  mongoose.connect('mongodb://127.0.0.1:27017/online-banking');
  ```

- **JWT Secret Key:**
  ```js
  jwt.sign({ id: user._id }, 'secret_key', { expiresIn: '1h' });
  ```

---

## **📊 API Endpoints**  

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/register` | Register a new user |
| `POST` | `/api/login` | User login (JWT Token) |
| `GET`  | `/api/balance` | Get user balance |
| `POST` | `/api/transfer` | Transfer money |
| `GET`  | `/api/transactions` | View transaction history |
| `POST` | `/api/contact` | Submit a contact form |

---

## **📫 Support**  
For support, please open an **issue** in the repository or contact the maintainers.

---

## **📄 License**  
This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

