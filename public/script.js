// Function to check user authentication and update UI
const checkAuth = () => {
  const token = localStorage.getItem('token');
  const user = JSON.parse(localStorage.getItem('user'));

  if (user && token) {
    document.getElementById('loginLink')?.style.display = 'none';
    document.getElementById('registerLink')?.style.display = 'none';
    document.getElementById('logout')?.style.display = 'block';
    document.getElementById('userInfo')?.style.display = 'block';
    document.getElementById('userName')?.textContent = user.name;
    document.getElementById('accountNumber')?.textContent = user.accountNumber;

    updateBalance();
    loadTransactions();
  } else {
    window.location.href = 'login.html'; // Redirect to login if not authenticated
  }
};

// Function to update balance
const updateBalance = () => {
  const token = localStorage.getItem('token');

  fetch('/api/balance', {
    headers: { 'Authorization': token },
  })
    .then(response => response.json())
    .then(data => {
      document.getElementById('balance')?.textContent = `$${data.balance}`;
    })
    .catch(err => console.error('❌ Error fetching balance:', err));
};

// Function to fetch and display transaction history
const loadTransactions = () => {
  const token = localStorage.getItem('token');

  fetch('/api/transactions', {
    headers: { 'Authorization': token },
  })
    .then(response => response.json())
    .then(data => {
      const history = document.getElementById('transactionHistory');
      history.innerHTML = ''; // Clear previous history

      if (data.length === 0) {
        history.innerHTML = '<li>No transactions found.</li>';
      } else {
        data.forEach(transaction => {
          const li = document.createElement('li');
          li.textContent = `💵 $${transaction.amount} to ${transaction.recipient} on ${new Date(transaction.date).toLocaleString()}`;
          history.appendChild(li);
        });
      }
      document.getElementById('transactionSection')?.style.display = 'block';
    })
    .catch(err => console.error('❌ Error fetching transactions:', err));
};

// Login Form Submission
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();
    if (response.ok) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data));
      window.location.href = 'index.html';
    } else {
      document.getElementById('error').textContent = `❌ ${data.message}`;
    }
  } catch (error) {
    console.error('❌ Login error:', error);
  }
});

// Registration Form Submission
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('name').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password }),
    });

    const data = await response.json();
    if (response.ok) {
      alert('✅ Registration successful! Please login.');
      window.location.href = 'login.html';
    } else {
      document.getElementById('error').textContent = `❌ ${data.message}`;
    }
  } catch (error) {
    console.error('❌ Registration error:', error);
  }
});

// Transfer Money Form Submission
document.getElementById('transferForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const recipient = document.getElementById('recipient').value;
  const amount = parseFloat(document.getElementById('amount').value);
  const token = localStorage.getItem('token');

  if (!token) {
    alert('❌ Please log in first.');
    return;
  }

  try {
    const response = await fetch('/api/transfer', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token,
      },
      body: JSON.stringify({ recipient, amount }),
    });

    const data = await response.json();
    document.getElementById('transferStatus').textContent = data.message;
    
    if (response.ok) {
      alert('✅ Transfer successful!');
      updateBalance(); // Update balance dynamically
      loadTransactions(); // Refresh transaction history
      document.getElementById('transferForm').reset();
    }
  } catch (error) {
    console.error('❌ Transfer error:', error);
  }
});

// Logout Functionality
document.getElementById('logout')?.addEventListener('click', () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  window.location.href = 'login.html';
});

// Contact Form Submission
document.getElementById('contactForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('contactName').value;
  const email = document.getElementById('contactEmail').value;
  const message = document.getElementById('contactMessage').value;

  try {
    const response = await fetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, message }),
    });

    const data = await response.json();
    if (response.ok) {
      alert('✅ Your message has been sent successfully!');
      document.getElementById('contactForm').reset();
    } else {
      alert(`❌ ${data.message}`);
    }
  } catch (error) {
    console.error('❌ Contact form error:', error);
  }
});

// Run authentication check on page load
checkAuth();
