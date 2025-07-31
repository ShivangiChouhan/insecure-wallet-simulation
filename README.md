# Insecure Wallet Simulation

This project is a deliberately vulnerable web application simulating a digital wallet system. It is designed as a hands-on playground for exploring and demonstrating common web application security flaws, especially those highlighted in the OWASP Top 10.

The application is built for educational and demonstrative purposes only and must not be deployed in production environments.

---

## Features

- Simulates a simple wallet system with login, balance display, deposit, and withdrawal functionality
- Implements intentionally insecure practices to simulate real-world vulnerabilities
- Demonstrates exploitation and remediation of:
  - Insecure Direct Object References (IDOR)
  - Broken Authentication and Session Management
  - Cross-Site Request Forgery (CSRF)
  - Missing Authorization Controls
  - JWT token misuse and insecure storage

---

## Tech Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express.js
- **Authentication**: JSON Web Tokens (JWT)
- **Testing Tools Used**: Postman, Burp Suite

---

## Folder Structure

insecure-wallet-app/
├── public/
│ ├── index.html # Landing page
│ ├── login.html # Login form + quick login buttons
│ ├── wallet.html # Dashboard to simulate deposit, withdraw, IDOR
│ ├── style.css # UI styling (responsive, card-based layout)
│ └── script.js # Frontend logic (API calls, token handling)
├── server.js # Express backend with intentional vulnerabilities
└── package.json # Project metadata and dependencies


---

## Vulnerabilities Simulated

### 1. Insecure Direct Object Reference (IDOR)
Authenticated users can access or modify other users’ wallet data by tampering with URL parameters (e.g., `userId`) without access control checks.

### 2. Broken Authentication
- JWT tokens are issued with no expiration.
- Weak or hardcoded secrets are used for signing.
- Tokens are reused and exposed both in cookies and responses.
- No secure password hashing or proper validation logic in some flows.

### 3. Missing Authorization Controls
All authenticated users can access sensitive endpoints like `/api/users`, regardless of role. Role-based access checks are absent or improperly implemented.

### 4. CSRF (Cross-Site Request Forgery)
State-changing operations such as deposit and withdraw do not implement CSRF tokens or same-site cookie restrictions, allowing exploitation via forged requests.

---

## How to Run Locally

### Prerequisites
- Node.js (v16 or above)
- npm

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/ShivangiChouhan/insecure-wallet-simulation.git
   cd insecure-wallet-simulation
Install dependencies:
npm install

Start the server:
node server.js

Access the application at:
http://localhost:3000/index.html
