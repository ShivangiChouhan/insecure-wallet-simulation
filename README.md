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
2. Install dependencies:
   ```bash
   npm install
3. Start the server:
   ```bash
   node server.js
4. Access the application at:
   ```bash
   http://localhost:3000/index.html
                  
Testing Accounts
The following accounts are pre-configured for demonstration purposes:

Username	Password	Role	Balance
alice	password123	  user	1000
bob	password123   	user	500
admin	admin123	   admin	10000

Security Tools Used
- Burp Suite: For manual interception, CSRF PoC generation, and replay attacks
- Postman: For API testing and token manipulation
- Manual Testing: JWT tampering, IDOR enumeration, role escalation

Educational Use Only
This application intentionally lacks key security mechanisms and must never be deployed in a live or production environment. It is intended solely for research, training, and awareness purposes.
