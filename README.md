# hackminaaziz.fly.dev 🛡️  
**A deliberately vulnerable Flask web application for learning, practicing, and demonstrating real-world web application security vulnerabilities.**

⚠️ **Warning:** This application is intentionally insecure and should never be deployed in a production environment.

---

## 🎯 Purpose

This project replicates common real-world vulnerabilities found in insecure web applications.  
Each vulnerability includes:

- The vulnerable code snippet  
- Why it’s insecure  
- How to attack/exploit it  
- Secure remediation code  

This makes the repo useful for:
- AppSec portfolio
- Job interviews
- Students learning OWASP concepts
- Red team / blue team training
- Workshops or demos

---

## 🧱 Tech Stack

| Layer | Technology |
|------|------------|
| Backend | Flask (Python) |
| Database | SQLite3 |
| Rendering | Jinja2 |
| UI | Custom CSS (dark theme) |
| OS Interaction | subprocess (for injection demo) |

---

## 🚨 Implemented Vulnerabilities

| Vulnerability | Endpoint | Severity | Description |
|--------------|----------|----------|-------------|
| **IDOR** | `/profile/<id>` | High | No auth, no authorization, SQLi bonus |
| **SQL Injection** | `/comments`, `/profile` | Critical | Raw string concatenation |
| **Stored XSS** | `/comments` | High | Stored + executes for all users |
| **Reflected XSS** | `/search` | Medium | Query param rendered unsafely |
| **Broken Password Reset** | `/reset` | High | Predictable tokens → account takeover |
| **CSRF** | `/comments` | Medium | No token validation |
| **Command Injection** | `/ping` | Critical | `shell=True` + user input |

Full details are in the documentation section.

---

## 📚 Full Vulnerability Guide

All detailed writeups are available here:

👉 **[`docs/vulnerability-guide.md`](docs/vulnerability-guide.md)**

Each subsection includes:

- Vulnerable code (exact snippet from app.py)
- Explanation of the vulnerability
- Impact and attack scenarios
- Real payloads
- Correct secure remediation

---

## 🚀 Running Locally

```bash
git clone https://github.com/your-username/hackminaaziz.git
cd hackminaaziz

python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

pip install -r requirements.txt
python app.py
