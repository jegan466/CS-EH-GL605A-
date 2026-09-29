# Password Strength Analyzer 🛡️

A modern, high-performance, client-side cybersecurity web application designed to analyze, score, and enhance password security. The application evaluates passwords in real time using regular expressions, detects common patterns and dictionary vulnerabilities, calculates information entropy, estimates brute-force crack time, and features a cryptographically secure password generator.

---

## 🚀 Live Demo & Quick Start

### 1. Direct Browser Launch
Since the application is built entirely with vanilla standard web technologies (HTML5, CSS3, JavaScript ES6+), no build step, compiler, or package manager is required.

Simply double-click `index.html` or open it in any modern web browser:
```bash
# Windows
start index.html
```

### 2. Local Web Server (Optional)
If you prefer running via a local HTTP server:
```bash
# Python 3
python -m http.server 8080
# Open http://localhost:8080 in your browser
```

---

## 🎯 Key Features

### 1. Real-Time Password Analysis
* **Dynamic Evaluation**: Analyzes strength automatically on every keystroke without requiring form submission.
* **Explicit Scan Option**: Includes a **"Check Strength"** button with responsive visual feedback and pulse animations.
* **Show/Hide Password**: Instant toggle with accessible eye icons and ARIA labels.
* **Clear Action**: One-click input wipe with focus return.

### 2. Multi-Metric Scoring System
Evaluates password robustness based on standard cybersecurity metrics:
* **Length ≥ 8 characters**: +20 points
* **Length ≥ 12 characters**: +10 additional points
* **Uppercase letters (`A–Z`)**: +15 points
* **Lowercase letters (`a–z`)**: +15 points
* **Numbers (`0–9`)**: +15 points
* **Special characters (`!@#$%^&*...`)**: +20 points
* **High-Diversity Combination Bonus**: +5 points for combinations with length ≥ 16
* **Normalized Range**: 0% to 100%

### 3. Strength Levels & Visual Feedback
* **0–20%**: `Very Weak` (Crimson Red `#ef4444`)
* **21–40%**: `Weak` (Orange `#f97316`)
* **41–60%**: `Medium` (Amber `#f59e0b`)
* **61–85%**: `Strong` (Emerald Green `#10b981`)
* **86–100%**: `Very Strong` (Neon Cyan `#06b6d4`)

Visual indicators include:
* **5-Segment Glowing Progress Bar**
* **Circular SVG Gauge** with dynamic stroke offset
* **Telemetry Display** (Entropy bits, crack time, character set count)
* **Status Advisory Banner** with contextual security messages

### 4. Interactive Requirements Checklist
Live checklist items update instantly with smooth transitions and status markers:
* ✓ **At least 8 characters**
* ✓ **Contains uppercase letter (A–Z)**
* ✓ **Contains lowercase letter (a–z)**
* ✓ **Contains number (0–9)**
* ✓ **Contains special character (!, @, #, $, %, etc.)**

### 5. Advanced Vulnerability & Pattern Detection
* **Top Common Passwords**: Flags matches against common breached passwords (e.g. `password`, `123456`, `admin123`, `qwerty`).
* **Sequential Patterns**: Detects alphabetical, numeric, and keyboard walks (`123456`, `abcdef`, `qwerty`, `asdfgh`).
* **Repeated Characters**: Detects triple-or-more consecutive identical characters (`aaaaaa`, `1111`).
* **Dictionary Words**: Detects common terms such as `password`, `admin`, `welcome`, `login`.
* **Personal Info Patterns**: Identifies potential birth years or 4-digit date stamps (`1990–2029`).

### 6. Information Entropy & Brute Force Estimator
* **Information Density (Entropy)**: Computed using Shannon entropy principles:
  $$E = L \times \log_2(R)$$
  Where $L$ is password length and $R$ is character pool size (up to 95 printable ASCII symbols).
* **Crack Time Estimation**: Models offline cracking attempts against a high-end multi-GPU cluster ($10^{10}$ hashes per second):
  $$\text{Seconds} = \frac{0.5 \times R^L}{10^{10}}$$
  Formats results into intuitive human terms: `Instant`, `5 seconds`, `2 hours`, `300 years`, `Centuries`.

### 7. Cryptographically Secure Password Generator
* **CSPRNG Generation**: Uses `window.crypto.getRandomValues()` for unpredictable random bytes.
* **Customizable Length**: Range slider from 8 to 32 characters.
* **Character Set Controls**: Independent toggles for Uppercase, Lowercase, Numbers, and Symbols.
* **Ambiguous Character Filter**: Exclude confusing glyphs (`l, 1, I, O, 0`).
* **One-Click Actions**:
  * **Copy to Clipboard** with animated toast confirmation.
  * **Use in Analyzer** to immediately test generated credentials.

### 8. Privacy & Zero-Knowledge Guarantee
* **100% Client-Side**: All regex parsing and strength evaluation occur strictly inside the user's browser.
* **Zero Network Requests**: No external API calls, tracking scripts, or analytics.
* **Transient Memory**: Input passwords are never cached in LocalStorage or cookies.

---

## 📁 File Structure

```
├── index.html       # Semantic HTML5 markup, ARIA accessibility, SVG icons
├── style.css        # Cybersecurity dark theme, glassmorphism, responsive grid
├── script.js        # Pure vanilla JavaScript analysis engine & password generator
└── README.md        # Comprehensive documentation and technical specifications
```

---

## 🔍 Regular Expressions Reference

| Requirement | Regex Pattern | Purpose |
| :--- | :--- | :--- |
| **Uppercase** | `/[A-Z]/` | Verifies presence of capital Latin letters |
| **Lowercase** | `/[a-z]/` | Verifies presence of lowercase Latin letters |
| **Number** | `/[0-9]/` | Verifies presence of numeric digits |
| **Special Character** | `/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/` | Verifies printable special symbols |
| **Repeated Chars** | `/(.)\1{2,}/i` | Flags 3 or more consecutive identical characters |
| **Dictionary Words** | `/password\|admin\|welcome\|login\|user\|qwerty/i` | Flags common credential terms |
| **4-Digit Year** | `/(19\d{2}\|20[0-2]\d)/` | Detects birth years or predictable dates |

---

## 🧪 Verified Test Scenarios

| Test Password | Strength Level | Score | Checklist Met | Key Feedback |
| :--- | :--- | :--- | :--- | :--- |
| `MyPassword@123` | **Strong** | **85%** | 5 of 5 | "Great! Your password is strong and secure." |
| `123456` | **Very Weak** | **15%** | 1 of 5 | "Avoid common passwords. Breached password database match." |
| `admin123` | **Weak** | **40%** | 3 of 5 | "Password is too short. Avoid common dictionary words." |
| `Tr0ub4dor&3#2026` | **Very Strong** | **95%** | 5 of 5 | "Great! Your password meets the recommended security requirements." |
| `qW9#m$L2!vR8*xP` | **Very Strong** | **100%** | 5 of 5 | Full entropy, estimated crack time: Centuries |

---

## 🎨 Design System

* **Theme**: Deep dark cyberpunk aesthetic (`#0a0e17`) with glassmorphic cards (`rgba(16, 24, 42, 0.75)`).
* **Gradients**: Electric indigo (`#6366f1`), purple (`#8b5cf6`), and neon cyan (`#06b6d4`).
* **Typography**:
  * UI Text: `Plus Jakarta Sans`
  * Code/Passwords/Telemetry: `Fira Code`
* **Accessibility**: Fully keyboard operable, visible focus rings, ARIA roles, and high contrast text ratios.
