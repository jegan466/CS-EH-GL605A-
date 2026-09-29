/**
 * Password Strength Analyzer
 * Pure client-side security diagnostic engine with real-time regex analysis,
 * dynamic scoring, pattern detection, entropy calculation, and password generator.
 */

(function () {
  'use strict';

  // ============================================================================
  // Security Data & Dictionaries
  // ============================================================================

  // Top common passwords and patterns to detect
  const COMMON_PASSWORDS = new Set([
    'password', 'password1', 'password123', 'pass1234', '123456', '12345678',
    '123456789', '12345', '1234', '111111', '123123', 'admin', 'admin123',
    'administrator', 'welcome', 'welcome1', 'qwerty', 'qwerty123', 'asdfgh',
    'zxcvbn', 'iloveyou', 'sunshine', 'princess', 'monkey', 'dragon', 'football',
    'superman', 'trustno1', 'letmein', 'shadow', 'master', 'charlie', 'michael',
    'batman', 'starwars', 'killer', 'test', 'secret', 'default', 'login',
    'guest', 'root', 'access', 'computer', 'system', 'internet', 'hello',
    'freedom', 'whatever', 'orange', 'matrix', 'liverpool', 'arsenal', 'chelsea',
    'passw0rd', 'p@ssword', 'p@ssw0rd', 'abc123', '000000', '666666', '1111',
    '123321', '654321', '987654321', 'star', 'donald', 'ashley', 'bailey'
  ]);

  // Sequential patterns to detect
  const SEQUENTIAL_PATTERNS = [
    '123456', '234567', '345678', '456789', '567890',
    'abcdef', 'bcdefg', 'cdefgh', 'defghi', 'efghij',
    'qwerty', 'asdfgh', 'zxcvbn', 'qwertz', 'azerty'
  ];

  // Concrete Hex Colors for reliable cross-browser SVG and CSS rendering
  const COLOR_PALETTE = {
    'empty': '#475569',
    'very-weak': '#ef4444',
    'weak': '#f97316',
    'medium': '#f59e0b',
    'strong': '#10b981',
    'very-strong': '#06b6d4'
  };

  // Special characters regex set
  const REGEX = {
    uppercase: /[A-Z]/,
    lowercase: /[a-z]/,
    number: /[0-9]/,
    special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/,
    repeatedChars: /(.)\1{2,}/i, // 3 or more repeated identical characters
    commonWords: /password|admin|welcome|login|user|qwerty|secret/i,
    yearPattern: /(19\d{2}|20[0-2]\d)/ // Birth year or recent year pattern
  };

  // Character sets for generator
  const CHAR_SETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  const AMBIGUOUS_CHARS = /[il1Lo0O]/g;

  // ============================================================================
  // Initialization Function
  // ============================================================================

  function initApp() {
    // DOM Elements
    const passwordInput = document.getElementById('passwordInput');
    const togglePasswordBtn = document.getElementById('togglePasswordBtn');
    const eyeOpenIcon = togglePasswordBtn ? togglePasswordBtn.querySelector('.eye-open-icon') : null;
    const eyeOffIcon = togglePasswordBtn ? togglePasswordBtn.querySelector('.eye-off-icon') : null;
    const clearBtn = document.getElementById('clearBtn');
    const checkStrengthBtn = document.getElementById('checkStrengthBtn');

    // Strength card elements
    const strengthCard = document.getElementById('strengthCard');
    const strengthText = document.getElementById('strengthText');
    const strengthScore = document.getElementById('strengthScore');
    const circleProgress = document.getElementById('circleProgress');
    const gaugeIcon = document.getElementById('gaugeIcon');
    const meterProgressFill = document.getElementById('meterProgressFill');
    const segmentedMeter = document.getElementById('segmentedMeter');
    const segments = segmentedMeter ? segmentedMeter.querySelectorAll('.meter-segment') : [];
    const statusMessageBanner = document.getElementById('statusMessageBanner');
    const statusMessageText = document.getElementById('statusMessageText');

    // Telemetry elements
    const entropyValue = document.getElementById('entropyValue');
    const crackTimeValue = document.getElementById('crackTimeValue');
    const charSetsValue = document.getElementById('charSetsValue');

    // Checklist elements
    const checklistCounter = document.getElementById('checklistCounter');
    const reqLength = document.getElementById('req-length');
    const reqUppercase = document.getElementById('req-uppercase');
    const reqLowercase = document.getElementById('req-lowercase');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');

    // Suggestions & advisory
    const suggestionsContainer = document.getElementById('suggestionsContainer');

    // Generator elements
    const generatedPasswordDisplay = document.getElementById('generatedPasswordDisplay');
    const copyGeneratedBtn = document.getElementById('copyGeneratedBtn');
    const copyBtnText = document.getElementById('copyBtnText');
    const useInAnalyzerBtn = document.getElementById('useInAnalyzerBtn');
    const generateBtn = document.getElementById('generateBtn');
    const lengthSlider = document.getElementById('lengthSlider');
    const lengthDisplay = document.getElementById('lengthDisplay');
    const genUppercase = document.getElementById('genUppercase');
    const genLowercase = document.getElementById('genLowercase');
    const genNumbers = document.getElementById('genNumbers');
    const genSymbols = document.getElementById('genSymbols');
    const genExcludeAmbiguous = document.getElementById('genExcludeAmbiguous');

    // Toast container
    const toastContainer = document.getElementById('toastContainer');

    if (!passwordInput) {
      console.error('Password Strength Analyzer: #passwordInput element not found.');
      return;
    }

    // ==========================================================================
    // Analysis Engine
    // ==========================================================================

    function evaluatePassword(pwd) {
      if (!pwd || pwd.length === 0) {
        return {
          empty: true,
          score: 0,
          level: 'Enter a Password',
          levelClass: 'empty',
          checklist: { length: false, uppercase: false, lowercase: false, number: false, special: false },
          entropy: '0.0',
          crackTime: 'Instant',
          characterSets: 0,
          length: 0,
          suggestions: [],
          message: 'Begin typing to evaluate your password security in real time.'
        };
      }

      // 1. Checklist Requirements Verification (Regex)
      const hasLength8 = pwd.length >= 8;
      const hasLength12 = pwd.length >= 12;
      const hasUppercase = REGEX.uppercase.test(pwd);
      const hasLowercase = REGEX.lowercase.test(pwd);
      const hasNumber = REGEX.number.test(pwd);
      const hasSpecial = REGEX.special.test(pwd);

      const checklist = {
        length: hasLength8,
        uppercase: hasUppercase,
        lowercase: hasLowercase,
        number: hasNumber,
        special: hasSpecial
      };

      // 2. Score Calculation
      // Real-time progressive length score so every keystroke animates the meter
      let lengthScore = 0;
      if (pwd.length < 8) {
        lengthScore = Math.floor(pwd.length * 2.5); // 1-7 chars: 2 to 17 pts
      } else if (pwd.length < 12) {
        lengthScore = 20; // Length >= 8: +20 points
      } else {
        lengthScore = 30; // Length >= 12: +10 additional points (Total 30)
      }

      let score = lengthScore;
      if (hasUppercase) score += 15;
      if (hasLowercase) score += 15;
      if (hasNumber) score += 15;
      if (hasSpecial) score += 20;

      // Character pool count
      let poolSize = 0;
      let charSetsCount = 0;
      if (hasLowercase) { poolSize += 26; charSetsCount++; }
      if (hasUppercase) { poolSize += 26; charSetsCount++; }
      if (hasNumber) { poolSize += 10; charSetsCount++; }
      if (hasSpecial) { poolSize += 33; charSetsCount++; }

      // Combination Bonus for high variety and length >= 16
      if (charSetsCount === 4 && pwd.length >= 16) {
        score += 5;
      }

      // 3. Pattern & Weakness Checks
      const warnings = [];
      const lowerPwd = pwd.toLowerCase();

      // Check 1: Exact common password match
      const isCommon = COMMON_PASSWORDS.has(lowerPwd);
      if (isCommon) {
        score = Math.min(score, 15);
        warnings.push({
          type: 'warning',
          text: 'Avoid common passwords. This password appears in well-known breach databases.'
        });
      } else {
        // Check 2: Substring containing common dictionary words
        const containsCommonWord = REGEX.commonWords.test(lowerPwd);
        if (containsCommonWord) {
          warnings.push({
            type: 'warning',
            text: 'Avoid common passwords and dictionary words such as "password", "admin", or "welcome".'
          });
        }

        // Check 3: Simple sequential sequences (12345, qwerty, etc.)
        let hasSequence = false;
        for (const seq of SEQUENTIAL_PATTERNS) {
          if (lowerPwd.includes(seq)) {
            hasSequence = true;
            break;
          }
        }
        if (/012|123|234|345|456|567|678|789|890/.test(pwd)) {
          hasSequence = true;
        }
        if (hasSequence) {
          warnings.push({
            type: 'warning',
            text: 'Avoid simple sequential numbers or keyboard patterns like "123" or "qwerty".'
          });
        }

        // Check 4: Repeated characters e.g. "aaaaaa" or "1111"
        const hasRepeated = REGEX.repeatedChars.test(pwd);
        if (hasRepeated) {
          warnings.push({
            type: 'warning',
            text: 'Avoid repeating identical characters consecutively (e.g. "aaaaa" or "1111").'
          });
        }

        // Deduct penalties (capped)
        let penalty = 0;
        if (containsCommonWord || hasSequence) {
          penalty += 10;
        }
        if (hasRepeated) {
          penalty += 10;
        }
        score -= penalty;
      }

      // Check 5: Birth year / recent year pattern
      if (REGEX.yearPattern.test(pwd)) {
        warnings.push({
          type: 'tip',
          text: 'Avoid using personal information such as birth years, phone digits, or recognizable dates.'
        });
      }

      // Clamp score between 5 and 100
      score = Math.max(5, Math.min(100, score));

      // 4. Entropy Calculation: E = L * log2(R)
      const entropy = poolSize > 0 ? (pwd.length * (Math.log(poolSize) / Math.LN2)) : 0;

      // 5. Estimated Crack Time Calculation (at 10^10 hashes/second)
      const crackTime = calculateCrackTime(entropy, poolSize, pwd.length, isCommon);

      // 6. Strength Level Mapping
      // 0–20%   → Very Weak
      // 21–40%  → Weak
      // 41–60%  → Medium
      // 61–85%  → Strong
      // 86–100% → Very Strong
      let level = '';
      let levelClass = '';
      let message = '';

      if (score <= 20) {
        level = 'Very Weak';
        levelClass = 'very-weak';
        message = 'Extremely vulnerable! This password could be compromised almost immediately.';
      } else if (score <= 40) {
        level = 'Weak';
        levelClass = 'weak';
        message = 'Weak password. It fails to meet multiple standard cybersecurity benchmarks.';
      } else if (score <= 60) {
        level = 'Medium';
        levelClass = 'medium';
        message = 'Moderate security. Adding length or missing character types will significantly strengthen it.';
      } else if (score <= 85) {
        level = 'Strong';
        levelClass = 'strong';
        message = 'Great! Your password is strong and secure.';
      } else {
        level = 'Very Strong';
        levelClass = 'very-strong';
        message = 'Great! Your password meets the recommended security requirements.';
      }

      // 7. Improvement Suggestions
      const suggestions = [...warnings];

      if (!hasLength8) {
        suggestions.push({
          type: 'warning',
          text: 'Password is too short. Use at least 8–12 characters.'
        });
      } else if (!hasLength12 && score < 85) {
        suggestions.push({
          type: 'tip',
          text: 'Expand length to 12+ characters for enhanced brute-force resistance.'
        });
      }

      if (!hasUppercase) {
        suggestions.push({
          type: 'tip',
          text: 'Add an uppercase letter.'
        });
      }

      if (!hasLowercase) {
        suggestions.push({
          type: 'tip',
          text: 'Add a lowercase letter.'
        });
      }

      if (!hasNumber) {
        suggestions.push({
          type: 'tip',
          text: 'Add a number.'
        });
      }

      if (!hasSpecial) {
        suggestions.push({
          type: 'tip',
          text: 'Add a special character.'
        });
      }

      if (suggestions.length === 0) {
        suggestions.push({
          type: 'success',
          text: 'Great! Your password meets the recommended security requirements.'
        });
      }

      return {
        empty: false,
        score,
        level,
        levelClass,
        checklist,
        entropy: entropy.toFixed(1),
        crackTime,
        characterSets: charSetsCount,
        length: pwd.length,
        suggestions,
        message
      };
    }

    function calculateCrackTime(entropy, poolSize, length, isCommon) {
      if (isCommon || length < 4 || poolSize <= 0) return 'Instant';

      // Combinations = poolSize^length
      const combinations = Math.pow(poolSize, length);
      const guessesPerSecond = 1e10; // 10 Billion guesses/sec
      const seconds = (combinations * 0.5) / guessesPerSecond;

      if (seconds < 0.01) return 'Instant';
      if (seconds < 1) return 'Less than 1 sec';
      if (seconds < 60) return `${Math.round(seconds)} seconds`;
      if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
      if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
      if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
      if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
      if (seconds < 315360000) return `${Math.round(seconds / 31536000)} years`;
      if (seconds < 31536000000) return `${Math.round(seconds / 31536000).toLocaleString()} years`;
      return 'Centuries';
    }

    // ==========================================================================
    // UI Update System
    // ==========================================================================

    function updateUI(analysis) {
      const activeColor = COLOR_PALETTE[analysis.levelClass] || COLOR_PALETTE.empty;

      if (analysis.empty) {
        // Reset indicators
        if (strengthText) {
          strengthText.textContent = 'Enter a Password';
          strengthText.className = 'strength-badge empty';
        }
        if (strengthScore) {
          strengthScore.textContent = '0%';
          strengthScore.className = 'strength-percentage';
        }
        if (circleProgress) {
          circleProgress.setAttribute('stroke-dasharray', '0, 100');
          circleProgress.setAttribute('stroke', COLOR_PALETTE.empty);
          circleProgress.style.stroke = COLOR_PALETTE.empty;
        }
        if (gaugeIcon) {
          gaugeIcon.style.color = 'var(--text-muted)';
        }

        // Reset Continuous Bar
        if (meterProgressFill) {
          meterProgressFill.style.width = '0%';
          meterProgressFill.style.backgroundColor = COLOR_PALETTE.empty;
          meterProgressFill.style.boxShadow = 'none';
        }

        // Reset Segments
        if (segments && segments.length) {
          segments.forEach(seg => {
            seg.style.backgroundColor = 'rgba(255, 255, 255, 0.06)';
            seg.style.boxShadow = 'none';
          });
        }

        // Reset Checklist
        updateChecklist({ length: false, uppercase: false, lowercase: false, number: false, special: false });

        // Reset Telemetry
        if (entropyValue) entropyValue.textContent = '0.0 bits';
        if (crackTimeValue) crackTimeValue.textContent = 'Instant';
        if (charSetsValue) charSetsValue.textContent = '0 chars • 0 sets';

        // Reset Banner
        if (statusMessageBanner) statusMessageBanner.className = 'status-message-banner empty';
        if (statusMessageText) statusMessageText.textContent = analysis.message;

        // Reset Suggestions
        renderSuggestions([
          {
            type: 'tip',
            text: 'Enter a password above or try one of the sample presets to run live analysis.'
          }
        ]);
        return;
      }

      // Update Strength Text & Percentage
      if (strengthText) {
        strengthText.textContent = analysis.level;
        strengthText.className = `strength-badge ${analysis.levelClass}`;
      }
      if (strengthScore) {
        strengthScore.textContent = `${analysis.score}%`;
        strengthScore.className = `strength-percentage ${analysis.levelClass}`;
      }

      // Update Continuous Glowing Progress Bar
      if (meterProgressFill) {
        meterProgressFill.style.width = `${analysis.score}%`;
        meterProgressFill.style.backgroundColor = activeColor;
        meterProgressFill.style.boxShadow = `0 0 14px ${activeColor}`;
      }

      // Update Circular Progress Gauge
      if (circleProgress) {
        circleProgress.setAttribute('stroke-dasharray', `${analysis.score}, 100`);
        circleProgress.setAttribute('stroke', activeColor);
        circleProgress.style.stroke = activeColor;
      }
      if (gaugeIcon) {
        gaugeIcon.style.color = activeColor;
      }

      // Update 5-Segment Meter
      const thresholds = [0, 20, 40, 60, 85];
      if (segments && segments.length) {
        segments.forEach((seg, idx) => {
          if (analysis.score > thresholds[idx]) {
            seg.style.backgroundColor = activeColor;
            seg.style.boxShadow = `0 0 10px ${activeColor}`;
          } else {
            seg.style.backgroundColor = 'rgba(255, 255, 255, 0.06)';
            seg.style.boxShadow = 'none';
          }
        });
      }

      // Update Message Banner
      if (statusMessageBanner) statusMessageBanner.className = `status-message-banner ${analysis.levelClass}`;
      if (statusMessageText) statusMessageText.textContent = analysis.message;

      // Update Checklist
      updateChecklist(analysis.checklist);

      // Update Telemetry
      if (entropyValue) entropyValue.textContent = `${analysis.entropy} bits`;
      if (crackTimeValue) crackTimeValue.textContent = analysis.crackTime;
      if (charSetsValue) charSetsValue.textContent = `${analysis.length} chars • ${analysis.characterSets} sets`;

      // Update Suggestions
      renderSuggestions(analysis.suggestions);
    }

    function updateChecklist(chk) {
      const items = [
        { el: reqLength, met: chk.length },
        { el: reqUppercase, met: chk.uppercase },
        { el: reqLowercase, met: chk.lowercase },
        { el: reqNumber, met: chk.number },
        { el: reqSpecial, met: chk.special }
      ];

      let metCount = 0;
      items.forEach(item => {
        if (item.el) {
          if (item.met) {
            item.el.classList.add('is-valid');
            metCount++;
          } else {
            item.el.classList.remove('is-valid');
          }
        }
      });

      if (checklistCounter) {
        checklistCounter.textContent = `${metCount} of 5 Met`;
        if (metCount === 5) {
          checklistCounter.classList.add('all-met');
        } else {
          checklistCounter.classList.remove('all-met');
        }
      }
    }

    function renderSuggestions(suggestions) {
      if (!suggestionsContainer) return;
      suggestionsContainer.innerHTML = '';

      suggestions.forEach(sug => {
        const item = document.createElement('div');
        item.className = `suggestion-item ${sug.type}`;

        let iconSvg = '';
        if (sug.type === 'warning') {
          iconSvg = `
            <svg class="suggestion-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          `;
        } else if (sug.type === 'success') {
          iconSvg = `
            <svg class="suggestion-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="m9 12 2 2 4-4"/>
            </svg>
          `;
        } else {
          iconSvg = `
            <svg class="suggestion-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
          `;
        }

        item.innerHTML = `
          ${iconSvg}
          <span>${sug.text}</span>
        `;
        suggestionsContainer.appendChild(item);
      });
    }

    function runAnalysis() {
      try {
        const pwd = passwordInput ? passwordInput.value : '';
        const analysis = evaluatePassword(pwd);
        updateUI(analysis);
      } catch (err) {
        console.error('Password Strength Analyzer Error:', err);
      }
    }

    // ==========================================================================
    // Password Generator
    // ==========================================================================

    function getSecureRandomInt(max) {
      if (max <= 0) return 0;
      if (window.crypto && window.crypto.getRandomValues) {
        const array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        return array[0] % max;
      }
      return Math.floor(Math.random() * max);
    }

    function generatePassword() {
      if (!lengthSlider || !generatedPasswordDisplay) return '';
      const length = parseInt(lengthSlider.value, 10);
      const useUpper = genUppercase ? genUppercase.checked : true;
      const useLower = genLowercase ? genLowercase.checked : true;
      const useNumbers = genNumbers ? genNumbers.checked : true;
      const useSymbols = genSymbols ? genSymbols.checked : true;
      const avoidAmbiguous = genExcludeAmbiguous ? genExcludeAmbiguous.checked : true;

      let pool = '';
      const guaranteedChars = [];

      const addSet = (chars) => {
        let cleanChars = chars;
        if (avoidAmbiguous) {
          cleanChars = chars.replace(AMBIGUOUS_CHARS, '');
        }
        if (cleanChars.length === 0) return;
        pool += cleanChars;
        const randIdx = getSecureRandomInt(cleanChars.length);
        guaranteedChars.push(cleanChars[randIdx]);
      };

      if (useUpper) addSet(CHAR_SETS.uppercase);
      if (useLower) addSet(CHAR_SETS.lowercase);
      if (useNumbers) addSet(CHAR_SETS.numbers);
      if (useSymbols) addSet(CHAR_SETS.symbols);

      if (pool.length === 0) {
        showToast('Please select at least one character set.');
        return '';
      }

      const passwordChars = [...guaranteedChars];
      const remainingCount = length - guaranteedChars.length;

      for (let i = 0; i < remainingCount; i++) {
        const randIdx = getSecureRandomInt(pool.length);
        passwordChars.push(pool[randIdx]);
      }

      // Shuffle using Fisher-Yates with CSPRNG
      for (let i = passwordChars.length - 1; i > 0; i--) {
        const j = getSecureRandomInt(i + 1);
        [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
      }

      const generated = passwordChars.join('');
      generatedPasswordDisplay.textContent = generated;
      return generated;
    }

    function showToast(message) {
      if (!toastContainer) return;
      const toast = document.createElement('div');
      toast.className = 'cyber-toast';
      toast.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        <span>${message}</span>
      `;
      toastContainer.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.25s ease';
        setTimeout(() => toast.remove(), 250);
      }, 2400);
    }

    // ==========================================================================
    // Event Listeners
    // ==========================================================================

    // Multiple input triggers for 100% responsiveness (typing, pasting, keyboard navigation)
    ['input', 'keyup', 'change', 'paste', 'cut'].forEach(evtType => {
      passwordInput.addEventListener(evtType, () => {
        runAnalysis();
        // Additional next-tick check for paste/cut operations
        setTimeout(runAnalysis, 15);
      });
    });

    // Enter key triggers active scan check
    passwordInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (checkStrengthBtn) checkStrengthBtn.click();
      }
    });

    // Show / Hide Password toggle
    if (togglePasswordBtn) {
      togglePasswordBtn.addEventListener('click', () => {
        const isPassword = passwordInput.getAttribute('type') === 'password';
        if (isPassword) {
          passwordInput.setAttribute('type', 'text');
          if (eyeOpenIcon) eyeOpenIcon.classList.add('is-hidden');
          if (eyeOffIcon) eyeOffIcon.classList.remove('is-hidden');
          togglePasswordBtn.setAttribute('aria-label', 'Hide password');
        } else {
          passwordInput.setAttribute('type', 'password');
          if (eyeOpenIcon) eyeOpenIcon.classList.remove('is-hidden');
          if (eyeOffIcon) eyeOffIcon.classList.add('is-hidden');
          togglePasswordBtn.setAttribute('aria-label', 'Show password');
        }
      });
    }

    // Clear input button
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        passwordInput.value = '';
        runAnalysis();
        passwordInput.focus();
        showToast('Password cleared.');
      });
    }

    // "Check Strength" button
    if (checkStrengthBtn) {
      checkStrengthBtn.addEventListener('click', () => {
        runAnalysis();
        if (strengthCard) {
          strengthCard.style.boxShadow = '0 0 32px rgba(99, 102, 241, 0.45)';
          setTimeout(() => {
            strengthCard.style.boxShadow = '';
          }, 450);
        }
        showToast('Password strength analysis updated.');
      });
    }

    // Quick Sample Pills
    document.querySelectorAll('.sample-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        const sample = btn.getAttribute('data-sample') || '';
        passwordInput.value = sample;
        runAnalysis();
        passwordInput.focus();
        showToast(`Loaded sample: "${sample}"`);
      });
    });

    // Password Generator slider
    if (lengthSlider && lengthDisplay) {
      lengthSlider.addEventListener('input', (e) => {
        lengthDisplay.textContent = e.target.value;
        generatePassword();
      });
    }

    // Password Generator checkboxes
    [genUppercase, genLowercase, genNumbers, genSymbols, genExcludeAmbiguous].forEach(cb => {
      if (cb) cb.addEventListener('change', generatePassword);
    });

    // Password Generator button
    if (generateBtn) {
      generateBtn.addEventListener('click', () => {
        generatePassword();
        showToast('New strong password generated.');
      });
    }

    // Copy Generated Password to clipboard
    if (copyGeneratedBtn && generatedPasswordDisplay) {
      copyGeneratedBtn.addEventListener('click', async () => {
        let text = generatedPasswordDisplay.textContent.trim();
        if (!text || text.includes('Click Generate')) {
          text = generatePassword();
        }

        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
          } else {
            const tempArea = document.createElement('textarea');
            tempArea.value = text;
            document.body.appendChild(tempArea);
            tempArea.select();
            document.execCommand('copy');
            tempArea.remove();
          }
          if (copyBtnText) copyBtnText.textContent = 'Copied!';
          showToast('Generated password copied to clipboard!');
          setTimeout(() => {
            if (copyBtnText) copyBtnText.textContent = 'Copy';
          }, 2000);
        } catch (err) {
          showToast('Failed to copy. Please copy manually.');
        }
      });
    }

    // Use in Analyzer button
    if (useInAnalyzerBtn && generatedPasswordDisplay) {
      useInAnalyzerBtn.addEventListener('click', () => {
        let text = generatedPasswordDisplay.textContent.trim();
        if (!text || text.includes('Click Generate')) {
          text = generatePassword();
        }
        passwordInput.value = text;
        runAnalysis();
        passwordInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        passwordInput.focus();
        showToast('Password transferred to analyzer!');
      });
    }

    // Check URL parameters for preset testing e.g. ?pwd=MyPassword@123
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const urlPwd = urlParams.get('pwd') || urlParams.get('test');
      if (urlPwd) {
        passwordInput.value = urlPwd;
      }
    } catch (e) {}

    // Run initial state
    runAnalysis();
    generatePassword();
  }

  // Ensure DOM is ready before executing
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
})();
