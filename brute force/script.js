/*
 * script.js
 * ---------
 * Pure client-side, local-only logic for the Password Security Console.
 *
 * This file does NOT guess, brute-force, or transmit any password anywhere.
 * It only:
 *   1) Reads a password typed into the local input field,
 *   2) Runs simple, well-known pattern checks against that password,
 *   3) Displays a static, pre-computed table of generic guess-rate
 *      scenarios describing the size of the whole 10,000-value space.
 */

const TOTAL_COMBINATIONS = 10000;

const MODE_CONFIG = {
  custom: {
    label: 'Custom password',
    inputLabel: 'Password',
    placeholder: 'Type or paste a password',
    helpText: 'Use any mix of letters, numbers, symbols, spaces, or Unicode characters.',
    analyzeLabel: 'ANALYZE PASSWORD',
    lcdLabel: 'ENTER PASSWORD',
  },
  pin4: {
    label: '4-digit checker',
    inputLabel: '4-digit code',
    placeholder: 'Enter 4 digits',
    helpText: 'Numeric digits only. Great for quick 4-digit PIN-style checks.',
    analyzeLabel: 'ANALYZE 4-DIGIT',
    lcdLabel: 'ENTER 4 DIGITS',
    exactLength: 4,
    numericOnly: true,
  },
  pin6: {
    label: '6-digit checker',
    inputLabel: '6-digit code',
    placeholder: 'Enter 6 digits',
    helpText: 'Numeric digits only. Great for 6-digit PIN-style checks.',
    analyzeLabel: 'ANALYZE 6-DIGIT',
    lcdLabel: 'ENTER 6 DIGITS',
    exactLength: 6,
    numericOnly: true,
  },
  pin8: {
    label: '8-digit checker',
    inputLabel: '8-digit code',
    placeholder: 'Enter 8 digits',
    helpText: 'Numeric digits only. Great for 8-digit PIN-style checks.',
    analyzeLabel: 'ANALYZE 8-DIGIT',
    lcdLabel: 'ENTER 8 DIGITS',
    exactLength: 8,
    numericOnly: true,
  },
};

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'passw0rd', 'admin', 'welcome',
  'letmein', 'qwerty', 'monkey', 'dragon', 'iloveyou',
  'abc123', '111111', '123456', '1234567', '12345678',
  '123456789', '123123', '123password', 'password123', '000000', 'sunshine', 'football',
]);

const COMMON_PINS = new Set([
  '0000', '1111', '1234', '1212', '4321', '2580',
  '1122', '1357', '2468', '246810', '654321', '987654',
  '111111', '123456', '222222', '6543210', '12345678', '87654321',
]);

const KEYBOARD_ROWS = [
  '1234567890',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
];

const GUESS_RATE_SCENARIOS = [
  { name: 'Manual entry (device lockout, ~1 try/30s)', ratePerSecond: 1 / 30 },
  { name: 'Unthrottled online attempt (~1 try/sec)', ratePerSecond: 1 },
  { name: 'Fast automated attempt (~10 tries/sec)', ratePerSecond: 10 },
  { name: 'Offline high-speed attempt (~1,000,000 tries/sec)', ratePerSecond: 1000000 },
];

// ---------------------------------------------------------------------
// Pattern detection helpers
// ---------------------------------------------------------------------

function toCharacters(value) {
  return Array.from(value);
}

function normalizeForComparison(value) {
  const replacements = {
    '@': 'a',
    '4': 'a',
    '3': 'e',
    '1': 'l',
    '!': 'i',
    '0': 'o',
    '$': 's',
    '5': 's',
    '7': 't',
    '8': 'b',
    '9': 'g',
  };

  return toCharacters(value.toLowerCase())
    .map((character) => replacements[character] ?? character)
    .filter((character) => /[a-z0-9]/.test(character))
    .join('');
}

function hasSingleRepeatedCharacter(value) {
  return new Set(toCharacters(value)).size === 1;
}

function isSequentialAscending(value) {
  const characters = toCharacters(value.toLowerCase());
  if (characters.length < 4) return false;

  return characters.every((character, index) => {
    if (index === 0) return true;
    return characters[index - 1].charCodeAt(0) + 1 === character.charCodeAt(0);
  });
}

function isSequentialDescending(value) {
  const characters = toCharacters(value.toLowerCase());
  if (characters.length < 4) return false;

  return characters.every((character, index) => {
    if (index === 0) return true;
    return characters[index - 1].charCodeAt(0) - 1 === character.charCodeAt(0);
  });
}

function hasRepeatedPattern(value) {
  const characters = toCharacters(value);
  if (characters.length < 4) return false;

  for (let patternLength = 1; patternLength <= Math.floor(characters.length / 2); patternLength += 1) {
    if (characters.length % patternLength !== 0) continue;

    let matches = true;
    for (let index = patternLength; index < characters.length; index += 1) {
      if (characters[index] !== characters[index % patternLength]) {
        matches = false;
        break;
      }
    }

    if (matches) return true;
  }

  return false;
}

function hasLongRepeatingRun(value) {
  const characters = toCharacters(value);
  let runLength = 1;

  for (let index = 1; index < characters.length; index += 1) {
    if (characters[index] === characters[index - 1]) {
      runLength += 1;
      if (runLength >= 3) return true;
    } else {
      runLength = 1;
    }
  }

  return false;
}

function hasKeyboardPattern(value) {
  const normalized = value.toLowerCase();

  return KEYBOARD_ROWS.some((row) => {
    const reversedRow = row.split('').reverse().join('');
    for (let windowSize = 4; windowSize <= normalized.length; windowSize += 1) {
      for (let startIndex = 0; startIndex <= normalized.length - windowSize; startIndex += 1) {
        const fragment = normalized.slice(startIndex, startIndex + windowSize);
        if (row.includes(fragment) || reversedRow.includes(fragment)) {
          return true;
        }
      }
    }
    return false;
  });
}

function isAsciiAlphanumericSequence(value) {
  return /^[a-z0-9]+$/i.test(value);
}

function hasSequentialCharacters(value) {
  const normalized = value.toLowerCase();
  if (!isAsciiAlphanumericSequence(normalized) || normalized.length < 4) return false;

  const characters = toCharacters(normalized);
  let ascending = true;
  let descending = true;

  for (let index = 1; index < characters.length; index += 1) {
    const previousCode = characters[index - 1].charCodeAt(0);
    const currentCode = characters[index].charCodeAt(0);
    if (previousCode + 1 !== currentCode) ascending = false;
    if (previousCode - 1 !== currentCode) descending = false;
  }

  return ascending || descending;
}

function detectWeaknesses(password) {
  const weaknesses = [];
  const comparisonValue = normalizeForComparison(password);

  if ([...COMMON_PASSWORDS].some((commonPassword) => comparisonValue.includes(commonPassword))) {
    weaknesses.push('This is one of the most commonly used passwords.');
  }
  if (hasSingleRepeatedCharacter(password)) {
    weaknesses.push('The password repeats a single character.');
  }
  if (hasRepeatedPattern(password)) {
    weaknesses.push('The password repeats the same pattern multiple times.');
  }
  if (hasSequentialCharacters(password)) {
    weaknesses.push('Characters form a straight ascending or descending sequence.');
  }
  if (hasKeyboardPattern(password)) {
    weaknesses.push('The password contains a keyboard-row pattern such as qwerty or 1234.');
  }
  if (hasLongRepeatingRun(password)) {
    weaknesses.push('The password has repeated characters in a row.');
  }
  if (/(?:19|20)\d{2}/.test(password)) {
    weaknesses.push('The password includes a year-like sequence.');
  }

  return weaknesses;
}

function detectDigitWeaknesses(value) {
  const weaknesses = [];

  if (COMMON_PINS.has(value)) {
    weaknesses.push('This is a commonly chosen PIN-style code.');
  }
  if (hasSingleRepeatedCharacter(value)) {
    weaknesses.push('All digits are identical.');
  }
  if (hasRepeatedPattern(value)) {
    weaknesses.push('The digits repeat the same pattern.');
  }
  if (isSequentialAscending(value)) {
    weaknesses.push('The digits form an ascending sequence.');
  }
  if (isSequentialDescending(value)) {
    weaknesses.push('The digits form a descending sequence.');
  }
  if (hasLongRepeatingRun(value)) {
    weaknesses.push('The digits include repeated runs.');
  }

  return weaknesses;
}

function getCharacterClasses(password) {
  return {
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    digit: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9\s]/.test(password),
    space: /\s/.test(password),
    unicode: /[^\x00-\x7F]/.test(password),
  };
}

function countActiveClasses(classes) {
  return Object.values(classes).filter(Boolean).length;
}

function getModeConfig(mode) {
  return MODE_CONFIG[mode] || MODE_CONFIG.custom;
}

function isDigitMode(mode) {
  const config = getModeConfig(mode);
  return Boolean(config.numericOnly);
}

function scorePassword(password, weaknesses) {
  let score = 0;

  const characters = toCharacters(password);
  const uniqueCharacters = new Set(characters).size;
  const classes = getCharacterClasses(password);
  const classCount = countActiveClasses(classes);
  const length = characters.length;

  score += Math.min(length * 4, 40);
  score += Math.min(uniqueCharacters * 1.5, 15);
  score += Math.min(classCount * 10, 30);

  if (length >= 16) score += 10;
  else if (length >= 12) score += 5;

  if (length < 8) score -= 20;
  else if (length < 12) score -= 10;

  if (classCount < 2) score -= 10;

  weaknesses.forEach((weakness) => {
    if (weakness.includes('commonly used')) score -= 45;
    else if (weakness.includes('repeats a single character')) score -= 24;
    else if (weakness.includes('repeats the same pattern')) score -= 18;
    else if (weakness.includes('straight ascending or descending')) score -= 18;
    else if (weakness.includes('keyboard-row pattern')) score -= 18;
    else if (weakness.includes('repeated characters in a row')) score -= 10;
    else if (weakness.includes('year-like')) score -= 8;
  });

  return Math.max(0, Math.min(100, Math.round(score)));
}

function scoreDigits(value, weaknesses, exactLength) {
  let score = 0;
  const length = value.length;
  const uniqueDigits = new Set(toCharacters(value)).size;

  score += exactLength * 8;
  score += uniqueDigits * 6;

  if (length === exactLength) score += 20;
  if (length < exactLength) score -= 20;

  weaknesses.forEach((weakness) => {
    if (weakness.includes('commonly chosen')) score -= 40;
    else if (weakness.includes('identical')) score -= 25;
    else if (weakness.includes('repeat the same pattern')) score -= 20;
    else if (weakness.includes('ascending')) score -= 18;
    else if (weakness.includes('descending')) score -= 18;
    else if (weakness.includes('repeated runs')) score -= 10;
  });

  return Math.max(0, Math.min(100, Math.round(score)));
}

function labelForScore(score) {
  if (score >= 85) return 'Strong';
  if (score >= 65) return 'Moderate';
  if (score >= 40) return 'Weak';
  return 'Very Weak';
}

function recommendationFor(label) {
  const map = {
    Strong: 'Good choice. Keep it unique and enable multi-factor authentication (MFA) wherever possible.',
    Moderate: 'This password is usable but not ideal. Make it longer or more unique, and enable MFA.',
    Weak: 'This password is easy to predict. Use a longer phrase with more variety.',
    'Very Weak': 'This password is highly guessable. Change it immediately and enable MFA.',
  };
  return map[label] || 'Enable multi-factor authentication (MFA).';
}

function analyzePassword(password, mode) {
  const config = getModeConfig(mode);

  if (password.length === 0) {
    return { isValid: false, error: 'Enter a password.' };
  }

  if (config.numericOnly && !/^\d+$/.test(password)) {
    return { isValid: false, error: `Enter only digits for the ${config.exactLength}-digit checker.` };
  }

  if (config.exactLength && password.length !== config.exactLength) {
    return { isValid: false, error: `Enter exactly ${config.exactLength} digits.` };
  }

  if (!config.numericOnly && password.length > 0 && password.length < 1) {
    return { isValid: false, error: 'Enter a password.' };
  }

  const weaknesses = config.numericOnly ? detectDigitWeaknesses(password) : detectWeaknesses(password);
  const score = config.numericOnly ? scoreDigits(password, weaknesses, config.exactLength) : scorePassword(password, weaknesses);
  const label = labelForScore(score);
  const recommendation = recommendationFor(label);
  const classes = getCharacterClasses(password);
  const activeClassCount = countActiveClasses(classes);
  const alphabetSize = config.numericOnly ? 10 : ([
    classes.lowercase ? 26 : 0,
    classes.uppercase ? 26 : 0,
    classes.digit ? 10 : 0,
    classes.symbol ? 33 : 0,
    classes.space ? 1 : 0,
    classes.unicode ? 100 : 0,
  ].reduce((total, size) => total + size, 0) || 1);
  const entropyBits = password.length * Math.log2(alphabetSize);
  const searchSpacePercent = Math.max(0, Math.min(100, (entropyBits / 80) * 100));

  return {
    isValid: true,
    password,
    score,
    label,
    recommendation,
    weaknesses,
    entropyBits,
    activeClassCount,
    alphabetSize,
    searchSpacePercent,
  };
}

function formatSearchSpaceEstimate(password, alphabetSize) {
  if (password.length === 0) {
    return 'Add a password to estimate';
  }

  const estimatedCombinations = alphabetSize ** password.length;
  if (Number.isFinite(estimatedCombinations) && estimatedCombinations < 1e12) {
    return `~${estimatedCombinations.toLocaleString()} combinations`;
  }

  const entropyBits = password.length * Math.log2(alphabetSize);
  return `~2^${entropyBits.toFixed(1)} combinations`;
}

function formatSeconds(seconds) {
  if (seconds < 1) return '< 1 second';
  const units = [
    ['year', 60 * 60 * 24 * 365],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
    ['second', 1],
  ];
  for (const [name, unitSeconds] of units) {
    if (seconds >= unitSeconds) {
      const value = seconds / unitSeconds;
      const formatted = value.toLocaleString(undefined, { maximumFractionDigits: 1 });
      return `${formatted} ${name}${value !== 1 ? 's' : ''}`;
    }
  }
  return '< 1 second';
}

function getTimeEstimates() {
  return GUESS_RATE_SCENARIOS.map(({ name, ratePerSecond }) => ({
    scenario: name,
    ratePerSecond,
    secondsToExhaustSpace: TOTAL_COMBINATIONS / ratePerSecond,
  }));
}

// ---------------------------------------------------------------------
// UI wiring
// ---------------------------------------------------------------------

const state = { password: '', visible: false, mode: 'custom' };

const lcdStatus = document.getElementById('lcdStatus');
const visibilityToggle = document.getElementById('visibilityToggle');
const modeSelect = document.getElementById('modeSelect');
const passwordInput = document.getElementById('passwordInput');
const passwordPreview = document.getElementById('passwordPreview');
const analyzeBtn = document.getElementById('analyzeBtn');
const analyzeBtnText = document.getElementById('analyzeBtnText');

const strengthValue = document.getElementById('strengthValue');
const scoreCaption = document.getElementById('scoreCaption');
const ledMeter = document.getElementById('ledMeter');
const totalValue = document.getElementById('totalValue');
const spaceFill = document.getElementById('spaceFill');
const spaceMarker = document.getElementById('spaceMarker');
const spaceCaption = document.getElementById('spaceCaption');
const patternLog = document.getElementById('patternLog');
const recommendationText = document.getElementById('recommendationText');
const passwordFieldLabel = document.querySelector('.password-field-label');
const passwordHelp = document.getElementById('passwordHelp');

function applyModeUi() {
  const config = getModeConfig(state.mode);
  lcdStatus.textContent = config.lcdLabel;
  passwordFieldLabel.textContent = config.inputLabel;
  passwordInput.placeholder = config.placeholder;
  passwordHelp.textContent = config.helpText;
  analyzeBtnText.textContent = config.analyzeLabel;
  passwordInput.inputMode = config.numericOnly ? 'numeric' : 'text';
  passwordInput.maxLength = config.exactLength || 128;
  if (config.numericOnly) {
    passwordInput.pattern = '\\d*';
  } else {
    passwordInput.removeAttribute('pattern');
  }
}

modeSelect.addEventListener('change', () => {
  state.mode = modeSelect.value;
  updatePasswordFromInput();
  applyModeUi();
});

function renderPasswordPreview() {
  const characters = toCharacters(state.password);
  if (characters.length === 0) {
    passwordPreview.textContent = '';
    lcdStatus.textContent = getModeConfig(state.mode).lcdLabel;
    lcdStatus.className = 'lcd-status';
    return;
  }

  if (state.visible) {
    passwordPreview.textContent = state.password;
  } else {
    const maskedPreview = '•'.repeat(Math.min(characters.length, 24));
    passwordPreview.textContent = characters.length > 24 ? `${maskedPreview}…` : maskedPreview;
  }

  lcdStatus.textContent = `READY TO ANALYZE ${isDigitMode(state.mode) ? `${getModeConfig(state.mode).exactLength}-DIGIT` : 'PASSWORD'}`;
  lcdStatus.className = 'lcd-status';
}

function updatePasswordFromInput() {
  const config = getModeConfig(state.mode);
  const value = config.numericOnly ? passwordInput.value.replace(/\D/g, '') : passwordInput.value;
  state.password = config.exactLength ? value.slice(0, config.exactLength) : value;
  if (passwordInput.value !== state.password) {
    passwordInput.value = state.password;
  }
  renderPasswordPreview();
}

passwordInput.addEventListener('input', () => {
  updatePasswordFromInput();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    passwordInput.value = '';
    updatePasswordFromInput();
  } else if (e.key === 'Enter' && document.activeElement !== analyzeBtn) {
    runAnalysis();
  }
});

visibilityToggle.addEventListener('click', () => {
  state.visible = !state.visible;
  visibilityToggle.setAttribute('aria-pressed', String(state.visible));
  visibilityToggle.textContent = state.visible ? 'HIDE' : 'SHOW';
  passwordInput.type = state.visible ? 'text' : 'password';
  renderPasswordPreview();
});

function ledClassForLabel(label) {
  if (label === 'Strong') return 'on-safe';
  if (label === 'Moderate') return 'on-warn';
  return 'on-danger';
}

function updateLedMeter(score, label) {
  const leds = Array.from(ledMeter.querySelectorAll('.led'));
  const litCount = Math.round((score / 100) * leds.length);
  const cls = ledClassForLabel(label);
  leds.forEach((led, i) => {
    led.className = 'led' + (i < litCount ? ' ' + cls : '');
  });
}

function renderPatternLog(weaknesses) {
  patternLog.innerHTML = '';
  if (weaknesses.length === 0) {
    const li = document.createElement('li');
    li.className = 'log-line log-ok';
    li.textContent = '> no common weak patterns detected';
    patternLog.appendChild(li);
    return;
  }
  weaknesses.forEach((w) => {
    const li = document.createElement('li');
    li.className = 'log-line log-warn';
    li.textContent = `> ${w}`;
    patternLog.appendChild(li);
  });
}

function runAnalysis() {
  const result = analyzePassword(state.password, state.mode);

  if (!result.isValid) {
    lcdStatus.textContent = result.error.toUpperCase();
    lcdStatus.className = 'lcd-status state-veryweak';
    strengthValue.textContent = '—';
    scoreCaption.textContent = 'Score: — / 100';
    totalValue.textContent = 'Password search estimate';
    spaceFill.style.width = '0%';
    spaceMarker.style.left = '0%';
    spaceCaption.textContent = 'Estimated position within a password space: —';
    renderPatternLog([]);
    recommendationText.textContent = getModeConfig(state.mode).numericOnly
      ? `Enter exactly ${getModeConfig(state.mode).exactLength} digits and press ANALYZE.`
      : 'Enter a password and press ANALYZE.';
    return;
  }

  strengthValue.textContent = `${result.label} — ${result.score}/100`;
  scoreCaption.textContent = `Score: ${result.score} / 100`;
  updateLedMeter(result.score, result.label);

  totalValue.textContent = `Estimated search space: ${formatSearchSpaceEstimate(result.password, result.alphabetSize)}`;
  spaceFill.style.width = `${result.searchSpacePercent}%`;
  spaceMarker.style.left = `${result.searchSpacePercent}%`;
  spaceCaption.textContent = `Estimated position within a ${getModeConfig(state.mode).numericOnly ? `${getModeConfig(state.mode).exactLength}-digit space` : 'password space'}: ${result.entropyBits.toFixed(1)} bits`;

  renderPatternLog(result.weaknesses);
  recommendationText.textContent = result.recommendation;

  lcdStatus.textContent = result.label.toUpperCase();
  lcdStatus.className = 'lcd-status state-' + result.label.toLowerCase().replace(' ', '');
}

analyzeBtn.addEventListener('click', runAnalysis);

// ---------------------------------------------------------------------
// Populate the static, educational time-estimate table on load
// ---------------------------------------------------------------------

function renderEstimatesTable() {
  const tbody = document.getElementById('estimatesBody');
  getTimeEstimates().forEach(({ scenario, ratePerSecond, secondsToExhaustSpace }) => {
    const tr = document.createElement('tr');

    const tdScenario = document.createElement('td');
    tdScenario.textContent = scenario;

    const tdRate = document.createElement('td');
    const rateDisplay = ratePerSecond >= 1
      ? `${ratePerSecond.toLocaleString()}/s`
      : `${ratePerSecond.toFixed(3)}/s`;
      tdRate.textContent = rateDisplay;

    const tdTime = document.createElement('td');
    tdTime.textContent = formatSeconds(secondsToExhaustSpace);

    tr.append(tdScenario, tdRate, tdTime);
    tbody.appendChild(tr);
  });
}

applyModeUi();
updatePasswordFromInput();
renderEstimatesTable();
