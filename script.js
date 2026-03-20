// ===== Smooth Scroll Function =====
function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
    }
}

// ===== Common Dictionary Words =====
const commonDictionary = [
    'password', 'pass', 'word', 'admin', 'user', 'login', 'welcome', 'hello',
    'sunshine', 'princess', 'qwerty', 'monkey', 'dragon', 'master', 'batman',
    'football', 'letmein', 'trustno1', 'shadow', 'ashley', 'michael', 'person',
    'computer', 'internet', 'software', 'database', 'network', 'system', 'server',
    'client', 'data', 'code', 'program', 'test', 'demo', 'temp', 'backup',
    'security', 'cipher', 'encrypt', 'decrypt', 'username', 'account', 'profile',
    'email', 'mail', 'phone', 'contact', 'address', 'street', 'city', 'state'
];

// ===== Characteristic Extraction Phase (CE) =====
function extractCharacteristics(password) {
    // Create OG and Normalized versions
    const ogPassword = password;
    const normalized = normalizePassword(password);

    // Initialize feature vector object
    const features = {
        length: 0,
        has_lowercase: 0,
        has_uppercase: 0,
        has_digit: 0,
        has_symbol: 0,
        character_class_count: 0,
        dictionary_present: 0,
        has_leetspeak: 0,
        common_capitalization: 0,
        numeric_suffix: 0,
        symbol_affix: 0,
        has_sequence: 0,
        has_repetition: 0,
        rule_pattern_present: 0
    };

    // 1. Length extraction
    features.length = ogPassword.length;

    // 2. Character type scanning (single pass)
    let charClassCount = 0;
    const hasLower = /[a-z]/.test(ogPassword);
    const hasUpper = /[A-Z]/.test(ogPassword);
    const hasDigit = /\d/.test(ogPassword);
    const hasSymbol = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(ogPassword);

    if (hasLower) { features.has_lowercase = 1; charClassCount++; }
    if (hasUpper) { features.has_uppercase = 1; charClassCount++; }
    if (hasDigit) { features.has_digit = 1; charClassCount++; }
    if (hasSymbol) { features.has_symbol = 1; charClassCount++; }

    features.character_class_count = charClassCount;

    // 3. Detect sequential patterns (abc, 123)
    if (detectSequence(ogPassword)) {
        features.has_sequence = 1;
    }

    // 4. Detect repeated characters
    if (detectRepetition(ogPassword)) {
        features.has_repetition = 1;
    }

    // 5. Detect leetspeak substitutions
    if (detectLeetspeak(ogPassword)) {
        features.has_leetspeak = 1;
    }

    // 6. Detect capitalization pattern
    if (detectCapitalization(ogPassword)) {
        features.common_capitalization = 1;
    }

    // 7. Detect numeric suffix
    if (detectNumericSuffix(ogPassword)) {
        features.numeric_suffix = 1;
    }

    // 8. Detect symbol prefix or suffix
    if (detectSymbolAffix(ogPassword)) {
        features.symbol_affix = 1;
    }

    // 9. Dictionary detection (using normalized version)
    if (detectDictionary(normalized)) {
        features.dictionary_present = 1;
    }

    // 10. Aggregate rule-based pattern flag
    if (features.has_leetspeak || features.common_capitalization || 
        features.numeric_suffix || features.symbol_affix || 
        features.has_sequence || features.has_repetition) {
        features.rule_pattern_present = 1;
    }

    return features;
}

// ===== Normalization Helper =====
function normalizePassword(password) {
    let normalized = password.toLowerCase();
    // Replace common leetspeak substitutions
    normalized = normalized.replace(/@/g, 'a');
    normalized = normalized.replace(/0/g, 'o');
    normalized = normalized.replace(/1/g, 'i');
    normalized = normalized.replace(/3/g, 'e');
    normalized = normalized.replace(/\$/g, 's');
    normalized = normalized.replace(/5/g, 's');
    normalized = normalized.replace(/7/g, 't');
    return normalized;
}

// ===== Pattern Detection Functions =====
function detectSequence(password) {
    const sequences = ['abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
        '012', '123', '234', '345', '456', '567', '678', '789'];
    const lower = password.toLowerCase();
    for (let seq of sequences) {
        if (lower.includes(seq)) return true;
    }
    return false;
}

function detectRepetition(password) {
    return /(.)\1{2,}/.test(password);
}

function detectLeetspeak(password) {
    return /[@0135$7]/.test(password);
}

function detectCapitalization(password) {
    // Check if capital at start and rest mixed case
    if (/^[A-Z]/.test(password) && /[a-z].*[A-Z]|[A-Z].*[a-z]/.test(password.slice(1))) {
        return true;
    }
    // Check for alternating caps pattern
    return /[A-Z][a-z][A-Z].*[a-z]|[a-z][A-Z][a-z].*[A-Z]/.test(password);
}

function detectNumericSuffix(password) {
    return /\d+$/.test(password);
}

function detectSymbolAffix(password) {
    return /^[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]|[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]$/.test(password);
}

function detectDictionary(normalized) {
    // Check if any dictionary word exists in normalized password
    for (let word of commonDictionary) {
        if (normalized.includes(word)) {
            return true;
        }
    }
    // Check for 4+ character substrings that might be words
    const substr = normalized.match(/[a-z]{4,}/g);
    if (substr) {
        for (let s of substr) {
            if (commonDictionary.includes(s)) {
                return true;
            }
        }
    }
    return false;
}

// ===== Tree-Based Classification (TBC) Phase =====
function classifyVulnerability(features) {
    // Decision Tree Logic
    // Node 1: Dictionary present?
    if (features.dictionary_present === 1) {
        // If dictionary word found, check for rule-based patterns
        if (features.has_leetspeak || features.common_capitalization || 
            features.numeric_suffix || features.symbol_affix) {
            return 'RULE-BASED';
        } else {
            return 'DICTIONARY';
        }
    } else {
        // No dictionary word found
        // Node 2: Character class count < 3?
        if (features.character_class_count < 3) {
            return 'BRUTE-FORCE';
        } else {
            // Node 3: Sequence present?
            if (features.has_sequence === 1) {
                return 'RULE-BASED';
            } else {
                return 'BRUTE-FORCE';
            }
        }
    }
}

// ===== Password Strength Checker (Enhanced) =====
function checkPassword() {
    const password = document.getElementById('passwordInput').value;
    const strengthBar = document.getElementById('strengthBar');
    const strengthResult = document.getElementById('strengthResult');
    const criteriaList = document.getElementById('criteriaList');
    const vulnerabilityResult = document.getElementById('vulnerabilityResult');
    const featureVector = document.getElementById('featureVector');

    if (password.length === 0) {
        if (strengthBar) strengthBar.style.width = '0%';
        if (strengthResult) strengthResult.innerHTML = '';
        if (criteriaList) criteriaList.innerHTML = '';
        if (vulnerabilityResult) vulnerabilityResult.style.display = 'none';
        if (featureVector) featureVector.style.display = 'none';

        return;
    }

    // PHASE 1: CHARACTERISTICS EXTRACTION (CE)
    const features = extractCharacteristics(password);

    // PHASE 2: TREE-BASED CLASSIFICATION (TBC)
    const vulnerability = classifyVulnerability(features);

    // Calculate password strength score
    let strength = 0;
    const criteria = [];

    // Length check
    if (password.length >= 8) {
        strength += 20;
        criteria.push({ met: true, text: 'At least 8 characters' });
    } else {
        criteria.push({ met: false, text: 'At least 8 characters' });
    }

    if (password.length >= 12) {
        strength += 10;
        criteria.push({ met: true, text: 'At least 12 characters' });
    } else {
        criteria.push({ met: false, text: 'At least 12 characters' });
    }

    // Character diversity
    if (features.has_lowercase) {
        strength += 20;
        criteria.push({ met: true, text: 'Contains lowercase letters (a-z)' });
    } else {
        criteria.push({ met: false, text: 'Contains lowercase letters (a-z)' });
    }

    if (features.has_uppercase) {
        strength += 20;
        criteria.push({ met: true, text: 'Contains uppercase letters (A-Z)' });
    } else {
        criteria.push({ met: false, text: 'Contains uppercase letters (A-Z)' });
    }

    if (features.has_digit) {
        strength += 15;
        criteria.push({ met: true, text: 'Contains numbers (0-9)' });
    } else {
        criteria.push({ met: false, text: 'Contains numbers (0-9)' });
    }

    if (features.has_symbol) {
        strength += 15;
        criteria.push({ met: true, text: 'Contains special characters' });
    } else {
        criteria.push({ met: false, text: 'Contains special characters' });
    }

    // Pattern checks
    if (!features.has_sequence) {
        strength += 5;
        criteria.push({ met: true, text: 'No sequential patterns' });
    } else {
        criteria.push({ met: false, text: 'No sequential patterns' });
    }

    if (!features.has_repetition) {
        strength += 5;
        criteria.push({ met: true, text: 'No repeated characters' });
    } else {
        criteria.push({ met: false, text: 'No repeated characters' });
    }

    if (!features.dictionary_present) {
        strength += 10;
        criteria.push({ met: true, text: 'No dictionary words' });
    } else {
        criteria.push({ met: false, text: 'No dictionary words' });
    }

    // Update strength bar (if present)
    if (strengthBar) strengthBar.style.width = strength + '%';

    // Determine strength level
    let level = 'Very Weak';
    let color = '#e74c3c';
    
    if (strength >= 90) {
        level = '🔒 Very Strong';
        color = '#2ecc71';
    } else if (strength >= 70) {
        level = '✓ Strong';
        color = '#2ecc71';
    } else if (strength >= 50) {
        level = '⚡ Moderate';
        color = '#f39c12';
    } else if (strength >= 30) {
        level = '⚠️ Weak';
        color = '#e67e22';
    }

    strengthResult.innerHTML = '';
    strengthResult.style.display = 'none';

    // Update criteria list
    let criteriaHTML = '';
    criteria.forEach(criterion => {
        const className = criterion.met ? 'met' : '';
        criteriaHTML += `<li class="${className}">${criterion.text}</li>`;
    });
    criteriaList.innerHTML = `
        <h4>Password Criteria:</h4>
        <ul>${criteriaHTML}</ul>
    `;

    // Display Vulnerability Classification
    displayVulnerabilityResult(vulnerability);

    // Display Feature Vector
    displayFeatureVector(features);

    displayRecommendations(vulnerability, features);
}

// ===== Display Vulnerability Result =====
function displayVulnerabilityResult(vulnerability) {
    const vulnResult = document.getElementById('vulnerabilityResult');
    const vulnType = document.getElementById('vulnerabilityType');
    const vulnExplain = document.getElementById('vulnerabilityExplain');

    vulnResult.style.display = 'block';

    let typeClass = vulnerability.toLowerCase().replace(/ /g, '-');
    let icon = '';
    let explanation = '';

    if (vulnerability === 'RULE-BASED') {
        icon = '🔴';
        explanation = 'Password is vulnerable to rule-based dictionary attacks. It contains dictionary words combined with predictable transformations like leetspeak, capitalization patterns, or numeric suffixes.';
    } else if (vulnerability === 'DICTIONARY') {
        icon = '🟠';
        explanation = 'Password is vulnerable to dictionary attacks. It contains common words that exist in password dictionaries, making it susceptible to direct dictionary lookup attacks.';
    } else if (vulnerability === 'BRUTE-FORCE') {
        icon = '🟢';
        explanation = 'Password is resistant to common attacks. It has no predictable patterns or dictionary words, requiring attackers to use brute-force methods (character-by-character guessing), which is computationally expensive.';
    }

    vulnType.className = 'vulnerability-type ' + typeClass;
    vulnType.innerHTML = `${icon} ${vulnerability}`;
    vulnExplain.innerHTML = explanation;
}

// ===== Display Feature Vector =====
function displayFeatureVector(features) {
    const vectorDisplay = document.getElementById('featureVector');
    const vectorContent = document.getElementById('vectorDisplay');

    vectorDisplay.style.display = 'block';

    let vectorHTML = '[\n';
    for (let key in features) {
        vectorHTML += `<div style="display: flex; gap: 10px;">
            <span style="color: #2ecc71;">  ${key}</span>
            <span style="color: #ff9999;">:</span>
            <span style="color: #6dd5ff;">${features[key]}</span>
            <span style="color: #ff9999;">,</span>
        </div>`;
    }
    vectorHTML += ']';

    vectorContent.innerHTML = vectorHTML;
}

// ===== Toggle Password Visibility =====
function togglePassword() {
    const passwordInput = document.getElementById('passwordInput');
    const toggleBtn = document.getElementById('toggleBtn');

    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.textContent = '🙈';
    } else {
        passwordInput.type = 'password';
        toggleBtn.textContent = '👁️';
    }
}

// ===== Test Password Button =====
function testPassword() {
    const testerSection = document.getElementById('tester');
    testerSection.scrollIntoView({ behavior: 'smooth' });
    document.getElementById('passwordInput').focus();
}

// ===== Intersection Observer for Fade-in Effects =====
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.animation = 'fadeIn 0.6s ease forwards';
        }
    });
}, observerOptions);

// Observe all cards on load
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('.overview-card, .feature-item, .timeline-item');
    cards.forEach(card => {
        observer.observe(card);
    });
});

// ===== Keyboard Accessibility =====
document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && document.activeElement === document.getElementById('passwordInput')) {
        checkPassword();
    }
});

// ===== Real-time password check =====
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) {
        passwordInput.addEventListener('input', checkPassword);
    }
});

// ===== Add subtle animation on scroll =====
window.addEventListener('scroll', function() {
    const scrollPosition = window.scrollY;
    const parallaxElements = document.querySelectorAll('.hero');
    
    parallaxElements.forEach(element => {
        element.style.transform = `translateY(${scrollPosition * 0.5}px)`;
    });
});

// ===== Interactive decision tree simulation =====
function simulateDecisionTree(password) {
    let decision = '';
    
    if (password.length < 8) {
        decision = 'WEAK - Password length is less than 8 characters';
    } else {
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

        const complexityScore = (hasUppercase ? 1 : 0) + (hasLowercase ? 1 : 0) + 
                               (hasNumbers ? 1 : 0) + (hasSpecial ? 1 : 0);

        if (complexityScore < 2) {
            decision = 'MODERATE - Password has low complexity';
        } else {
            decision = 'STRONG - Password has high complexity';
        }
    }
    
    return decision;
}

// ===== Navigation Active State =====
window.addEventListener('scroll', function() {
    const sections = document.querySelectorAll('section');
    const navLinks = document.querySelectorAll('.nav-link');

    let activeSectionId = '';
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (window.scrollY >= sectionTop - 200) {
            activeSectionId = section.getAttribute('id');
        }
    });

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === '#' + activeSectionId) {
            link.classList.add('active');
        }
    });
});

// ===== Add CSS for active nav link =====
const style = document.createElement('style');
style.textContent = `
    .nav-link.active {
        color: #e94560;
    }
    .nav-link.active::after {
        width: 100%;
    }
`;
document.head.appendChild(style);

// ===== Mobile menu toggle (optional enhancement) =====
function createMobileMenu() {
    const navbar = document.querySelector('.navbar');
    if (window.innerWidth <= 768) {
        // Mobile adjustments handled by CSS media queries
    }
}

window.addEventListener('resize', createMobileMenu);
createMobileMenu();

// ===== Password strength tester initialization =====
console.log('Password Strategy Vulnerability Analysis - Decision Tree Classification System Loaded');
console.log('Ready to evaluate user passwords and provide vulnerability assessments');

// ===== Display Recommendations =====
function displayRecommendations(vulnerability, features) {
    const box = document.getElementById('recommendationBox');
    const list = document.getElementById('recommendationList');

    box.style.display = 'block';

    let recommendations = [];

    // Feature-based recommendations (PERSONALIZED)
const password = document.getElementById('passwordInput').value;

// Detect sequence
const seqMatch = password.match(/abc|bcd|cde|def|123|234|345|456|567|678|789/i);
if (seqMatch) {
    recommendations.push(`Avoid sequence "${seqMatch[0]}" found in your password`);
}

// Detect repetition
const repMatch = password.match(/(.)\1{2,}/);
if (repMatch) {
    recommendations.push(`Avoid repeated characters like "${repMatch[0]}"`);
}

// Detect numeric suffix
const numSuffix = password.match(/\d+$/);
if (numSuffix) {
    recommendations.push(`Avoid predictable numeric ending "${numSuffix[0]}"`);
}

// Detect dictionary word (simple highlight)
for (let word of commonDictionary) {
    if (password.toLowerCase().includes(word)) {
        recommendations.push(`Avoid using common word "${word}" in your password`);
        break;
    }
}

// Missing symbol
if (!features.has_symbol) {
    recommendations.push(`Add at least one special character (e.g., @, #, $)`);
}

// Short length
if (features.length < 12) {
    recommendations.push(`Increase length (current: ${features.length}, recommended: 12+)`);
}

// Suggest better placement of symbols (smart tip)
if (features.numeric_suffix || features.symbol_affix) {
    recommendations.push(`Try modifying your password by inserting symbols in the middle instead of the end`);
}
    // Render
    let html = '';
    recommendations.forEach(rec => {
        html += `<li>${rec}</li>`;
    });

    list.innerHTML = html;
}