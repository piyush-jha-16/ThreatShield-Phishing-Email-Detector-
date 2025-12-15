// ThreatShield - Email Phishing Detection System
// Main JavaScript Application

// ==========================================
// Application State Management
// ==========================================
const AppState = {
    isAuthenticated: false,
    currentUser: null,
    currentTab: 'manual',
    selectedFile: null
};

// ==========================================
// DOM Ready Event
// ==========================================
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

// ==========================================
// Application Initialization
// ==========================================
function initializeApp() {
    setupEventListeners();
    setupDragAndDrop();
    checkAuthenticationState();
}

// ==========================================
// Event Listeners Setup
// ==========================================
function setupEventListeners() {
    // Login Form
    const loginForm = document.getElementById('loginFormElement');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Register Form
    const registerForm = document.getElementById('registerFormElement');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    // Manual Analysis Form
    const manualForm = document.getElementById('manualAnalysisForm');
    if (manualForm) {
        manualForm.addEventListener('submit', handleManualAnalysis);
    }

    // File Analysis Form
    const fileForm = document.getElementById('fileAnalysisForm');
    if (fileForm) {
        fileForm.addEventListener('submit', handleFileAnalysis);
    }

    // File Input
    const fileInput = document.getElementById('emlFileInput');
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelection);
    }
}

// ==========================================
// Drag and Drop Setup
// ==========================================
function setupDragAndDrop() {
    const uploadArea = document.getElementById('uploadArea');
    if (!uploadArea) return;

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = 'var(--color-accent)';
        uploadArea.style.background = 'var(--color-surface)';
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.style.borderColor = '';
        uploadArea.style.background = '';
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = '';
        uploadArea.style.background = '';

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (file.name.endsWith('.eml')) {
                const fileInput = document.getElementById('emlFileInput');
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(file);
                fileInput.files = dataTransfer.files;
                handleFileSelection({ target: fileInput });
            } else {
                showError('Please upload a valid .eml file');
            }
        }
    });

    uploadArea.addEventListener('click', () => {
        document.getElementById('emlFileInput').click();
    });
}

// ==========================================
// Authentication Functions
// ==========================================
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    const errorElement = document.getElementById('loginError');
    errorElement.textContent = '';
    errorElement.classList.remove('active');
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            AppState.isAuthenticated = true;
            AppState.currentUser = username;
            showMainApp();
        } else {
            showError(data.message, 'loginError');
        }
    } catch (error) {
        showError('Connection error. Please try again.', 'loginError');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    
    const errorElement = document.getElementById('registerError');
    errorElement.textContent = '';
    errorElement.classList.remove('active');
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess('Registration successful! Please sign in.');
            setTimeout(() => switchToLogin(), 1500);
        } else {
            showError(data.message, 'registerError');
        }
    } catch (error) {
        showError('Connection error. Please try again.', 'registerError');
    }
}

async function handleLogout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        AppState.isAuthenticated = false;
        AppState.currentUser = null;
        location.reload();
    } catch (error) {
        console.error('Logout error:', error);
        location.reload();
    }
}

function checkAuthenticationState() {
    // Check if user is authenticated (this is simplified)
    // In production, implement proper session management
}

// ==========================================
// UI Navigation Functions
// ==========================================
function switchToRegister() {
    document.getElementById('loginForm').classList.remove('active');
    document.getElementById('registerForm').classList.add('active');
    clearError('loginError');
}

function switchToLogin() {
    document.getElementById('registerForm').classList.remove('active');
    document.getElementById('loginForm').classList.add('active');
    clearError('registerError');
}

function showMainApp() {
    document.getElementById('authModal').classList.remove('active');
    document.getElementById('mainApp').classList.add('active');
    document.getElementById('currentUser').textContent = AppState.currentUser;
}

function switchTab(tab) {
    AppState.currentTab = tab;
    
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.dataset.tab === tab) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    // Update panels
    document.querySelectorAll('.analysis-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    
    if (tab === 'manual') {
        document.getElementById('manualPanel').classList.add('active');
    } else {
        document.getElementById('filePanel').classList.add('active');
    }
    
    // Clear results when switching tabs
    clearResults();
}

// ==========================================
// Form Handling Functions
// ==========================================
function handleFileSelection(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    if (!file.name.endsWith('.eml')) {
        showError('Please select a valid .eml file');
        return;
    }
    
    AppState.selectedFile = file;
    
    // Show file info
    document.getElementById('uploadArea').style.display = 'none';
    document.getElementById('fileSelected').style.display = 'flex';
    document.getElementById('selectedFileName').textContent = file.name;
    document.getElementById('selectedFileSize').textContent = formatFileSize(file.size);
    document.getElementById('analyzeFileBtn').disabled = false;
}

function clearFileSelection() {
    AppState.selectedFile = null;
    document.getElementById('emlFileInput').value = '';
    document.getElementById('uploadArea').style.display = 'flex';
    document.getElementById('fileSelected').style.display = 'none';
    document.getElementById('analyzeFileBtn').disabled = true;
}

function clearManualForm() {
    document.getElementById('manualAnalysisForm').reset();
}

// ==========================================
// Analysis Functions
// ==========================================
async function handleManualAnalysis(e) {
    e.preventDefault();
    
    const sender = document.getElementById('emailSender').value.trim();
    const subject = document.getElementById('emailSubject').value.trim();
    const body = document.getElementById('emailBody').value.trim();
    
    showLoading();
    
    try {
        const response = await fetch('/api/analyze-manual', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ sender, subject, body })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data.result);
        } else {
            showError(data.message);
        }
    } catch (error) {
        showError('Analysis failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function handleFileAnalysis(e) {
    e.preventDefault();
    
    if (!AppState.selectedFile) {
        showError('Please select a file first');
        return;
    }
    
    showLoading();
    
    const formData = new FormData();
    formData.append('file', AppState.selectedFile);
    
    try {
        const response = await fetch('/api/analyze-file', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data.result, data.email_preview);
        } else {
            showError(data.message);
        }
    } catch (error) {
        showError('Analysis failed. Please try again.');
    } finally {
        hideLoading();
    }
}

// ==========================================
// Results Display Functions
// ==========================================
function displayResults(result, emailPreview = null) {
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    // Display risk score
    displayRiskScore(result.risk_score, result.classification);
    
    // Display flags
    displayFlags(result.flags);
    
    // Display details
    displayDetails(result.details, emailPreview);
}

function displayRiskScore(score, classification) {
    // Update score text
    document.getElementById('riskScoreValue').textContent = score;
    
    // Update circular progress
    const circle = document.getElementById('riskScoreCircle');
    const circumference = 2 * Math.PI * 52; // radius = 52
    const offset = circumference - (score / 100) * circumference;
    circle.style.strokeDashoffset = offset;
    
    // Set color based on classification
    let color;
    if (classification === 'SAFE') {
        color = 'var(--color-safe)';
    } else if (classification === 'SUSPICIOUS') {
        color = 'var(--color-suspicious)';
    } else {
        color = 'var(--color-danger)';
    }
    circle.style.stroke = color;
    
    // Update classification badge
    const badge = document.getElementById('classificationBadge');
    badge.className = 'classification-badge ' + classification.toLowerCase();
    document.getElementById('classificationText').textContent = classification;
    
    // Update description
    const descriptions = {
        'SAFE': 'No significant phishing indicators detected. The email appears to be legitimate based on rule-based analysis.',
        'SUSPICIOUS': 'Multiple suspicious patterns detected. Exercise caution and verify sender authenticity before taking any action.',
        'PHISHING': 'High-confidence phishing attempt detected. Do not interact with this email. Report to security team immediately.'
    };
    document.getElementById('classificationDescription').textContent = descriptions[classification];
}

function displayFlags(flags) {
    const flagsList = document.getElementById('flagsList');
    flagsList.innerHTML = '';
    
    if (!flags || flags.length === 0) {
        flagsList.innerHTML = `
            <div class="no-flags">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M16 2L4 8V14C4 21 9 27.5 16 30C23 27.5 28 21 28 14V8L16 2Z"/>
                    <path d="M12 16L15 19L20 13"/>
                </svg>
                <p>No security flags detected</p>
            </div>
        `;
        return;
    }
    
    flags.forEach((flag, index) => {
        const severity = determineFlagSeverity(flag);
        const flagItem = document.createElement('div');
        flagItem.className = `flag-item ${severity}`;
        flagItem.innerHTML = `
            <svg class="flag-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <span class="flag-text">${escapeHtml(flag)}</span>
        `;
        flagsList.appendChild(flagItem);
    });
}

function displayDetails(details, emailPreview = null) {
    const detailsList = document.getElementById('detailsList');
    detailsList.innerHTML = '';
    
    // Add email preview if available
    if (emailPreview) {
        addDetailItem('Sender', emailPreview.sender);
        addDetailItem('Subject', emailPreview.subject);
    }
    
    // Add analysis details
    if (details.sender_domain) {
        addDetailItem('Sender Domain', details.sender_domain);
    }
    
    if (details.url_count !== undefined) {
        addDetailItem('URLs Found', details.url_count.toString());
    }
    
    if (details.suspicious_urls && details.suspicious_urls.length > 0) {
        details.suspicious_urls.forEach((url, index) => {
            addDetailItem(`Suspicious URL ${index + 1}`, url);
        });
    }
    
    // Add timestamp
    const timestamp = new Date().toLocaleString();
    addDetailItem('Analysis Time', timestamp);
}

function addDetailItem(label, value) {
    const detailsList = document.getElementById('detailsList');
    const detailItem = document.createElement('div');
    detailItem.className = 'detail-item';
    detailItem.innerHTML = `
        <span class="detail-label">${escapeHtml(label)}</span>
        <span class="detail-value">${escapeHtml(value)}</span>
    `;
    detailsList.appendChild(detailItem);
}

function clearResults() {
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'none';
}

// ==========================================
// Utility Functions
// ==========================================
function determineFlagSeverity(flag) {
    const highSeverityKeywords = [
        'spoofing', 'phishing', 'malicious', 'suspicious attachment',
        'SPF', 'DKIM', 'IP address', 'misleading'
    ];
    
    const flagLower = flag.toLowerCase();
    for (const keyword of highSeverityKeywords) {
        if (flagLower.includes(keyword.toLowerCase())) {
            return 'high-severity';
        }
    }
    
    return '';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showError(message, elementId = null) {
    if (elementId) {
        const errorElement = document.getElementById(elementId);
        errorElement.textContent = message;
        errorElement.classList.add('active');
    } else {
        alert(message);
    }
}

function clearError(elementId) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.classList.remove('active');
    }
}

function showSuccess(message) {
    // Simple success notification (could be enhanced with a toast component)
    const successDiv = document.createElement('div');
    successDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--color-safe);
        color: white;
        padding: 1rem 1.5rem;
        border-radius: var(--radius-md);
        box-shadow: var(--shadow-lg);
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    successDiv.textContent = message;
    document.body.appendChild(successDiv);
    
    setTimeout(() => {
        successDiv.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => successDiv.remove(), 300);
    }, 3000);
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
