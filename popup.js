// SafeGuard Browser Extension - Popup Interface JavaScript

// Initialize popup when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('SafeGuard popup initializing...');
    initializePopup();
    setupEventListeners();
});

// Main initialization function
async function initializePopup() {
    try {
        showLoadingScreen();
        
        // Load current tab's risk data
        const riskData = await getRiskData();
        
        // Load extension settings
        const settings = await getExtensionSettings();
        
        // Simulate loading delay for better UX
        setTimeout(() => {
            hideLoadingScreen();
            
            if (riskData) {
                displaySecurityData(riskData);
                showMainContent();
            } else {
                showNoDataScreen();
            }
            
            updateSettingsUI(settings);
        }, 1500);
        
    } catch (error) {
        console.error('Error initializing popup:', error);
        hideLoadingScreen();
        showNoDataScreen();
    }
}

// Get risk data for current tab
function getRiskData() {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getRiskData' }, (response) => {
            console.log('Risk data received:', response);
            resolve(response);
        });
    });
}

// Get extension settings
function getExtensionSettings() {
    return new Promise((resolve) => {
        chrome.storage.sync.get([
            'extensionEnabled', 
            'blockMalicious', 
            'showWarnings', 
            'logActivity'
        ], (settings) => {
            resolve(settings);
        });
    });
}

// Display security analysis data
function displaySecurityData(data) {
    const { url, score, factors, level, timestamp } = data;
    
    // Update website URL
    document.getElementById('websiteUrl').textContent = formatUrl(url);
    
    // Update risk score and level
    document.getElementById('riskScore').textContent = score.toFixed(1);
    document.getElementById('detailedScore').textContent = score.toFixed(1) + '/10';
    document.getElementById('riskLevelText').textContent = formatRiskLevel(level);
    
    // Update risk circle appearance
    const riskCircle = document.getElementById('riskCircle');
    riskCircle.className = 'risk-circle ' + getRiskCircleClass(level);
    
    // Update scan time
    document.getElementById('scanTime').textContent = `Last scanned: ${formatTime(timestamp)}`;
    
    // Display risk factors if any exist
    if (factors && factors.length > 0) {
        displayRiskFactors(factors);
        document.getElementById('riskFactorsSection').style.display = 'block';
    } else {
        document.getElementById('riskFactorsSection').style.display = 'none';
    }
}

// Display risk factors list
function displayRiskFactors(factors) {
    const factorsList = document.getElementById('factorsList');
    factorsList.innerHTML = '';
    
    factors.forEach((factor, index) => {
        const factorElement = document.createElement('div');
        factorElement.className = 'factor-item';
        
        // Add animation delay for each factor
        factorElement.style.animationDelay = `${index * 100}ms`;
        
        factorElement.innerHTML = `
            <div class="factor-icon">⚠️</div>
            <div>${factor.description}</div>
        `;
        
        factorsList.appendChild(factorElement);
    });
}

// Update settings toggle switches
function updateSettingsUI(settings) {
    const toggles = document.querySelectorAll('.toggle-switch');
    
    toggles.forEach(toggle => {
        const setting = toggle.getAttribute('data-setting');
        const isEnabled = settings[setting] !== false; // Default to true if undefined
        
        toggle.classList.toggle('active', isEnabled);
        
        // Add visual feedback
        if (isEnabled) {
            toggle.style.boxShadow = '0 0 10px rgba(76, 175, 80, 0.3)';
        } else {
            toggle.style.boxShadow = 'none';
        }
    });
}

// Setup event listeners for UI interactions
function setupEventListeners() {
    // Settings toggle switches
    document.querySelectorAll('.toggle-switch').forEach(toggle => {
        toggle.addEventListener('click', handleSettingToggle);
    });
    
    // Add hover effects
    document.querySelectorAll('.toggle-switch').forEach(toggle => {
        toggle.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.05)';
        });
        
        toggle.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    });
}

// Handle setting toggle clicks
async function handleSettingToggle(event) {
    const toggle = event.currentTarget;
    const setting = toggle.getAttribute('data-setting');
    const isCurrentlyActive = toggle.classList.contains('active');
    const newValue = !isCurrentlyActive;
    
    // Update UI immediately for responsiveness
    toggle.classList.toggle('active', newValue);
    
    // Add visual feedback
    if (newValue) {
        toggle.style.boxShadow = '0 0 10px rgba(76, 175, 80, 0.3)';
    } else {
        toggle.style.boxShadow = 'none';
    }
    
    // Save setting to storage
    const settingUpdate = {};
    settingUpdate[setting] = newValue;
    
    try {
        await new Promise((resolve) => {
            chrome.runtime.sendMessage({
                action: 'updateSettings',
                settings: settingUpdate
            }, (response) => {
                resolve(response);
            });
        });
        
        // Show feedback message
        showSettingFeedback(setting, newValue);
        
    } catch (error) {
        console.error('Error updating setting:', error);
        
        // Revert UI on error
        toggle.classList.toggle('active', isCurrentlyActive);
    }
}

// Show setting change feedback
function showSettingFeedback(setting, enabled) {
    const settingNames = {
        'extensionEnabled': 'Protection',
        'blockMalicious': 'Site Blocking',
        'showWarnings': 'Security Warnings',
        'logActivity': 'Activity Logging'
    };
    
    const settingName = settingNames[setting] || setting;
    const status = enabled ? 'enabled' : 'disabled';
    const color = enabled ? '#4CAF50' : '#ff9800';
    
    // Create feedback element
    const feedback = document.createElement('div');
    feedback.style.cssText = `
        position: fixed;
        top: 15px;
        right: 15px;
        background: ${color};
        color: white;
        padding: 10px 20px;
        border-radius: 25px;
        font-size: 12px;
        font-weight: bold;
        z-index: 10000;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        animation: slideInFeedback 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    `;
    feedback.textContent = `${settingName} ${status}`;
    
    document.body.appendChild(feedback);
    
    // Remove feedback after delay
    setTimeout(() => {
        feedback.style.animation = 'slideOutFeedback 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
        setTimeout(() => feedback.remove(), 300);
    }, 2000);
}

// Refresh data manually
async function refreshData() {
    console.log('Refreshing security data...');
    
    showLoadingScreen();
    
    // Wait a moment for any background processing
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Reload data
    const riskData = await getRiskData();
    const settings = await getExtensionSettings();
    
    setTimeout(() => {
        hideLoadingScreen();
        
        if (riskData) {
            displaySecurityData(riskData);
            showMainContent();
        } else {
            showNoDataScreen();
        }
        
        updateSettingsUI(settings);
    }, 1000);
}

// UI State Management Functions
function showLoadingScreen() {
    document.getElementById('loadingScreen').style.display = 'block';
    document.getElementById('mainContent').style.display = 'none';
    document.getElementById('noDataScreen').style.display = 'none';
}

function hideLoadingScreen() {
    document.getElementById('loadingScreen').style.display = 'none';
}

function showMainContent() {
    document.getElementById('mainContent').style.display = 'block';
    document.getElementById('noDataScreen').style.display = 'none';
}

function showNoDataScreen() {
    document.getElementById('mainContent').style.display = 'none';
    document.getElementById('noDataScreen').style.display = 'block';
}

// Utility Functions
function formatUrl(url) {
    try {
        const urlObj = new URL(url);
        let displayUrl = urlObj.hostname;
        
        if (urlObj.pathname !== '/') {
            displayUrl += urlObj.pathname;
        }
        
        // Truncate if too long
        if (displayUrl.length > 35) {
            displayUrl = displayUrl.substring(0, 35) + '...';
        }
        
        return displayUrl;
    } catch {
        return url.length > 35 ? url.substring(0, 35) + '...' : url;
    }
}

function formatRiskLevel(level) {
    const levelNames = {
        'SAFE': 'Secure',
        'LOW': 'Low Risk',
        'MEDIUM': 'Medium Risk',
        'HIGH': 'High Risk'
    };
    
    return levelNames[level] || 'Unknown';
}

function getRiskCircleClass(level) {
    const classNames = {
        'SAFE': 'risk-safe',
        'LOW': 'risk-low',
        'MEDIUM': 'risk-medium',
        'HIGH': 'risk-high'
    };
    
    return classNames[level] || 'risk-safe';
}

function formatTime(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const now = Date.now();
    const diff = now - timestamp;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    if (seconds > 30) return `${seconds}s ago`;
    return 'Just now';
}

// Global function for refresh button
window.refreshData = refreshData;

// Add CSS animations
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes slideInFeedback {
        from { 
            transform: translateX(100%);
            opacity: 0;
        }
        to { 
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutFeedback {
        from { 
            transform: translateX(0);
            opacity: 1;
        }
        to { 
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .factor-item {
        animation: fadeInUp 0.4s ease forwards;
        opacity: 0;
        transform: translateY(10px);
    }
    
    @keyframes fadeInUp {
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .status-card {
        animation: fadeIn 0.6s ease forwards;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
`;

document.head.appendChild(styleSheet);

// Console log for debugging
console.log('SafeGuard popup script loaded successfully');