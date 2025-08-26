// SafeGuard Browser Extension - Content Script
// Handles in-page warnings and security monitoring

(function() {
    'use strict';
    
    let warningOverlay = null;
    let isWarningDisplayed = false;
    let suspiciousActivityScore = 0;
    
    console.log('SafeGuard content script loaded');
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        console.log('Content script received message:', request);
        
        if (request.action === 'showWarning' && !isWarningDisplayed) {
            showSecurityWarning(request.data);
            sendResponse({ success: true });
        }
        
        return true; // Keep message channel open
    });
    
    // Display security warning overlay
    function showSecurityWarning(riskData) {
        if (isWarningDisplayed) return;
        
        console.log('Displaying security warning:', riskData);
        isWarningDisplayed = true;
        
        // Create warning overlay
        warningOverlay = document.createElement('div');
        warningOverlay.id = 'safeguard-security-warning';
        warningOverlay.innerHTML = createWarningHTML(riskData);
        
        // Inject CSS styles
        injectWarningStyles();
        
        // Add to page
        document.body.appendChild(warningOverlay);
        
        // Setup event listeners
        setupWarningInteractions();
        
        // Auto-hide after 15 seconds if no user interaction
        setTimeout(() => {
            if (warningOverlay && document.body.contains(warningOverlay)) {
                hideWarning();
            }
        }, 15000);
    }
    
    // Create warning overlay HTML
    function createWarningHTML(riskData) {
        const riskColor = getRiskColor(riskData.score);
        const riskLevel = formatRiskLevel(riskData.level);
        const iconEmoji = getRiskIcon(riskData.score);
        
        return `
            <div class="safeguard-overlay-backdrop">
                <div class="safeguard-warning-container">
                    <div class="safeguard-warning-header">
                        <div class="safeguard-warning-icon" style="background: ${riskColor}">
                            ${iconEmoji}
                        </div>
                        <h2 class="safeguard-warning-title" style="color: ${riskColor}">
                            Security Warning
                        </h2>
                        <button class="safeguard-close-btn" onclick="window.safeguardHideWarning()">
                            ✕
                        </button>
                    </div>
                    
                    <div class="safeguard-warning-content">
                        <div class="safeguard-risk-summary">
                            <div class="safeguard-risk-score" style="color: ${riskColor}">
                                ${riskData.score.toFixed(1)}/10
                            </div>
                            <div class="safeguard-risk-level">${riskLevel} Detected</div>
                        </div>
                        
                        <p class="safeguard-warning-message">
                            This website has been flagged for potential security risks. 
                            We recommend exercising caution while browsing this site.
                        </p>
                        
                        ${createFactorsHTML(riskData.factors)}
                        
                        <div class="safeguard-warning-actions">
                            <a href="www.google.com"> <button class="safeguard-btn safeguard-btn-primary" onclick="window.safeguardGoBack()" >
                                🔙 Go Back to Safety
                            </button></a>
                            <button class="safeguard-btn safeguard-btn-secondary" onclick="window.safeguardContinue()">
                                Continue with Caution
                            </button>
                        </div>
                        
                        <div class="safeguard-warning-footer">
                            <small>🛡️ Protected by SafeGuard Browser Extension</small>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Create risk factors HTML
    function createFactorsHTML(factors) {
        if (!factors || factors.length === 0) {
            return '';
        }
        
        const factorItems = factors.map(factor => `
            <div class="safeguard-factor-item">
                <span class="safeguard-factor-icon">⚠️</span>
                <span class="safeguard-factor-text">${factor.description}</span>
            </div>
        `).join('');
        
        return `
            <div class="safeguard-factors-section">
                <h4 class="safeguard-factors-title">Security Issues Detected:</h4>
                <div class="safeguard-factors-list">
                    ${factorItems}
                </div>
            </div>
        `;
    }
    
    // Inject CSS styles for warning overlay
    function injectWarningStyles() {
        if (document.getElementById('safeguard-warning-styles')) return;
        
        const styles = document.createElement('style');
        styles.id = 'safeguard-warning-styles';
        styles.textContent = `
            .safeguard-overlay-backdrop {
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                height: 100% !important;
                background: rgba(0, 0, 0, 0.8) !important;
                backdrop-filter: blur(5px) !important;
                z-index: 2147483647 !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
                animation: safeguardFadeIn 0.3s ease !important;
            }
            
            .safeguard-warning-container {
                background: white !important;
                border-radius: 20px !important;
                max-width: 500px !important;
                width: 90% !important;
                max-height: 80vh !important;
                overflow-y: auto !important;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3) !important;
                animation: safeguardSlideUp 0.4s cubic-bezier(0.4, 0, 0.2, 1) !important;
                position: relative !important;
            }
            
            .safeguard-warning-header {
                display: flex !important;
                align-items: center !important;
                padding: 25px 25px 0 25px !important;
                position: relative !important;
            }
            
            .safeguard-warning-icon {
                width: 60px !important;
                height: 60px !important;
                border-radius: 50% !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                font-size: 30px !important;
                margin-right: 20px !important;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2) !important;
            }
            
            .safeguard-warning-title {
                font-size: 24px !important;
                font-weight: bold !important;
                margin: 0 !important;
                flex: 1 !important;
            }
            
            .safeguard-close-btn {
                position: absolute !important;
                top: 15px !important;
                right: 15px !important;
                background: #f0f0f0 !important;
                border: none !important;
                border-radius: 50% !important;
                width: 35px !important;
                height: 35px !important;
                font-size: 16px !important;
                cursor: pointer !important;
                transition: all 0.3s ease !important;
            }
            
            .safeguard-close-btn:hover {
                background: #e0e0e0 !important;
                transform: scale(1.1) !important;
            }
            
            .safeguard-warning-content {
                padding: 20px 25px 25px 25px !important;
            }
            
            .safeguard-risk-summary {
                text-align: center !important;
                margin-bottom: 20px !important;
                padding: 20px !important;
                background: #f8f9fa !important;
                border-radius: 15px !important;
            }
            
            .safeguard-risk-score {
                font-size: 36px !important;
                font-weight: bold !important;
                margin-bottom: 5px !important;
            }
            
            .safeguard-risk-level {
                font-size: 16px !important;
                font-weight: 600 !important;
                text-transform: uppercase !important;
                letter-spacing: 1px !important;
                color: #666 !important;
            }
            
            .safeguard-warning-message {
                font-size: 16px !important;
                line-height: 1.6 !important;
                color: #333 !important;
                margin-bottom: 20px !important;
                text-align: center !important;
            }
            
            .safeguard-factors-section {
                margin: 20px 0 !important;
            }
            
            .safeguard-factors-title {
                font-size: 16px !important;
                font-weight: bold !important;
                color: #333 !important;
                margin-bottom: 12px !important;
            }
            
            .safeguard-factors-list {
                display: flex !important;
                flex-direction: column !important;
                gap: 8px !important;
            }
            
            .safeguard-factor-item {
                background: #fff3cd !important;
                border: 1px solid #ffeaa7 !important;
                border-radius: 8px !important;
                padding: 12px 15px !important;
                display: flex !important;
                align-items: center !important;
                gap: 12px !important;
                animation: safeguardFactorSlideIn 0.4s ease forwards !important;
                opacity: 0 !important;
            }
            
            .safeguard-factor-icon {
                font-size: 18px !important;
            }
            
            .safeguard-factor-text {
                font-size: 14px !important;
                color: #8b5a00 !important;
                font-weight: 500 !important;
            }
            
            .safeguard-warning-actions {
                display: flex !important;
                gap: 15px !important;
                margin-top: 25px !important;
                flex-wrap: wrap !important;
            }
            
            .safeguard-btn {
                flex: 1 !important;
                padding: 15px 20px !important;
                border: none !important;
                border-radius: 12px !important;
                font-size: 16px !important;
                font-weight: bold !important;
                cursor: pointer !important;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
                min-width: 140px !important;
            }
            
            .safeguard-btn-primary {
                background: linear-gradient(45deg, #4CAF50, #66BB6A) !important;
                color: white !important;
                box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3) !important;
            }
            
            .safeguard-btn-primary:hover {
                transform: translateY(-2px) !important;
                box-shadow: 0 8px 25px rgba(76, 175, 80, 0.4) !important;
            }
            
            .safeguard-btn-secondary {
                background: #f8f9fa !important;
                color: #495057 !important;
                border: 2px solid #dee2e6 !important;
            }
            
            .safeguard-btn-secondary:hover {
                background: #e9ecef !important;
                transform: translateY(-2px) !important;
            }
            
            .safeguard-warning-footer {
                text-align: center !important;
                margin-top: 20px !important;
                padding-top: 15px !important;
                border-top: 1px solid #eee !important;
                color: #666 !important;
                font-size: 12px !important;
            }
            
            @keyframes safeguardFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            @keyframes safeguardSlideUp {
                from { 
                    opacity: 0;
                    transform: translateY(50px) scale(0.9);
                }
                to { 
                    opacity: 1;
                    transform: translateY(0) scale(1);
                }
            }
            
            @keyframes safeguardFactorSlideIn {
                from {
                    opacity: 0;
                    transform: translateX(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            @media (max-width: 600px) {
                .safeguard-warning-container {
                    width: 95% !important;
                    margin: 20px !important;
                }
                
                .safeguard-warning-actions {
                    flex-direction: column !important;
                }
                
                .safeguard-btn {
                    width: 100% !important;
                }
            }
        `;
        
        document.head.appendChild(styles);
    }
    
    // Setup warning interaction handlers
    function setupWarningInteractions() {
        // Add animation delays to factors
        const factorItems = document.querySelectorAll('.safeguard-factor-item');
        factorItems.forEach((item, index) => {
            item.style.animationDelay = `${index * 150}ms`;
        });
        
        // Global functions for button handlers
        window.safeguardHideWarning = hideWarning;
        window.safeguardGoBack = handleGoBack;
        window.safeguardContinue = handleContinue;
        
        // Close on escape key
        document.addEventListener('keydown', handleEscapeKey);
        
        // Close on backdrop click
        if (warningOverlay) {
            warningOverlay.addEventListener('click', (e) => {
                if (e.target === warningOverlay.querySelector('.safeguard-overlay-backdrop')) {
                    hideWarning();
                }
            });
        }
    }
    
    // Handle escape key press
    function handleEscapeKey(e) {
        if (e.key === 'Escape' && isWarningDisplayed) {
            hideWarning();
        }
    }
    
    // Handle go back button
    function handleGoBack() {
        console.log('User chose to go back');
        
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = 'https://www.google.com';
        }
        
        hideWarning();
    }
    
    // Handle continue button
    function handleContinue() {
        console.log('User chose to continue with caution');
        
        // Show additional confirmation for high-risk sites
        const riskScore = parseFloat(document.querySelector('.safeguard-risk-score')?.textContent || '0');
        
        if (riskScore >= 7) {
            const confirmed = confirm(
                'FINAL WARNING: This website poses significant security risks. ' +
                'Continuing may expose you to malware, phishing, or data theft. ' +
                'Are you absolutely sure you want to proceed?'
            );
            
            if (!confirmed) {
                return;
            }
        }
        
        hideWarning();
    }
    
    // Hide warning overlay
    function hideWarning() {
        if (warningOverlay && document.body.contains(warningOverlay)) {
            warningOverlay.style.animation = 'safeguardFadeOut 0.3s ease';
            
            setTimeout(() => {
                if (document.body.contains(warningOverlay)) {
                    document.body.removeChild(warningOverlay);
                }
                
                // Cleanup
                warningOverlay = null;
                isWarningDisplayed = false;
                
                // Remove event listeners
                document.removeEventListener('keydown', handleEscapeKey);
                
                // Remove global functions
                delete window.safeguardHideWarning;
                delete window.safeguardGoBack;
                delete window.safeguardContinue;
                
            }, 300);
        }
    }
    
    // Monitor suspicious page behavior
    function initializeBehaviorMonitoring() {
        // Track suspicious redirects
        let redirectCount = 0;
        const originalPushState = history.pushState;
        const originalReplaceState = history.replaceState;
        
        history.pushState = function() {
            redirectCount++;
            if (redirectCount > 15) {
                suspiciousActivityScore += 3;
                reportSuspiciousActivity('excessive_redirects');
            }
            return originalPushState.apply(history, arguments);
        };
        
        history.replaceState = function() {
            redirectCount++;
            if (redirectCount > 15) {
                suspiciousActivityScore += 3;
                reportSuspiciousActivity('excessive_redirects');
            }
            return originalReplaceState.apply(history, arguments);
        };
        
        // Monitor DOM manipulation
        const observer = new MutationObserver((mutations) => {
            let suspiciousChanges = 0;
            
            mutations.forEach((mutation) => {
                // Large number of added nodes
                if (mutation.addedNodes.length > 100) {
                    suspiciousChanges += 2;
                }
                
                // Suspicious script additions
                mutation.addedNodes.forEach(node => {
                    if (node.tagName === 'SCRIPT' && node.src && 
                        (node.src.includes('data:') || node.src.includes('blob:'))) {
                        suspiciousChanges += 3;
                    }
                });
            });
            
            if (suspiciousChanges > 5) {
                suspiciousActivityScore += suspiciousChanges;
                reportSuspiciousActivity('dom_manipulation');
            }
        });
        
        // Start observing when DOM is ready
        if (document.body) {
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: false
            });
        }
        
        // Monitor for suspicious form submissions
        document.addEventListener('submit', (event) => {
            const form = event.target;
            if (form.action && (
                form.action.includes('data:') || 
                form.action.includes('javascript:') ||
                form.action.includes('blob:')
            )) {
                suspiciousActivityScore += 5;
                reportSuspiciousActivity('suspicious_form_submission');
                
                // Consider blocking the submission
                if (suspiciousActivityScore > 10) {
                    event.preventDefault();
                    alert('SafeGuard: Blocked potentially malicious form submission');
                }
            }
        });
    }
    
    // Report suspicious activity to background script
    function reportSuspiciousActivity(activityType) {
        try {
            chrome.runtime.sendMessage({
                action: 'suspiciousActivity',
                data: {
                    type: activityType,
                    score: suspiciousActivityScore,
                    url: window.location.href,
                    timestamp: Date.now()
                }
            });
        } catch (error) {
            console.log('Could not report suspicious activity:', error);
        }
        
        // Reset score after reporting
        if (suspiciousActivityScore > 15) {
            suspiciousActivityScore = 0;
        }
    }
    
    // Utility functions
    function getRiskColor(score) {
        if (score >= 8) return '#f44336';
        if (score >= 5) return '#ff9800';
        if (score >= 2) return '#ffc107';
        return '#4caf50';
    }
    
    function getRiskIcon(score) {
        if (score >= 8) return '🚨';
        if (score >= 5) return '⚠️';
        if (score >= 2) return '⚡';
        return '✅';
    }
    
    function formatRiskLevel(level) {
        const levels = {
            'HIGH': 'High Risk',
            'MEDIUM': 'Medium Risk',
            'LOW': 'Low Risk',
            'SAFE': 'Safe'
        };
        return levels[level] || 'Unknown Risk';
    }
    
    // Initialize behavior monitoring when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeBehaviorMonitoring);
    } else {
        initializeBehaviorMonitoring();
    }
    
    // Add fade out animation
    const fadeOutStyle = document.createElement('style');
    fadeOutStyle.textContent = `
        @keyframes safeguardFadeOut {
            from { opacity: 1; }
            to { opacity: 0; }
        }
    `;
    if (document.head) {
        document.head.appendChild(fadeOutStyle);
    }
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (warningOverlay && document.body.contains(warningOverlay)) {
            document.body.removeChild(warningOverlay);
        }
    });
    
    console.log('SafeGuard content script fully initialized');
    
})();