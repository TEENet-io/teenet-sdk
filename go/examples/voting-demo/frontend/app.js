// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
// -----------------------------------------------------------------------------

// Toast notification system
function showNotification(message, type = 'success') {
    const container = document.getElementById('notification-container') || createNotificationContainer();

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span class="notification-icon">${type === 'success' ? '✅' : '❌'}</span>
        <span class="notification-message">${message}</span>
    `;

    container.appendChild(notification);

    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);

    // Auto remove after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notification-container';
    container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 10px;
    `;
    document.body.appendChild(container);

    // Add notification styles
    const style = document.createElement('style');
    style.textContent = `
        .notification {
            background: white;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 250px;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
        }
        .notification.show {
            opacity: 1;
            transform: translateX(0);
        }
        .notification-success {
            border-left: 4px solid #52c41a;
        }
        .notification-error {
            border-left: 4px solid #ff4d4f;
        }
        .notification-icon {
            font-size: 18px;
        }
        .notification-message {
            color: #333;
            font-size: 14px;
        }
    `;
    document.head.appendChild(style);

    return container;
}

// Global state
let votedMessages = new Set(); // Track messages that have been voted on
let appInstanceId = window.LOADED_APP_INSTANCE_ID || ''; // Load from global set by index.html

// Dynamic API base path detection - works for both direct access and proxy access
function getApiBase() {
    return window.location.pathname.replace(/\/+$/, '');
}

async function makeApiCall(endpoint, options = {}) {
    const url = getApiBase() + '/api/' + endpoint;
    return fetch(url, options);
}

// Direct sign message (without voting)
async function directSign() {
    const message = document.getElementById('signMessage').value.trim();
    const resultDiv = document.getElementById('signResult');

    if (!message) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'result error';
        resultDiv.innerHTML = '<h3>❌ Error</h3><p>Please enter a message</p>';
        return;
    }

    resultDiv.style.display = 'block';
    resultDiv.className = 'result-content loading';
    resultDiv.innerHTML = '<p>⏳ Signing message...</p>';

    try {
        const response = await makeApiCall('sign', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        });

        const result = await response.json();

        if (result.success) {
            if (result.voting_info && result.voting_info.status === 'pending') {
                const votingInfo = result.voting_info;
                resultDiv.className = 'result success';
                resultDiv.innerHTML = `
                    <h3>⏳ Pending Approval</h3>
                    <p class="success-message">Waiting for other voters...</p>
                    <div class="voting-details">
                        <p><strong>Progress:</strong> ${votingInfo.current_votes}/${votingInfo.required_votes}</p>
                        <p><strong>Hash:</strong> <code>${votingInfo.hash}</code></p>
                    </div>
                `;
                return;
            }

            resultDiv.className = 'result success';
            resultDiv.innerHTML = `
                <h3>✅ Signature Generated</h3>
                <p class="success-message">Message signed successfully</p>

                <div class="signature-section">
                    <p><strong>🔐 Signature:</strong></p>
                    <div class="signature-box">
                        <code id="directSignSignature">${result.signature}</code>
                    </div>
                    <button class="btn-small" onclick="copyFromElement('directSignSignature', 'Signature')">
                        📋 Copy Signature
                    </button>
                </div>

                <div class="voting-details">
                    <p><strong>Details:</strong></p>
                    <ul>
                        <li>App Instance ID: <code>${result.app_instance_id || appInstanceId}</code></li>
                        <li>Message: ${result.message}</li>
                    </ul>
                </div>
            `;

            // Auto-fill verification form
            document.getElementById('directVerifyMessage').value = message;
            document.getElementById('directVerifySignature').value = result.signature;
        } else {
            resultDiv.className = 'result error';
            resultDiv.innerHTML = `
                <h3>❌ Sign Failed</h3>
                <p>${result.error || 'Unknown error'}</p>
            `;
        }
    } catch (error) {
        resultDiv.className = 'result error';
        resultDiv.innerHTML = `
            <h3>❌ Network Error</h3>
            <p>${error.message}</p>
        `;
    }
}

// Direct verify signature
async function directVerify() {
    const message = document.getElementById('directVerifyMessage').value.trim();
    const signature = document.getElementById('directVerifySignature').value.trim();
    const resultDiv = document.getElementById('directVerifyResult');

    if (!message || !signature) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'result error';
        resultDiv.innerHTML = '<h3>❌ Error</h3><p>Please enter message and signature</p>';
        return;
    }

    resultDiv.style.display = 'block';
    resultDiv.className = 'result-content loading';
    resultDiv.innerHTML = '<p>⏳ Verifying signature...</p>';

    try {
        const response = await makeApiCall('verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
                signature: signature
            })
        });

        const result = await response.json();

        if (result.success && result.valid) {
            resultDiv.className = 'result success';
            resultDiv.innerHTML = `
                <h3>✅ Signature is VALID</h3>
                <p class="success-message">The signature is valid for this message</p>

                <div class="verify-details">
                    <p><strong>Public Key Information:</strong></p>
                    <p><strong>Public Key:</strong> <code>${result.public_key || 'N/A'}</code></p>
                    <p><strong>Protocol:</strong> ${result.protocol || 'N/A'}</p>
                    <p><strong>Curve:</strong> ${result.curve || 'N/A'}</p>
                </div>
            `;
        } else if (result.success && !result.valid) {
            resultDiv.className = 'result error';
            resultDiv.innerHTML = `
                <h3>❌ Signature is INVALID</h3>
                <p>The signature does not match the message</p>
            `;
        } else {
            resultDiv.className = 'result error';
            resultDiv.innerHTML = `
                <h3>❌ Verification Failed</h3>
                <p>${result.error || 'Unknown error'}</p>
            `;
        }
    } catch (error) {
        resultDiv.className = 'result error';
        resultDiv.innerHTML = `
            <h3>❌ Network Error</h3>
            <p>${error.message}</p>
        `;
    }
}

// Submit vote
async function vote() {
    const message = document.getElementById('message').value.trim();

    // Validation
    if (!message) {
        showNotification('Please enter a message', 'error');
        return;
    }

    // Check if this specific message has already been voted on
    if (votedMessages.has(message)) {
        const retry = confirm('You have already voted on this message. Do you want to vote again?');
        if (!retry) {
            return;
        }
    }

    const voteBtn = document.getElementById('voteBtn');
    const originalText = voteBtn.innerHTML;

    try {
        // Disable button and show loading state
        voteBtn.disabled = true;
        voteBtn.classList.add('loading');
        voteBtn.innerHTML = '⏳ Voting...';

        // Send vote request
        const response = await makeApiCall('vote', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        });

        const result = await response.json();

        if (result.success) {
            // Track this message as voted
            votedMessages.add(message);
            updateVotingStatus(result);

            // Check if we have a signature
            if (result.signature) {
                displaySignature(result);
                // Re-enable button for next vote
                voteBtn.innerHTML = '✅ Vote Another Message';
                voteBtn.disabled = false;
                voteBtn.classList.remove('loading');
                voteBtn.classList.add('success');
            } else {
                showWaitingMessage(result.voting_info);
                // Re-enable button for next vote
                voteBtn.innerHTML = '✅ Vote Another Message';
                voteBtn.disabled = false;
                voteBtn.classList.remove('loading');
                voteBtn.classList.add('success');
            }
        } else {
            // Vote failed
            voteBtn.disabled = false;
            voteBtn.classList.remove('loading');
            voteBtn.innerHTML = originalText;

            showError(result.error || 'Vote failed');
        }
    } catch (error) {

        // Re-enable button on error
        voteBtn.disabled = false;
        voteBtn.classList.remove('loading');
        voteBtn.innerHTML = originalText;

        showError(error.message);
    }
}

// Update voting status display
function updateVotingStatus(result) {
    // Update app status
    document.getElementById('appStatus').innerHTML = '✅ Voted';
    document.getElementById('appStatus').classList.add('status-voted');

    // Update voting progress
    if (result.voting_info) {
        const progress = `${result.voting_info.current_votes}/${result.voting_info.required_votes}`;
        document.getElementById('progress').textContent = progress;
    }
}

// Show waiting message
function showWaitingMessage(votingInfo) {
    const resultDiv = document.getElementById('result');
    resultDiv.className = 'result waiting';

    if (votingInfo) {
        resultDiv.innerHTML = `
            <h3>✅ Vote Submitted</h3>
            <p class="large-text">⏳ Waiting for other voters...</p>
            <p>Current progress: ${votingInfo.current_votes}/${votingInfo.required_votes} votes</p>
            <p>Status: ${votingInfo.status}</p>
            ${votingInfo.hash ? `<p>Hash: <code>${votingInfo.hash.substring(0, 16)}...</code></p>` : ''}
        `;
    } else {
        resultDiv.innerHTML = `
            <p class="large-text">⏳ Waiting for voting result...</p>
        `;
    }
}

// Display signature result
function displaySignature(result) {
    const resultDiv = document.getElementById('result');
    resultDiv.className = 'result success';

    let votingInfoHTML = '';
    if (result.voting_info) {
        votingInfoHTML = `
            <div class="voting-details">
                <p><strong>Voting Details:</strong></p>
                <ul>
                    <li>Final votes: ${result.voting_info.current_votes}/${result.voting_info.required_votes}</li>
                    <li>Status: ${result.voting_info.status}</li>
                    ${result.voting_info.hash ? `<li>Hash: <code>${result.voting_info.hash.substring(0, 32)}...</code></li>` : ''}
                </ul>
            </div>
        `;
    }

    resultDiv.innerHTML = `
        <h3>🎉 Voting Successful!</h3>
        <p class="success-message">✅ Threshold reached, signature generated</p>

        ${votingInfoHTML}

        <div class="signature-section">
            <p><strong>🔐 Signature:</strong></p>
            <div class="signature-box">
                <code id="voteSignature">${result.signature}</code>
            </div>
            <button class="btn-small" onclick="copyFromElement('voteSignature', 'Signature')">
                📋 Copy Signature
            </button>
        </div>
    `;

    // Auto-fill verification section
    const message = document.getElementById('message').value;
    document.getElementById('verifyMessage').value = message;
    document.getElementById('verifySignature').value = result.signature;

    // Scroll to verification section
    setTimeout(() => {
        document.getElementById('verifyMessage').scrollIntoView({
            behavior: 'smooth',
            block: 'center'
        });
    }, 500);
}

// Show error message
function showError(errorMessage) {
    const resultDiv = document.getElementById('result');
    resultDiv.className = 'result error';
    resultDiv.innerHTML = `
        <h3>❌ Vote Failed</h3>
        <p>${errorMessage}</p>
    `;
}

// Verify signature
async function verifySignature() {
    const message = document.getElementById('verifyMessage').value.trim();
    const signature = document.getElementById('verifySignature').value.trim();
    const verifyResultDiv = document.getElementById('verifyResult');

    // Validation
    if (!message) {
        showNotification('Please enter the message', 'error');
        return;
    }

    if (!signature) {
        showNotification('Please enter the signature', 'error');
        return;
    }

    try {
        // Send verify request
        const response = await makeApiCall('verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
                signature: signature
            })
        });

        const result = await response.json();

        if (result.success && result.valid) {
            verifyResultDiv.className = 'result success';
            verifyResultDiv.innerHTML = `
                <h3>✅ Signature is VALID</h3>
                <p>The signature is valid for this message.</p>
                <div class="verify-details">
                    <p><strong>Public Key:</strong> <code>${result.public_key || 'N/A'}</code></p>
                    <p><strong>Protocol:</strong> ${result.protocol || 'N/A'}</p>
                    <p><strong>Curve:</strong> ${result.curve || 'N/A'}</p>
                </div>
            `;
        } else if (result.success && !result.valid) {
            verifyResultDiv.className = 'result error';
            verifyResultDiv.innerHTML = `
                <h3>❌ Signature is INVALID</h3>
                <p>The signature does not match the message.</p>
            `;
        } else {
            verifyResultDiv.className = 'result error';
            verifyResultDiv.innerHTML = `
                <h3>❌ Verification Failed</h3>
                <p>${result.error || 'Unknown error'}</p>
            `;
        }
    } catch (error) {
        verifyResultDiv.className = 'result error';
        verifyResultDiv.innerHTML = `
            <h3>❌ Verification Error</h3>
            <p>${error.message}</p>
        `;
    }
}

// Get API Key
async function getAPIKey() {
    const name = document.getElementById('getApiKeyName').value.trim();
    const resultDiv = document.getElementById('getApiKeyResult');

    if (!name) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'result error';
        resultDiv.innerHTML = '<h3>❌ Error</h3><p>Please enter an API key name</p>';
        return;
    }

    resultDiv.style.display = 'block';
    resultDiv.className = 'result-content loading';
    resultDiv.innerHTML = '<p>⏳ Retrieving API key...</p>';

    try {
        const response = await makeApiCall('apikey/get', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: name })
        });

        const result = await response.json();

        if (result.success) {
            resultDiv.className = 'result success';
            resultDiv.innerHTML = `
                <h3>✅ API Key Retrieved</h3>
                <p class="success-message">Successfully retrieved API key: <strong>${result.name}</strong></p>

                <div class="signature-section">
                    <p><strong>🔑 API Key:</strong></p>
                    <div class="signature-box">
                        <code id="getApiKeyValue">${result.api_key}</code>
                    </div>
                    <button class="btn-small" onclick="copyFromElement('getApiKeyValue', 'API Key')">
                        📋 Copy API Key
                    </button>
                </div>
            `;
        } else {
            resultDiv.className = 'result error';
            resultDiv.innerHTML = `
                <h3>❌ Failed to Get API Key</h3>
                <p>${result.error || 'Unknown error'}</p>
                <p class="help-text">
                    💡 <strong>Possible reasons:</strong><br>
                    • API key "${name}" doesn't exist<br>
                    • API key is not bound to this application<br>
                    • API key doesn't have an API key stored (only secret)
                </p>
            `;
        }
    } catch (error) {
        resultDiv.className = 'result error';
        resultDiv.innerHTML = `
            <h3>❌ Network Error</h3>
            <p>${error.message}</p>
        `;
    }
}

// Sign with API Secret
async function signWithAPISecret() {
    const name = document.getElementById('signApiKeyName').value.trim();
    const message = document.getElementById('signApiKeyMessage').value.trim();
    const resultDiv = document.getElementById('signApiKeyResult');

    if (!name || !message) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'result error';
        resultDiv.innerHTML = '<h3>❌ Error</h3><p>Please enter both API key name and message</p>';
        return;
    }

    resultDiv.style.display = 'block';
    resultDiv.className = 'result-content loading';
    resultDiv.innerHTML = '<p>⏳ Signing with API secret...</p>';

    try {
        const response = await makeApiCall('apikey/sign', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name,
                message: message
            })
        });

        const result = await response.json();

        if (result.success) {
            resultDiv.className = 'result success';
            resultDiv.innerHTML = `
                <h3>✅ Message Signed Successfully</h3>
                <p class="success-message">Signed with API secret: <strong>${result.name}</strong></p>

                <div class="signature-section">
                    <p><strong>🔐 Signature:</strong></p>
                    <div class="signature-box">
                        <code id="signApiKeySignature">${result.signature}</code>
                    </div>
                    <button class="btn-small" onclick="copyFromElement('signApiKeySignature', 'Signature')">
                        📋 Copy Signature
                    </button>
                </div>

                <div class="voting-details">
                    <p><strong>Details:</strong></p>
                    <ul>
                        <li>API Key Name: <code>${result.name}</code></li>
                        <li>Message: ${result.message}</li>
                        <li>Algorithm: ${result.algorithm}</li>
                        <li>Message Length: ${result.message_length} bytes</li>
                    </ul>
                </div>
            `;
        } else {
            resultDiv.className = 'result error';
            resultDiv.innerHTML = `
                <h3>❌ Failed to Sign</h3>
                <p>${result.error || 'Unknown error'}</p>
                <p class="help-text">
                    💡 <strong>Possible reasons:</strong><br>
                    • API key "${name}" doesn't exist<br>
                    • API key is not bound to this application<br>
                    • API key doesn't have an API secret stored (only key)
                </p>
            `;
        }
    } catch (error) {
        resultDiv.className = 'result error';
        resultDiv.innerHTML = `
            <h3>❌ Network Error</h3>
            <p>${error.message}</p>
        `;
    }
}

// Helper function to copy text to clipboard
function copyToClipboard(text, label) {
    // Try modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification(`${label} copied to clipboard!`, 'success');
        }).catch(err => {
            // Fallback to execCommand
            fallbackCopy(text, label);
        });
    } else {
        // Fallback for older browsers or insecure contexts
        fallbackCopy(text, label);
    }
}

// Fallback copy method using execCommand
function fallbackCopy(text, label) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.width = '2em';
    textarea.style.height = '2em';
    textarea.style.padding = '0';
    textarea.style.border = 'none';
    textarea.style.outline = 'none';
    textarea.style.boxShadow = 'none';
    textarea.style.background = 'transparent';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();

    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showNotification(`${label} copied to clipboard!`, 'success');
        } else {
            showNotification('Failed to copy to clipboard', 'error');
        }
    } catch (err) {
        showNotification('Failed to copy to clipboard', 'error');
    }

    document.body.removeChild(textarea);
}

// Helper function to copy text from element to clipboard
function copyFromElement(elementId, label) {
    const element = document.getElementById(elementId);
    if (!element) {
        showNotification('Element not found', 'error');
        return;
    }
    const text = element.textContent || element.innerText;
    copyToClipboard(text, label);
}

// Expose functions to global scope for onclick handlers
window.directSign = directSign;
window.directVerify = directVerify;
window.vote = vote;
window.verifySignature = verifySignature;
window.copyToClipboard = copyToClipboard;
window.copyFromElement = copyFromElement;
window.getAPIKey = getAPIKey;
window.signWithAPISecret = signWithAPISecret;
