// App State
let walletLoaded = false;
let pendingTransaction = null;

// DOM Elements
const elements = {
    // Views
    welcomeView: document.getElementById('welcome-view'),
    walletView: document.getElementById('wallet-view'),
    
    // Load Wallet
    privateKeyInput: document.getElementById('private_key'),
    toggleVisibilityBtn: document.getElementById('toggleVisibility'),
    loadButton: document.getElementById('loadButton'),
    generateButton: document.getElementById('generateButton'),
    loadingIndicator: document.getElementById('loadingIndicator'),
    errorMessage: document.getElementById('errorMessage'),
    successMessage: document.getElementById('successMessage'),
    
    // Wallet Info
    address: document.getElementById('address'),
    balance: document.getElementById('balance'),
    encrypted: document.getElementById('encrypted'),
    nonce: document.getElementById('nonce'),
    pendingTxs: document.getElementById('pending_txs'),
    totalBalance: document.getElementById('total-balance'),
    
    // Tabs
    sendTab: document.getElementById('send-tab'),
    privateTab: document.getElementById('private-tab'),
    encryptTab: document.getElementById('encrypt-tab'),
    claimTab: document.getElementById('claim-tab'),
    multiTab: document.getElementById('multi-tab'),
    
    // Form Views
    sendFormView: document.getElementById('send-form-view'),
    privateFormView: document.getElementById('private-form-view'),
    encryptFormView: document.getElementById('encrypt-form-view'),
    claimFormView: document.getElementById('claim-form-view'),
    multiFormView: document.getElementById('multi-form-view'),
    
    // Send Form
    sendForm: document.getElementById('send-form'),
    toAddress: document.getElementById('to_address'),
    amount: document.getElementById('amount'),
    message: document.getElementById('message'),
    sendButton: document.getElementById('send-button'),
    
    // Private Form
    privateTo: document.getElementById('private_to'),
    privateAmount: document.getElementById('private_amount'),
    privateSendButton: document.getElementById('private-send-button'),
    
    // Encrypt Form
    encryptAmount: document.getElementById('encrypt_amount'),
    encryptButton: document.getElementById('encrypt-button'),
    decryptAmount: document.getElementById('decrypt_amount'),
    decryptButton: document.getElementById('decrypt-button'),
    
    // Claim Form
    pendingTransfers: document.getElementById('pending-transfers'),
    noPendingTransfers: document.getElementById('no-pending-transfers'),
    
    // Multi-Send Form
    multiRecipients: document.getElementById('multi-recipients'),
    addRecipientBtn: document.getElementById('add-recipient'),
    multiSendButton: document.getElementById('multi-send-button'),
    
    // Transactions
    transactions: document.getElementById('transactions'),
    
    // Confirmation Modal
    confirmationModal: document.getElementById('confirmation-modal'),
    confirmAmount: document.getElementById('confirm-amount'),
    confirmAddress: document.getElementById('confirm-address'),
    confirmButton: document.getElementById('confirm-button'),
    confirmType: document.getElementById('confirm-type'),
    
    // Multi-Send Modal
    multiConfirmModal: document.getElementById('multi-confirm-modal'),
    multiConfirmTotal: document.getElementById('multi-confirm-total'),
    multiConfirmCount: document.getElementById('multi-confirm-count'),
    multiConfirmButton: document.getElementById('multi-confirm-button')
};

// Initialize the app
document.addEventListener('DOMContentLoaded', () => {
    elements.loadButton.addEventListener('click', loadWallet);
    elements.generateButton.addEventListener('click', generateNewWallet);
    elements.toggleVisibilityBtn.addEventListener('click', toggleKeyVisibility);
    elements.sendButton.addEventListener('click', sendTransaction);
    elements.privateSendButton.addEventListener('click', sendPrivateTransaction);
    elements.encryptButton.addEventListener('click', encryptBalance);
    elements.decryptButton.addEventListener('click', decryptBalance);
    elements.confirmButton.addEventListener('click', confirmTransaction);
    elements.addRecipientBtn.addEventListener('click', addRecipientField);
    elements.multiSendButton.addEventListener('click', prepareMultiSend);
    elements.multiConfirmButton.addEventListener('click', executeMultiSend);
    
    // Tab switching
    elements.sendTab.addEventListener('click', () => switchTab('send'));
    elements.privateTab.addEventListener('click', () => switchTab('private'));
    elements.encryptTab.addEventListener('click', () => switchTab('encrypt'));
    elements.claimTab.addEventListener('click', () => switchTab('claim'));
    elements.multiTab.addEventListener('click', () => switchTab('multi'));
    
    // Check for saved wallet
    const savedWallet = localStorage.getItem('octraWallet');
    if (savedWallet) {
        try {
            const walletData = JSON.parse(savedWallet);
            loadWalletFromStorage(walletData.privateKey);
        } catch (e) {
            console.error('Failed to load saved wallet', e);
            showError('Failed to load saved wallet');
        }
    }
});

// Toggle private key visibility
function toggleKeyVisibility() {
    if (elements.privateKeyInput.type === 'password') {
        elements.privateKeyInput.type = 'text';
        elements.toggleVisibilityBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>`;
    } else {
        elements.privateKeyInput.type = 'password';
        elements.toggleVisibilityBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
    }
}

// Switch tabs
function switchTab(tab) {
    // Reset all tabs
    elements.sendTab.classList.remove('border-indigo-500', 'text-indigo-600');
    elements.privateTab.classList.remove('border-indigo-500', 'text-indigo-600');
    elements.encryptTab.classList.remove('border-indigo-500', 'text-indigo-600');
    elements.claimTab.classList.remove('border-indigo-500', 'text-indigo-600');
    elements.multiTab.classList.remove('border-indigo-500', 'text-indigo-600');
    
    elements.sendFormView.classList.add('hidden');
    elements.privateFormView.classList.add('hidden');
    elements.encryptFormView.classList.add('hidden');
    elements.claimFormView.classList.add('hidden');
    elements.multiFormView.classList.add('hidden');
    
    // Activate selected tab
    if (tab === 'send') {
        elements.sendTab.classList.add('border-indigo-500', 'text-indigo-600');
        elements.sendFormView.classList.remove('hidden');
    } else if (tab === 'private') {
        elements.privateTab.classList.add('border-indigo-500', 'text-indigo-600');
        elements.privateFormView.classList.remove('hidden');
    } else if (tab === 'encrypt') {
        elements.encryptTab.classList.add('border-indigo-500', 'text-indigo-600');
        elements.encryptFormView.classList.remove('hidden');
    } else if (tab === 'claim') {
        elements.claimTab.classList.add('border-indigo-500', 'text-indigo-600');
        elements.claimFormView.classList.remove('hidden');
        fetchPendingTransfers();
    } else if (tab === 'multi') {
        elements.multiTab.classList.add('border-indigo-500', 'text-indigo-600');
        elements.multiFormView.classList.remove('hidden');
    }
}

// Add recipient field for multi-send
function addRecipientField() {
    const recipientDiv = document.createElement('div');
    recipientDiv.className = 'recipient-field flex space-x-4 mb-4';
    recipientDiv.innerHTML = `
        <input type="text" placeholder="Address" class="flex-1 p-2 border rounded" required>
        <input type="number" step="0.000001" placeholder="Amount" class="w-1/4 p-2 border rounded" required>
        <input type="text" placeholder="Message (optional)" class="flex-1 p-2 border rounded">
        <button type="button" class="remove-recipient bg-red-500 text-white px-3 rounded hover:bg-red-600">×</button>
    `;
    elements.multiRecipients.appendChild(recipientDiv);
    
    // Add event listener to remove button
    recipientDiv.querySelector('.remove-recipient').addEventListener('click', () => {
        recipientDiv.remove();
    });
}

// Prepare multi-send confirmation
function prepareMultiSend() {
    const recipientFields = elements.multiRecipients.querySelectorAll('.recipient-field');
    if (recipientFields.length === 0) {
        showError('Please add at least one recipient');
        return;
    }

    let totalAmount = 0;
    const recipients = [];
    
    recipientFields.forEach(field => {
        const inputs = field.querySelectorAll('input');
        const address = inputs[0].value.trim();
        const amount = parseFloat(inputs[1].value);
        const message = inputs[2].value.trim();
        
        if (!address || !amount || amount <= 0) {
            showError('Please fill all required fields for each recipient');
            return;
        }
        
        totalAmount += amount;
        recipients.push({
            to: address,
            amount: amount,
            message: message || undefined
        });
    });

    pendingTransaction = {
        type: 'multi',
        recipients: recipients,
        totalAmount: totalAmount
    };

    elements.multiConfirmTotal.textContent = totalAmount.toFixed(6);
    elements.multiConfirmCount.textContent = recipients.length;
    elements.multiConfirmModal.classList.remove('hidden');
}

// Execute multi-send transaction
async function executeMultiSend() {
    if (!pendingTransaction || pendingTransaction.type !== 'multi') return;
    
    showLoading();
    elements.multiConfirmModal.classList.add('hidden');
    
    try {
        const response = await fetch('/api/multi_send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                recipients: pendingTransaction.recipients
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Multi-send failed');
        }

        const data = await response.json();
        showSuccess(`Sent ${data.success_count} transactions! ${data.failed_count > 0 ? `(${data.failed_count} failed)` : ''}`);
        
        // Clear form
        elements.multiRecipients.innerHTML = '';
        addRecipientField(); // Add one empty field
        
        await fetchWallet();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
        pendingTransaction = null;
    }
}

// Load wallet from private key
async function loadWallet(event) {
    if (event) event.preventDefault();
    const privateKey = elements.privateKeyInput.value.trim();
    if (!privateKey) {
        showError('Please enter a base64 private key');
        return;
    }

    showLoading();
    try {
        const response = await fetch('/api/load_wallet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ private_key: privateKey })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to load wallet');
        }

        const data = await response.json();
        showSuccess(`Wallet loaded! Address: ${data.address}`);
        localStorage.setItem('octraWallet', JSON.stringify({ privateKey }));
        showWalletView();
        await fetchWallet();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
        elements.privateKeyInput.value = '';
    }
}

// Load wallet from storage
async function loadWalletFromStorage(privateKey) {
    showLoading();
    try {
        const response = await fetch('/api/load_wallet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ private_key: privateKey })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to load wallet');
        }

        const data = await response.json();
        showSuccess(`Wallet loaded! Address: ${data.address}`);
        showWalletView();
        await fetchWallet();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Generate new wallet
function generateNewWallet() {
    showError('Wallet generation feature is coming soon!');
}

// Fetch wallet data
async function fetchWallet() {
    if (!walletLoaded) return;
    showLoading();
    try {
        const response = await fetch('/api/wallet');
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to fetch wallet data');
        }

        const data = await response.json();
        updateWalletUI(data);
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Fetch pending transfers
async function fetchPendingTransfers() {
    if (!walletLoaded) return;
    showLoading();
    try {
        const response = await fetch('/api/pending_transfers');
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to fetch pending transfers');
        }

        const data = await response.json();
        renderPendingTransfers(data.transfers || []);
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Update wallet UI
function updateWalletUI(data) {
    elements.address.textContent = data.address;

    const balance = parseFloat(data.balance);
    elements.balance.textContent = isNaN(balance) ? '0.000000' : balance.toFixed(6);
    
    const encrypted = parseFloat(data.encrypted_balance.encrypted);
    elements.encrypted.textContent = isNaN(encrypted) ? '0.000000' : encrypted.toFixed(6);

    const total = parseFloat(data.encrypted_balance.total);
    elements.totalBalance.textContent = isNaN(total) ? '0.000000' : total.toFixed(6);

    elements.nonce.textContent = data.nonce ?? '0';
    renderTransactions(data.transactions || []);
}

// Render transactions
function renderTransactions(transactions) {
    elements.transactions.innerHTML = transactions.slice(0, 10).map(tx => {
        const amt = parseFloat(tx.amt);
        const amtStr = isNaN(amt) ? '0.000000' : amt.toFixed(6);
        
        let typeText, typeColor;
        if (tx.type === 'in') {
            typeText = 'Received';
            typeColor = 'text-green-600';
        } else if (tx.type === 'out') {
            typeText = 'Sent';
            typeColor = 'text-red-600';
        } else if (tx.type === 'private_in') {
            typeText = 'Private In';
            typeColor = 'text-purple-600';
        } else if (tx.type === 'private_out') {
            typeText = 'Private Out';
            typeColor = 'text-purple-600';
        } else if (tx.type === 'encrypt') {
            typeText = 'Encrypted';
            typeColor = 'text-indigo-600';
        } else if (tx.type === 'decrypt') {
            typeText = 'Decrypted';
            typeColor = 'text-indigo-600';
        } else {
            typeText = 'Unknown';
            typeColor = 'text-gray-600';
        }
        
        return `
        <tr class="${tx.type.includes('in') ? 'bg-green-50' : tx.type.includes('out') ? 'bg-red-50' : 'bg-indigo-50'}">
            <td class="p-3">${tx.time || '-'}</td>
            <td class="p-3 ${typeColor}">
                ${typeText}
            </td>
            <td class="p-3">${amtStr} OCT</td>
            <td class="p-3 break-all">${tx.to?.substring(0, 10) || tx.from?.substring(0, 10) || ''}...</td>
            <td class="p-3">${tx.epoch ? `Epoch ${tx.epoch}` : 'Pending'}</td>
        </tr>
        `;
    }).join('');
}

// Render pending transfers
function renderPendingTransfers(transfers) {
    if (transfers.length === 0) {
        elements.noPendingTransfers.classList.remove('hidden');
        elements.pendingTransfers.innerHTML = '';
        return;
    }
    
    elements.noPendingTransfers.classList.add('hidden');
    elements.pendingTransfers.innerHTML = transfers.map((transfer, index) => {
        const amount = transfer.amount ? transfer.amount.toFixed(6) : 'Unknown';
        return `
        <div class="p-3 border-b border-gray-200">
            <div class="flex justify-between items-center">
                <div>
                    <p class="font-medium">From: ${transfer.sender.substring(0, 10)}...</p>
                    <p class="text-gray-600">Amount: ${amount} OCT</p>
                    <p class="text-sm text-gray-500">ID: ${transfer.id}</p>
                </div>
                <button onclick="claimTransfer('${transfer.id}')" class="bg-purple-600 text-white px-3 py-1 rounded-lg hover:bg-purple-700">Claim</button>
            </div>
        </div>
        `;
    }).join('');
}

// Send transaction
async function sendTransaction(event) {
    event.preventDefault();
    const to = elements.toAddress.value.trim();
    const amount = parseFloat(elements.amount.value);
    const message = elements.message.value.trim();
    
    if (!to || !amount || amount <= 0) {
        showError('Please enter a valid address and amount');
        return;
    }

    pendingTransaction = { to, amount, message, type: 'public' };
    elements.confirmAmount.textContent = amount.toFixed(6);
    elements.confirmAddress.textContent = to.substring(0, 10) + '...';
    elements.confirmType.textContent = 'Public Transaction';
    elements.confirmationModal.classList.remove('hidden');
}

// Send private transaction
async function sendPrivateTransaction() {
    const to = elements.privateTo.value.trim();
    const amount = parseFloat(elements.privateAmount.value);
    if (!to || !amount || amount <= 0) {
        showError('Please enter a valid address and amount');
        return;
    }

    pendingTransaction = { to, amount, type: 'private' };
    elements.confirmAmount.textContent = amount.toFixed(6);
    elements.confirmAddress.textContent = to.substring(0, 10) + '...';
    elements.confirmType.textContent = 'Private Transfer';
    elements.confirmationModal.classList.remove('hidden');
}

// Encrypt balance
async function encryptBalance() {
    const amount = parseFloat(elements.encryptAmount.value);
    if (!amount || amount <= 0) {
        showError('Please enter a valid amount');
        return;
    }

    showLoading();
    try {
        const response = await fetch('/api/encrypt_balance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Encryption failed');
        }

        const data = await response.json();
        showSuccess(`Balance encrypted! TX: ${data.tx_hash}`);
        await fetchWallet();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Decrypt balance
async function decryptBalance() {
    const amount = parseFloat(elements.decryptAmount.value);
    if (!amount || amount <= 0) {
        showError('Please enter a valid amount');
        return;
    }

    showLoading();
    try {
        const response = await fetch('/api/decrypt_balance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Decryption failed');
        }

        const data = await response.json();
        showSuccess(`Balance decrypted! TX: ${data.tx_hash}`);
        await fetchWallet();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Claim transfer
async function claimTransfer(transferId) {
    showLoading();
    try {
        const response = await fetch('/api/claim_transfer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ transfer_id: transferId })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Claim failed');
        }

        const data = await response.json();
        showSuccess(`Claimed ${data.amount} OCT!`);
        await fetchWallet();
        fetchPendingTransfers();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Confirm transaction
async function confirmTransaction() {
    if (!pendingTransaction) return;
    showLoading();
    try {
        let response;
        if (pendingTransaction.type === 'public') {
            response = await fetch('/api/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(pendingTransaction)
            });
        } else if (pendingTransaction.type === 'private') {
            response = await fetch('/api/private_transfer', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(pendingTransaction)
            });
        }

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Transaction failed');
        }

        const data = await response.json();
        showSuccess(`Transaction sent! ID: ${data.tx_hash || data.transfer_id}`);
        elements.toAddress.value = '';
        elements.amount.value = '';
        elements.message.value = '';
        elements.privateTo.value = '';
        elements.privateAmount.value = '';
        await fetchWallet();
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
        elements.confirmationModal.classList.add('hidden');
        pendingTransaction = null;
    }
}

// Cancel transaction
function cancelTransaction() {
    elements.confirmationModal.classList.add('hidden');
    pendingTransaction = null;
}

// Refresh wallet
async function refreshWallet() {
    await fetchWallet();
}

// Reset wallet
function resetWallet() {
    localStorage.removeItem('octraWallet');
    walletLoaded = false;
    elements.walletView.classList.add('hidden');
    elements.welcomeView.classList.remove('hidden');
}

// Copy to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;
    navigator.clipboard.writeText(text)
        .then(() => showSuccess('Copied to clipboard!'))
        .catch(err => showError('Failed to copy'));
}

// UI Helpers
function showLoading() {
    elements.loadingIndicator.classList.remove('hidden');
    if (elements.loadButton) elements.loadButton.disabled = true;
    if (elements.sendButton) elements.sendButton.disabled = true;
    if (elements.privateSendButton) elements.privateSendButton.disabled = true;
    if (elements.encryptButton) elements.encryptButton.disabled = true;
    if (elements.decryptButton) elements.decryptButton.disabled = true;
    if (elements.confirmButton) elements.confirmButton.disabled = true;
    if (elements.multiSendButton) elements.multiSendButton.disabled = true;
    if (elements.multiConfirmButton) elements.multiConfirmButton.disabled = true;
}

function hideLoading() {
    elements.loadingIndicator.classList.add('hidden');
    if (elements.loadButton) elements.loadButton.disabled = false;
    if (elements.sendButton) elements.sendButton.disabled = false;
    if (elements.privateSendButton) elements.privateSendButton.disabled = false;
    if (elements.encryptButton) elements.encryptButton.disabled = false;
    if (elements.decryptButton) elements.decryptButton.disabled = false;
    if (elements.confirmButton) elements.confirmButton.disabled = false;
    if (elements.multiSendButton) elements.multiSendButton.disabled = false;
    if (elements.multiConfirmButton) elements.multiConfirmButton.disabled = false;
}

function showError(message) {
    elements.errorMessage.textContent = message;
    elements.errorMessage.classList.remove('hidden');
    setTimeout(() => elements.errorMessage.classList.add('hidden'), 5000);
}

function showSuccess(message) {
    elements.successMessage.textContent = message;
    elements.successMessage.classList.remove('hidden');
    setTimeout(() => elements.successMessage.classList.add('hidden'), 5000);
}

function showWalletView() {
    elements.welcomeView.classList.add('hidden');
    elements.walletView.classList.remove('hidden');
    walletLoaded = true;
    // Add initial recipient field for multi-send
    addRecipientField();
}