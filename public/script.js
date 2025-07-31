// ---------- Utilities ----------
function getCurrentUser() {
    return localStorage.getItem('userEmail') || 'anonymous';
}

function sendLog(eventType, details = '') {
    const user = getCurrentUser();
    fetch('/api/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eventType, details, user })
    }).catch(err => console.error('Logging error:', err));
}

// ---------- Email & Phone Validators ----------
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
    if (!phone) return true;
    const cleaned = phone.replace(/[\s\-\(\)]+/g, '');
    return /^[\+]?[0-9]{7,15}$/.test(cleaned);
}

// ---------- Password Validator ----------
function isValidPassword(password) {
    return password && password.length >= 6;
}

// ---------- Name Validator ----------
function isValidName(name) {
    return name && name.trim().length >= 2;
}

// ---------- Show/Hide Password Toggle ----------
function addPasswordToggle(passwordInput) {
    const wrapper = document.createElement('div');
    wrapper.style.position = 'relative';
    passwordInput.parentNode.insertBefore(wrapper, passwordInput);
    wrapper.appendChild(passwordInput);

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.innerHTML = '👁️';
    toggleBtn.style.position = 'absolute';
    toggleBtn.style.right = '10px';
    toggleBtn.style.top = '50%';
    toggleBtn.style.transform = 'translateY(-50%)';
    toggleBtn.style.background = 'none';
    toggleBtn.style.border = 'none';
    toggleBtn.style.cursor = 'pointer';
    toggleBtn.style.fontSize = '16px';

    toggleBtn.addEventListener('click', () => {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.innerHTML = '🙈';
        } else {
            passwordInput.type = 'password';
            toggleBtn.innerHTML = '👁️';
        }
    });

    wrapper.appendChild(toggleBtn);
}

// ---------- ADMIN DASHBOARD FUNCTIONS ----------
class AdminDashboard {
    constructor() {
        this.logs = [];
        this.currentPage = 1;
        this.itemsPerPage = 20;
        this.filteredLogs = [];
        this.socket = null;
        this.chart = null;
        this.isDarkMode = localStorage.getItem('adminDarkMode') === 'true';
        
        this.init();
    }

    init() {
        this.checkAdminAuth();
        this.initializeElements();
        this.setupEventListeners();
        this.setupSocketConnection();
        this.loadLogs();
        this.initializeChart();
        this.applyDarkMode();
    }

    checkAdminAuth() {
        const adminToken = localStorage.getItem('adminToken');
        const userEmail = localStorage.getItem('userEmail');
        
        if (!adminToken || !userEmail) {
            alert('Admin access required. Please log in as admin.');
            window.location.href = 'login.html';
            return;
        }
    }

    initializeElements() {
        this.elements = {
            // Status and info
            connectionStatus: document.getElementById('connectionStatus'),
            statusText: document.getElementById('statusText'),
            adminInfo: document.getElementById('adminInfo'),
            
            // Stats cards
            totalLogs: document.getElementById('totalLogs'),
            successfulLogins: document.getElementById('successfulLogins'),
            failedLogins: document.getElementById('failedLogins'),
            contactMessages: document.getElementById('contactMessages'),
            
            // Controls
            filterType: document.getElementById('filterType'),
            searchInput: document.getElementById('searchInput'),
            refreshBtn: document.getElementById('refreshBtn'),
            exportCSVBtn: document.getElementById('exportCSVBtn'),
            exportXLSXBtn: document.getElementById('exportXLSXBtn'),
            exportPDFBtn: document.getElementById('exportPDFBtn'),
            darkModeToggle: document.getElementById('darkModeToggle'),
            
            // Table and pagination
            logTableBody: document.getElementById('logTableBody'),
            prevPageBtn: document.getElementById('prevPageBtn'),
            nextPageBtn: document.getElementById('nextPageBtn'),
            pageInfo: document.getElementById('pageInfo'),
            
            // Chart
            activityChart: document.getElementById('activityChart'),
            
            // Logout
            logoutBtn: document.getElementById('logoutBtn')
        };

        // Display admin info
        const adminEmail = localStorage.getItem('userEmail');
        if (this.elements.adminInfo && adminEmail) {
            this.elements.adminInfo.textContent = `Admin: ${adminEmail}`;
        }
    }

    setupEventListeners() {
        // Filter and search
        if (this.elements.filterType) {
            this.elements.filterType.addEventListener('change', () => this.filterLogs());
        }
        
        if (this.elements.searchInput) {
            this.elements.searchInput.addEventListener('input', this.debounce(() => this.filterLogs(), 300));
        }

        // Refresh button
        if (this.elements.refreshBtn) {
            this.elements.refreshBtn.addEventListener('click', () => this.loadLogs());
        }

        // Export buttons
        if (this.elements.exportCSVBtn) {
            this.elements.exportCSVBtn.addEventListener('click', () => this.exportToCSV());
        }
        if (this.elements.exportXLSXBtn) {
            this.elements.exportXLSXBtn.addEventListener('click', () => this.exportToExcel());
        }
        if (this.elements.exportPDFBtn) {
            this.elements.exportPDFBtn.addEventListener('click', () => this.exportToPDF());
        }

        // Dark mode toggle
        if (this.elements.darkModeToggle) {
            this.elements.darkModeToggle.addEventListener('click', () => this.toggleDarkMode());
        }

        // Pagination
        if (this.elements.prevPageBtn) {
            this.elements.prevPageBtn.addEventListener('click', () => this.previousPage());
        }
        if (this.elements.nextPageBtn) {
            this.elements.nextPageBtn.addEventListener('click', () => this.nextPage());
        }

        // Logout
        if (this.elements.logoutBtn) {
            this.elements.logoutBtn.addEventListener('click', () => this.logout());
        }
    }

    setupSocketConnection() {
        if (typeof io !== 'undefined') {
            try {
                this.socket = io();
                
                this.socket.on('connect', () => {
                    this.updateConnectionStatus('Connected', 'success');
                    console.log('Admin dashboard connected to server');
                });

                this.socket.on('disconnect', () => {
                    this.updateConnectionStatus('Disconnected', 'error');
                    console.log('Admin dashboard disconnected from server');
                });

                this.socket.on('new_log', (logEntry) => {
                    this.addNewLog(logEntry);
                });

                this.socket.on('connect_error', () => {
                    this.updateConnectionStatus('Connection Error', 'error');
                });

            } catch (error) {
                console.log('Socket.IO not available or connection failed');
                this.updateConnectionStatus('Socket.IO not available', 'warning');
            }
        }
    }

    updateConnectionStatus(message, type) {
        if (this.elements.connectionStatus && this.elements.statusText) {
            this.elements.statusText.textContent = message;
            this.elements.connectionStatus.className = `mb-4 p-3 rounded text-center ${
                type === 'success' ? 'bg-green-100 text-green-800' :
                type === 'error' ? 'bg-red-100 text-red-800' :
                'bg-yellow-100 text-yellow-800'
            }`;
            this.elements.connectionStatus.classList.remove('hidden');
        }
    }

    async loadLogs() {
    try {
        const response = await fetch('/admin/logs', { // <-- FIXED HERE
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`,
                'Content-Type': 'application/json'
            }
        });
        // ...rest of your code...

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            this.logs = Array.isArray(data) ? data : (data.logs || []);
            this.filterLogs();
            this.updateStats();
            this.updateChart();
            
            sendLog('admin_logs_loaded', `Loaded ${this.logs.length} log entries`);
        } catch (error) {
            console.error('Error loading logs:', error);
            this.logs = this.generateSampleLogs(); // Fallback to sample data
            this.filterLogs();
            this.updateStats();
            this.updateChart();
        }
    }

    generateSampleLogs() {
        const sampleLogs = [];
        const eventTypes = ['login_success', 'login_failed', 'signup_success', 'contact_message', 'page_visit'];
        const users = ['john@example.com', 'jane@example.com', 'admin@nexaeast.com', 'user@test.com'];
        
        for (let i = 0; i < 50; i++) {
            const now = new Date();
            const randomHours = Math.floor(Math.random() * 24 * 7); // Last 7 days
            const timestamp = new Date(now.getTime() - randomHours * 60 * 60 * 1000);
            
            const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
            const user = users[Math.floor(Math.random() * users.length)];
            
            sampleLogs.push({
                id: i + 1,
                timestamp: timestamp.toISOString(),
                eventType,
                details: this.generateSampleDetails(eventType),
                user,
                ip: `192.168.1.${Math.floor(Math.random() * 255)}`
            });
        }
        
        return sampleLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    generateSampleDetails(eventType) {
        const details = {
            'login_success': 'User logged in successfully',
            'login_failed': 'Invalid credentials provided',
            'signup_success': 'New user account created',
            'contact_message': 'Contact form submitted',
            'page_visit': 'User visited homepage'
        };
        return details[eventType] || 'System event';
    }

    filterLogs() {
        const filterType = this.elements.filterType?.value || 'all';
        const searchTerm = this.elements.searchInput?.value.toLowerCase() || '';

        this.filteredLogs = this.logs.filter(log => {
            const matchesType = filterType === 'all' || log.eventType === filterType;
            const matchesSearch = !searchTerm || 
                log.eventType.toLowerCase().includes(searchTerm) ||
                log.details.toLowerCase().includes(searchTerm) ||
                log.user.toLowerCase().includes(searchTerm);
            
            return matchesType && matchesSearch;
        });

        this.currentPage = 1;
        this.renderLogs();
        this.updatePagination();
    }

    renderLogs() {
        if (!this.elements.logTableBody) return;

        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;
        const logsToShow = this.filteredLogs.slice(startIndex, endIndex);

        this.elements.logTableBody.innerHTML = '';

        if (logsToShow.length === 0) {
            this.elements.logTableBody.innerHTML = `
                <tr>
                    <td colspan="4" class="px-4 py-8 text-center text-gray-500">
                        No logs found matching your criteria
                    </td>
                </tr>
            `;
            return;
        }

        logsToShow.forEach(log => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50 dark:hover:bg-gray-700';
            
            const timestamp = new Date(log.timestamp);
            const formattedTime = timestamp.toLocaleString();
            
            row.innerHTML = `
                <td class="px-4 py-2 text-sm">${formattedTime}</td>
                <td class="px-4 py-2">
                    <span class="px-2 py-1 text-xs rounded-full ${this.getEventTypeColor(log.eventType)}">
                        ${this.formatEventType(log.eventType)}
                    </span>
                </td>
                <td class="px-4 py-2 text-sm">${this.escapeHtml(log.details)}</td>
                <td class="px-4 py-2 text-sm">${this.escapeHtml(log.user)}</td>
            `;
            
            this.elements.logTableBody.appendChild(row);
        });
    }

    getEventTypeColor(eventType) {
        const colors = {
            'login_success': 'bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100',
            'login_failed': 'bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100',
            'signup_success': 'bg-blue-100 text-blue-800 dark:bg-blue-800 dark:text-blue-100',
            'signup_failed': 'bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100',
            'contact_message': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-800 dark:text-yellow-100',
            'admin_reset': 'bg-purple-100 text-purple-800 dark:bg-purple-800 dark:text-purple-100',
            'forgot_password_request': 'bg-orange-100 text-orange-800 dark:bg-orange-800 dark:text-orange-100'
        };
        return colors[eventType] || 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100';
    }

    formatEventType(eventType) {
        return eventType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateStats() {
        const stats = {
            total: this.logs.length,
            successful: this.logs.filter(log => log.eventType === 'login_success').length,
            failed: this.logs.filter(log => log.eventType === 'login_failed').length,
            contact: this.logs.filter(log => log.eventType === 'contact_message').length
        };

        if (this.elements.totalLogs) this.elements.totalLogs.textContent = stats.total;
        if (this.elements.successfulLogins) this.elements.successfulLogins.textContent = stats.successful;
        if (this.elements.failedLogins) this.elements.failedLogins.textContent = stats.failed;
        if (this.elements.contactMessages) this.elements.contactMessages.textContent = stats.contact;
    }

    initializeChart() {
        if (!this.elements.activityChart) return;
        if (typeof Chart === 'undefined') {
            console.error('Chart.js library is not loaded.');
            this.showNotification('Chart.js library is not loaded.', 'error');
            return;
        }

        const ctx = this.elements.activityChart.getContext('2d');
        
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Activity',
                    data: [],
                    borderColor: 'rgb(59, 130, 246)',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    updateChart() {
        if (!this.chart) return;

        // Group logs by hour for the last 24 hours
        const now = new Date();
        const last24Hours = [];
        const counts = [];

        for (let i = 23; i >= 0; i--) {
            const hour = new Date(now.getTime() - i * 60 * 60 * 1000);
            const hourLabel = hour.getHours().toString().padStart(2, '0') + ':00';
            last24Hours.push(hourLabel);

            const hourCount = this.logs.filter(log => {
                const logTime = new Date(log.timestamp);
                return logTime.getHours() === hour.getHours() &&
                       logTime.getDate() === hour.getDate();
            }).length;

            counts.push(hourCount);
        }

        this.chart.data.labels = last24Hours;
        this.chart.data.datasets[0].data = counts;
        this.chart.update();
    }

    addNewLog(logEntry) {
        this.logs.unshift(logEntry);
        this.filterLogs();
        this.updateStats();
        this.updateChart();
        
        // Show notification for new log
        this.showNotification('New activity logged', 'info');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded shadow-lg z-50 ${
            type === 'success' ? 'bg-green-500' :
            type === 'error' ? 'bg-red-500' :
            type === 'warning' ? 'bg-yellow-500' :
            'bg-blue-500'
        } text-white`;
        
        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    updatePagination() {
        const totalPages = Math.ceil(this.filteredLogs.length / this.itemsPerPage);
        
        if (this.elements.pageInfo) {
            this.elements.pageInfo.textContent = `Page ${this.currentPage} of ${totalPages} (${this.filteredLogs.length} total)`;
        }
        
        if (this.elements.prevPageBtn) {
            this.elements.prevPageBtn.disabled = this.currentPage <= 1;
        }
        
        if (this.elements.nextPageBtn) {
            this.elements.nextPageBtn.disabled = this.currentPage >= totalPages;
        }
    }

    previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.renderLogs();
            this.updatePagination();
        }
    }

    nextPage() {
        const totalPages = Math.ceil(this.filteredLogs.length / this.itemsPerPage);
        if (this.currentPage < totalPages) {
            this.currentPage++;
            this.renderLogs();
            this.updatePagination();
        }
    }

    toggleDarkMode() {
        this.isDarkMode = !this.isDarkMode;
        localStorage.setItem('adminDarkMode', this.isDarkMode.toString());
        this.applyDarkMode();
        sendLog('admin_dark_mode_toggle', `Dark mode: ${this.isDarkMode}`);
    }

    applyDarkMode() {
        if (this.isDarkMode) {
            document.body.classList.add('dark');
            if (this.elements.darkModeToggle) {
                this.elements.darkModeToggle.textContent = 'Light Mode';
                this.elements.darkModeToggle.className = 'px-3 py-1 rounded bg-gray-600 hover:bg-gray-700 text-white';
            }
        } else {
            document.body.classList.remove('dark');
            if (this.elements.darkModeToggle) {
                this.elements.darkModeToggle.textContent = 'Dark Mode';
                this.elements.darkModeToggle.className = 'px-3 py-1 rounded bg-gray-300 hover:bg-gray-400 text-gray-900';
            }
        }
    }

    exportToCSV() {
        const csvContent = this.generateCSVContent();
        this.downloadFile(csvContent, 'admin-logs.csv', 'text/csv');
        sendLog('admin_export_csv', `Exported ${this.filteredLogs.length} logs to CSV`);
    }

    exportToExcel() {
        if (typeof XLSX === 'undefined') {
            alert('Excel export not available. XLSX library not loaded.');
            this.showNotification('Excel export not available. XLSX library not loaded.', 'error');
            return;
        }

        const ws = XLSX.utils.json_to_sheet(this.filteredLogs.map(log => ({
            Time: new Date(log.timestamp).toLocaleString(),
            Type: this.formatEventType(log.eventType),
            Details: log.details,
            User: log.user
        })));

        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'Logs');
        XLSX.writeFile(wb, 'admin-logs.xlsx');
        
        sendLog('admin_export_excel', `Exported ${this.filteredLogs.length} logs to Excel`);
    }

    exportToPDF() {
        if (typeof jsPDF === 'undefined' || typeof window.jspdf === 'undefined' || typeof window.jspdf.jsPDF === 'undefined') {
            alert('PDF export not available. jsPDF library not loaded.');
            this.showNotification('PDF export not available. jsPDF library not loaded.', 'error');
            return;
        }
        if (typeof window.jspdf.autoTable === 'undefined' && typeof window.jspdf.jsPDF.prototype.autoTable === 'undefined') {
            alert('PDF export not available. jsPDF-AutoTable plugin not loaded.');
            this.showNotification('PDF export not available. jsPDF-AutoTable plugin not loaded.', 'error');
            return;
        }

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        doc.setFontSize(18);
        doc.text('NEXA East Hub - Admin Logs', 14, 22);
        
        doc.setFontSize(12);
        doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 32);
        doc.text(`Total Records: ${this.filteredLogs.length}`, 14, 40);

        const tableData = this.filteredLogs.slice(0, 100).map(log => [
            new Date(log.timestamp).toLocaleString(),
            this.formatEventType(log.eventType),
            log.details.substring(0, 50) + (log.details.length > 50 ? '...' : ''),
            log.user
        ]);

        doc.autoTable({
            head: [['Time', 'Type', 'Details', 'User']],
            body: tableData,
            startY: 50,
            styles: { fontSize: 8 }
        });

        if (this.filteredLogs.length > 100) {
            doc.text('Note: Only first 100 records shown due to PDF limitations', 14, doc.lastAutoTable.finalY + 10);
        }

        doc.save('admin-logs.pdf');
        sendLog('admin_export_pdf', `Exported ${Math.min(this.filteredLogs.length, 100)} logs to PDF`);
    }

    generateCSVContent() {
        const headers = ['Time', 'Type', 'Details', 'User'];
        const csvRows = [headers.join(',')];

        this.filteredLogs.forEach(log => {
            const row = [
                `"${new Date(log.timestamp).toLocaleString()}"`,
                `"${this.formatEventType(log.eventType)}"`,
                `"${log.details.replace(/"/g, '""')}"`,
                `"${log.user}"`
            ];
            csvRows.push(row.join(','));
        });

        return csvRows.join('\n');
    }

    downloadFile(content, filename, contentType) {
        const blob = new Blob([content], { type: contentType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    logout() {
        if (confirm('Are you sure you want to logout?')) {
            localStorage.removeItem('userEmail');
            localStorage.removeItem('userName');
            localStorage.removeItem('authToken');
            localStorage.removeItem('adminToken');
            sendLog('admin_logout', 'Admin logged out');
            alert('Logged out successfully.');
            window.location.href = 'index.html';
        }
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Add password toggles to all password inputs
    document.querySelectorAll('input[type="password"]').forEach(input => {
        addPasswordToggle(input);
    });

    // Initialize Admin Dashboard if on admin page
    if (window.location.pathname.includes('admin-dashboard.html') || 
        document.getElementById('logTable')) {
        window.adminDashboard = new AdminDashboard();
    }

    // ---------- Forgot Password Form ----------
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', async e => {
            e.preventDefault();
            const email = forgotPasswordForm.email.value.trim();
            const submitBtn = forgotPasswordForm.querySelector('button[type="submit"]');

            if (!email) {
                alert('Please enter your registered email.');
                return;
            }

            if (!isValidEmail(email)) {
                alert('Please enter a valid email address.');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Sending reset link...';

            try {
                const res = await fetch('/api/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    alert('✅ If this email is registered, a password reset link has been sent.');
                    sendLog('forgot_password_request', `Password reset requested for ${email}`);
                    forgotPasswordForm.reset();
                } else {
                    alert(`❌ ${data.error || 'Error sending reset link.'}`);
                    sendLog('forgot_password_failed', data.error || 'Unknown error');
                }
            } catch (error) {
                alert('❌ Network error. Please try again later.');
                console.error('Forgot password error:', error);
                sendLog('forgot_password_error', error.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Reset Password';
            }
        });
    }

    // ---------- Login Form ----------
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async e => {
            e.preventDefault();
            const email = e.target.email.value.trim();
            const password = e.target.password.value.trim();
            const submitBtn = loginForm.querySelector('button[type="submit"]');

            if (!email || !password) {
                alert('Please enter your email and password.');
                return;
            }

            if (!isValidEmail(email)) {
                alert('Please enter a valid email address.');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Logging in...';

            try {
                const res = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();

                if (data.success) {
                    alert(`✅ Login successful! Welcome, ${data.name || 'User'}.`);
                    localStorage.setItem('userEmail', email);
                    localStorage.setItem('userName', data.name || 'User');
                    if (data.token) {
                        localStorage.setItem('authToken', data.token);
                    }
                    if (data.role === 'admin') {
                        localStorage.setItem('adminToken', data.token);
                    }
                    sendLog('login_success', `Logged in as ${email}`);

                    window.location.href = data.role === 'admin' ? 'admin-dashboard.html' : 'user-dashboard.html';
                } else {
                    alert('❌ Incorrect email or password.');
                    sendLog('login_failed', `Login failed for: ${email}`);
                }
            } catch (err) {
                alert('❌ An error occurred during login.');
                console.error('Login error:', err);
                sendLog('login_error', err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Login';
            }
        });
    }

    // ---------- Signup Form ----------
    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        signupForm.addEventListener('submit', async e => {
            e.preventDefault();

            const formData = new FormData(signupForm);
            const name = formData.get('name').trim();
            const email = formData.get('email').trim();
            const password = formData.get('password').trim();
            const submitBtn = signupForm.querySelector('button[type="submit"]');

            // Validation
            const errors = [];
            if (!isValidName(name)) errors.push('Please enter a valid name (at least 2 characters).');
            if (!isValidEmail(email)) errors.push('Please enter a valid email address.');
            if (!isValidPassword(password)) errors.push('Password must be at least 6 characters long.');

            if (errors.length > 0) {
                alert('Please fix the following issues:\n' + errors.join('\n'));
                sendLog('signup_validation_error', errors.join('; '));
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing up...';

            try {
                const response = await fetch('/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    alert('✅ User registered successfully! Please log in.');
                    sendLog('signup_success', `New user: ${email}`);
                    signupForm.reset();
                    window.location.href = 'login.html';
                } else if (response.status === 409) {
                    alert('❌ Email already exists. Try logging in.');
                    sendLog('signup_failed', `Email exists: ${email}`);
                } else {
                    alert(`❌ Error: ${data.error || 'Unknown error'}`);
                    sendLog('signup_failed', `Error: ${data.error || 'Unknown'}`);
                }
            } catch (error) {
                alert('❌ Network error. Try again later.');
                console.error('Signup error:', error);
                sendLog('signup_error', error.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Sign Up';
            }
        });
    }

    // ---------- Contact Form ----------
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', async e => {
            e.preventDefault();
            const form = e.target;
            const name = form.name.value.trim();
            const email = form.email.value.trim();
            const phone = form.phone.value.trim();
            const service = form.service.value;
            const message = form.message.value.trim();
            const submitBtn = form.querySelector('button[type="submit"]');

            const errors = [];
            if (!name || name.length < 2) errors.push('Please enter your name (at least 2 characters).');
            if (!email || !isValidEmail(email)) errors.push('Please enter a valid email address.');
            if (!isValidPhone(phone)) errors.push('Please enter a valid phone number or leave blank.');
            if (!service) errors.push('Please select a service.');
            if (!message || message.length < 10) errors.push('Please enter a message (at least 10 characters).');

            if (errors.length) {
                alert('Please fix the following:\n' + errors.join('\n'));
                sendLog('contact_form_validation_error', errors.join('; '));
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Sending...';

            try {
                const res = await fetch('/contact', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, phone, service, message })
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    alert('✅ Thank you! Your message has been sent.');
                    sendLog('contact_form_submission_success', `From ${name} (${email}), service: ${service}`);
                    form.reset();
                } else {
                    alert('❌ Error sending message. Please try again.');
                    sendLog('contact_form_submission_failed', data.error || 'Unknown error');
                }
            } catch (error) {
                alert('❌ Network error. Please try again later.');
                console.error('Contact form error:', error);
                sendLog('contact_form_submission_error', error.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Send Message';
            }
        });
    }

    // ---------- Logout Functionality ----------
    const logoutBtns = document.querySelectorAll('.logout-btn, #logoutBtn');
    logoutBtns.forEach(btn => {
        if (btn.textContent.toLowerCase().includes('logout')) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                localStorage.removeItem('userEmail');
                localStorage.removeItem('userName');
                localStorage.removeItem('authToken');
                localStorage.removeItem('adminToken');
                sendLog('logout', 'User logged out');
                alert('Logged out successfully.');
                window.location.href = 'index.html';
            });
        }
    });

    // ---------- Auth Protection ----------
    function checkAuth() {
        const currentPage = window.location.pathname.split('/').pop();
        const protectedPages = ['user-dashboard.html', 'admin-dashboard.html', 'my-orders.html'];
        const authToken = localStorage.getItem('authToken');
        const userEmail = localStorage.getItem('userEmail');

        if (protectedPages.includes(currentPage) && (!authToken || !userEmail)) {
            alert('Please log in to access this page.');
            window.location.href = 'login.html';
            return false;
        }
        return true;
    }

    // Check auth on protected pages
    checkAuth();

    // ---------- Update User Info Display ----------
    const userInfoElements = document.querySelectorAll('.user-name, .welcome-msg');
    const userName = localStorage.getItem('userName');
    if (userName && userInfoElements.length > 0) {
        userInfoElements.forEach(el => {
            if (el.classList.contains('welcome-msg')) {
                el.textContent = `Welcome back, ${userName}! This is your personal dashboard.`;
            } else {
                el.textContent = userName;
            }
        });
    }

    // ---------- Smooth Scroll ----------
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', e => {
            e.preventDefault();
            const target = document.querySelector(anchor.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
                sendLog('smooth_scroll', `Scrolled to ${anchor.getAttribute('href')}`);
            }
        });
    });

    // ---------- Mobile Menu ----------
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const navMenu = document.querySelector('.nav-menu');
    if (mobileMenuToggle && navMenu) {
        mobileMenuToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            sendLog('mobile_menu_toggle', `Menu toggled: ${navMenu.classList.contains('active')}`);
        });
    }

    // ---------- Scroll-to-top ----------
    const scrollToTopBtn = document.querySelector('.scroll-to-top');
    if (scrollToTopBtn) {
        scrollToTopBtn.addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
            sendLog('scroll_to_top', 'Scroll to top clicked');
        });

        // Show/hide scroll to top button
        window.addEventListener('scroll', () => {
            if (window.pageYOffset > 100) {
                scrollToTopBtn.style.display = 'block';
            } else {
                scrollToTopBtn.style.display = 'none';
            }
        });
    }

    // ---------- Lazy Load Images ----------
    const lazyImages = document.querySelectorAll('img[data-src]');
    if (lazyImages.length > 0) {
        const imageObserver = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imageObserver.unobserve(img);
                    sendLog('lazy_image_loaded', `Image loaded: ${img.dataset.src}`);
                }
            });
        });
        lazyImages.forEach(img => imageObserver.observe(img));
    }

    // ---------- Form Auto-save (Draft) ----------
    const formsToSave = ['contactForm', 'signup-form'];
    formsToSave.forEach(formId => {
        const form = document.getElementById(formId);
        if (form) {
            // Load saved draft
            const savedData = localStorage.getItem(`draft_${formId}`);
            if (savedData) {
                try {
                    const data = JSON.parse(savedData);
                    Object.keys(data).forEach(key => {
                        const input = form.querySelector(`[name="${key}"]`);
                        if (input && input.type !== 'password') {
                            input.value = data[key];
                        }
                    });
                } catch (e) {
                    console.error('Error loading draft:', e);
                }
            }

            // Save draft on input
            form.addEventListener('input', () => {
                const formData = new FormData(form);
                const data = {};
                for (let [key, value] of formData.entries()) {
                    if (key !== 'password') { // Don't save passwords
                        data[key] = value;
                    }
                }
                localStorage.setItem(`draft_${formId}`, JSON.stringify(data));
            });

            // Clear draft on successful submission
            form.addEventListener('submit', () => {
                setTimeout(() => {
                    localStorage.removeItem(`draft_${formId}`);
                }, 1000); // Clear draft after successful submission
            });
        }
    });

    // ---------- Page Visit Tracking ----------
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    sendLog('page_visit', `Visited page: ${currentPage}`);

    // ---------- Session Duration Tracking ----------
    const sessionStart = Date.now();
    window.addEventListener('beforeunload', () => {
        const sessionDuration = Date.now() - sessionStart;
        sendLog('session_end', `Session duration: ${Math.round(sessionDuration / 1000)}s`);
    });

    // ---------- Error Handling ----------
    window.addEventListener('error', (e) => {
        sendLog('javascript_error', `${e.message} at ${e.filename}:${e.lineno}`);
    });

    // ---------- Copy to Clipboard Helper ----------
    window.copyToClipboard = async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            sendLog('clipboard_copy', 'Text copied to clipboard');
            return true;
        } catch (err) {
            console.error('Failed to copy:', err);
            sendLog('clipboard_copy_error', err.message);
            return false;
        }
    };

    // ---------- Initialize Socket.IO if available ----------
    if (typeof io !== 'undefined') {
        const socket = io();
        
        socket.on('connect', () => {
            console.log('Connected to server');
            sendLog('socket_connected', 'Socket.IO connection established');
        });

        socket.on('disconnect', () => {
            console.log('Disconnected from server');
            sendLog('socket_disconnected', 'Socket.IO connection lost');
        });

        socket.on('new_log', (logEntry) => {
            console.log('New log received:', logEntry);
            // You can handle real-time log updates here if needed
        });
    }

    // ---------- Service Worker Registration ----------
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js')
                .then(registration => {
                    console.log('Service Worker registered:', registration);
                    sendLog('service_worker_registered', 'Service worker registration successful');
                })
                .catch(error => {
                    console.log('Service Worker registration failed:', error);
                    sendLog('service_worker_error', error.message);
                });
        });
    }

    // ---------- Theme Toggle (if implemented) ----------
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        const currentTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', currentTheme);
        
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            sendLog('theme_toggle', `Theme changed to: ${newTheme}`);
        });
    }

    // ---------- Print Page Functionality ----------
    const printBtns = document.querySelectorAll('.print-btn');
    printBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            window.print();
            sendLog('page_print', 'Print dialog opened');
        });
    });

});

// If you need to fetch admin logs, wrap in an async function:
async function fetchAdminLogs() {
    const adminToken = localStorage.getItem('adminToken');
    if (!adminToken) return;
    try {
        await fetch('/admin/logs', {
            headers: {
                'Authorization': 'Bearer ' + adminToken
            }
        });
        // Handle response if needed
        // const data = await res.json();
        // console.log(data);
    } catch (err) {
        console.error('Error fetching admin logs:', err);
    }
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('service-contact-form');
  const errorBox = document.getElementById('form-error-message');

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();

      errorBox.textContent = '';
      errorBox.style.color = '';

      const formData = new FormData(form);
      const name = formData.get('name')?.trim();
      const email = formData.get('email')?.trim();
      const service = formData.get('service');
      const message = formData.get('message')?.trim();

      if (!name || !email || !service || !message) {
        errorBox.textContent = 'Please fill out all required fields.';
        errorBox.style.color = 'red';
        return;
      }

      form.reset();
      errorBox.textContent = 'Your request has been sent successfully!';
      errorBox.style.color = 'green';
    });
  }
});

const form = document.getElementById('testimonialForm');
const successMessage = document.getElementById('successMessage');

form.addEventListener('submit', (e) => {
  e.preventDefault();

  const testimonial = {
    name: form.customerName.value.trim(),
    service: form.serviceUsed.value,
    rating: form.rating.value,
    text: form.testimonialText.value.trim(),
    date: new Date().toISOString(),
    // Files are tricky in localStorage; you can save base64 strings if you want to get fancy
  };

  // Retrieve current testimonials or create array
  let testimonials = JSON.parse(localStorage.getItem('testimonials') || '[]');
  testimonials.push(testimonial);
  localStorage.setItem('testimonials', JSON.stringify(testimonials));

  successMessage.style.display = 'block';
  form.reset();
  document.getElementById('imagePreview').innerHTML = '';
});

  // Mobile toggle
  const toggle = document.getElementById('mobileMenuToggle');
  const navMenu = document.getElementById('navMenu');

  if (toggle) {
    toggle.addEventListener('click', () => {
      const expanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!expanded));
      navMenu.classList.toggle('active');
    });
  }

// Uncomment to use:
// fetchAdminLogs();
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js')
    .then(reg => console.log('✅ Service Worker registered:', reg.scope))
    .catch(err => console.error('❌ Service Worker registration failed:', err));
}



