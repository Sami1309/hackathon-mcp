/* JavaScript for NodeZero Security Management System */

// Global configuration
const APP_CONFIG = {
    refreshInterval: 5000, // 5 seconds
    toastDuration: 3000,   // 3 seconds
    animationDuration: 500 // 0.5 seconds
};

// Utility functions
const Utils = {
    // Show toast notification
    showToast(message, type = 'info', duration = APP_CONFIG.toastDuration) {
        const toastId = 'toast-' + Date.now();
        const bgClass = {
            'success': 'bg-success',
            'error': 'bg-danger',
            'warning': 'bg-warning',
            'info': 'bg-info'
        }[type] || 'bg-info';

        const icon = {
            'success': 'check-circle',
            'error': 'exclamation-triangle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        }[type] || 'info-circle';

        const toastHtml = `
            <div class="toast show position-fixed top-0 end-0 m-3" id="${toastId}" role="alert" style="z-index: 9999;">
                <div class="toast-header ${bgClass} text-white">
                    <i class="bi bi-${icon} me-2"></i>
                    <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
                    <button type="button" class="btn-close btn-close-white" onclick="Utils.dismissToast('${toastId}')"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', toastHtml);

        // Auto-dismiss after duration
        setTimeout(() => {
            Utils.dismissToast(toastId);
        }, duration);

        return toastId;
    },

    // Dismiss toast
    dismissToast(toastId) {
        const toast = document.getElementById(toastId);
        if (toast) {
            toast.classList.add('fade');
            setTimeout(() => {
                toast.remove();
            }, 150);
        }
    },

    // Format date
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    },

    // Format duration
    formatDuration(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const remainingSeconds = seconds % 60;

        if (hours > 0) {
            return `${hours}h ${minutes}m ${remainingSeconds}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${remainingSeconds}s`;
        } else {
            return `${remainingSeconds}s`;
        }
    },

    // Debounce function
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
    },

    // Copy to clipboard
    copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                Utils.showToast('Copied to clipboard!', 'success');
            });
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            Utils.showToast('Copied to clipboard!', 'success');
        }
    },

    // Show loading state
    showLoading(element) {
        if (element) {
            element.classList.add('loading');
            const spinner = element.querySelector('.spinner-border');
            if (!spinner) {
                element.insertAdjacentHTML('afterbegin', '<span class="spinner-border spinner-border-sm me-2"></span>');
            }
        }
    },

    // Hide loading state
    hideLoading(element) {
        if (element) {
            element.classList.remove('loading');
            const spinner = element.querySelector('.spinner-border');
            if (spinner) {
                spinner.remove();
            }
        }
    }
};

// API service
const API = {
    // Base fetch function with error handling
    async fetch(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        const mergedOptions = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, mergedOptions);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            Utils.showToast(`API Error: ${error.message}`, 'error');
            throw error;
        }
    },

    // Analyze vulnerabilities
    async analyzeVulnerabilities(vulnerabilityIds) {
        return this.fetch('/analyze_vulnerabilities', {
            method: 'POST',
            body: JSON.stringify({ vulnerability_ids: vulnerabilityIds })
        });
    },

    // Start pentest
    async startPentest(targets, scenarios) {
        return this.fetch('/start_pentest', {
            method: 'POST',
            body: JSON.stringify({ targets, scenarios })
        });
    },

    // Get pentest status
    async getPentestStatus(jobId) {
        return this.fetch(`/pentest_status/${jobId}`);
    },

    // Get pentest logs
    async getPentestLogs(jobId) {
        return this.fetch(`/pentest_logs/${jobId}`);
    }
};

// Vulnerability management
const VulnerabilityManager = {
    selectedVulnerabilities: new Set(),

    init() {
        this.bindEvents();
    },

    bindEvents() {
        // Bind filter events
        const filters = ['severityFilter', 'statusFilter', 'categoryFilter', 'searchFilter'];
        filters.forEach(filterId => {
            const element = document.getElementById(filterId);
            if (element) {
                const eventType = filterId === 'searchFilter' ? 'input' : 'change';
                element.addEventListener(eventType, Utils.debounce(this.filterTable.bind(this), 300));
            }
        });

        // Bind checkbox events
        document.addEventListener('change', (e) => {
            if (e.target.classList.contains('vuln-checkbox')) {
                this.updateSelection();
            }
        });
    },

    filterTable() {
        const filters = {
            severity: document.getElementById('severityFilter')?.value || '',
            status: document.getElementById('statusFilter')?.value || '',
            category: document.getElementById('categoryFilter')?.value || '',
            search: document.getElementById('searchFilter')?.value.toLowerCase() || ''
        };

        const rows = document.querySelectorAll('#vulnerabilitiesTable tbody tr');
        let visibleCount = 0;

        rows.forEach(row => {
            const shouldShow = this.shouldShowRow(row, filters);
            row.style.display = shouldShow ? '' : 'none';
            if (shouldShow) visibleCount++;
        });

        // Update counter
        const countElement = document.getElementById('totalCount');
        if (countElement) {
            countElement.textContent = visibleCount;
        }
    },

    shouldShowRow(row, filters) {
        const severity = row.dataset.severity;
        const status = row.dataset.status;
        const category = row.dataset.category;
        const text = row.textContent.toLowerCase();

        return (!filters.severity || severity === filters.severity) &&
               (!filters.status || status === filters.status) &&
               (!filters.category || category === filters.category) &&
               (!filters.search || text.includes(filters.search));
    },

    updateSelection() {
        this.selectedVulnerabilities.clear();

        document.querySelectorAll('.vuln-checkbox:checked').forEach(checkbox => {
            this.selectedVulnerabilities.add(checkbox.value);
        });

        // Update UI elements based on selection
        this.updateSelectionUI();
    },

    updateSelectionUI() {
        const selectedCount = this.selectedVulnerabilities.size;
        const analyzeButton = document.querySelector('[onclick*="analyzeSelected"]');

        if (analyzeButton) {
            analyzeButton.disabled = selectedCount === 0;
            analyzeButton.innerHTML = selectedCount > 0
                ? `<i class="bi bi-cpu"></i> Analyze ${selectedCount} Selected`
                : '<i class="bi bi-cpu"></i> Analyze Selected';
        }
    },

    async analyzeSelected() {
        if (this.selectedVulnerabilities.size === 0) {
            Utils.showToast('Please select vulnerabilities to analyze.', 'warning');
            return;
        }

        const button = document.querySelector('[onclick*="analyzeSelected"]');
        Utils.showLoading(button);

        try {
            const analysis = await API.analyzeVulnerabilities(Array.from(this.selectedVulnerabilities));
            this.showAnalysisModal(analysis);
        } catch (error) {
            Utils.showToast('Failed to analyze vulnerabilities.', 'error');
        } finally {
            Utils.hideLoading(button);
        }
    },

    showAnalysisModal(analysis) {
        const modal = new AnalysisModal(analysis);
        modal.show();
    }
};

// Analysis Modal
class AnalysisModal {
    constructor(analysis) {
        this.analysis = analysis;
        this.modalId = 'analysisModal-' + Date.now();
    }

    show() {
        const modalHtml = this.generateHTML();
        document.body.insertAdjacentHTML('beforeend', modalHtml);

        const modalElement = document.getElementById(this.modalId);
        const modal = new bootstrap.Modal(modalElement);

        // Clean up when modal is closed
        modalElement.addEventListener('hidden.bs.modal', () => {
            modalElement.remove();
        });

        modal.show();
    }

    generateHTML() {
        return `
            <div class="modal fade" id="${this.modalId}" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-cpu"></i>
                                Claude AI Vulnerability Analysis
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            ${this.generateBodyHTML()}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                                <i class="bi bi-x"></i> Close
                            </button>
                            <button type="button" class="btn btn-primary" onclick="this.startPentest()">
                                <i class="bi bi-play-circle"></i> Start NodeZero Pentest
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    generateBodyHTML() {
        return `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="bi bi-file-text"></i> Analysis Summary</h6>
                        </div>
                        <div class="card-body">
                            <p>${this.analysis.summary}</p>
                            <div class="alert alert-warning">
                                <strong>Priority:</strong> ${this.analysis.priority_assessment}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="bi bi-bullseye"></i> Recommended Targets</h6>
                        </div>
                        <div class="card-body">
                            <div class="list-group">
                                ${this.analysis.recommended_targets.map(target => `
                                    <div class="list-group-item">
                                        <i class="bi bi-server"></i> <code>${target}</code>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="bi bi-list-check"></i> Test Scenarios</h6>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                ${this.analysis.test_scenarios.map(scenario => `
                                    <div class="col-md-6 mb-2">
                                        <div class="d-flex align-items-center">
                                            <i class="bi bi-check-circle text-success me-2"></i>
                                            ${scenario}
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    async startPentest() {
        const button = event.target;
        Utils.showLoading(button);

        try {
            const result = await API.startPentest(
                this.analysis.recommended_targets,
                this.analysis.test_scenarios
            );

            Utils.showToast(`Pentest started successfully! Job ID: ${result.job_id}`, 'success');
            bootstrap.Modal.getInstance(document.getElementById(this.modalId)).hide();

            // Redirect to pentests page after short delay
            setTimeout(() => {
                window.location.href = '/pentests';
            }, 1000);
        } catch (error) {
            Utils.showToast('Failed to start pentest.', 'error');
        } finally {
            Utils.hideLoading(button);
        }
    }
}

// Pentest monitoring
const PentestMonitor = {
    intervals: new Map(),

    init() {
        this.startMonitoring();
    },

    startMonitoring() {
        // Monitor running jobs every 5 seconds
        const runningJobs = document.querySelectorAll('[data-job-id]');

        runningJobs.forEach(row => {
            const jobId = row.dataset.jobId;
            const statusElement = row.querySelector('.job-status');

            if (statusElement && statusElement.textContent.includes('Running')) {
                const intervalId = setInterval(() => {
                    this.updateJobStatus(jobId, row);
                }, APP_CONFIG.refreshInterval);

                this.intervals.set(jobId, intervalId);
            }
        });
    },

    async updateJobStatus(jobId, row) {
        try {
            const status = await API.getPentestStatus(jobId);

            if (status) {
                this.updateRowStatus(row, status);

                // Stop monitoring if completed
                if (status.status === 'Completed') {
                    this.stopMonitoring(jobId);
                }
            }
        } catch (error) {
            console.error('Failed to update job status:', error);
        }
    },

    updateRowStatus(row, status) {
        // Update status badge
        const statusElement = row.querySelector('.job-status');
        if (statusElement) {
            statusElement.textContent = status.status;
            statusElement.className = `badge job-status ${this.getStatusClass(status.status)}`;
        }

        // Update progress bar
        const progressBar = row.querySelector('.job-progress');
        if (progressBar) {
            progressBar.style.width = `${status.progress}%`;
            progressBar.textContent = `${status.progress}%`;
            progressBar.setAttribute('aria-valuenow', status.progress);
        }

        // Update findings count
        const findingsElement = row.querySelector('.findings-count');
        if (findingsElement) {
            findingsElement.textContent = status.findings_count;
            findingsElement.className = `badge findings-count ${status.findings_count > 0 ? 'bg-danger' : 'bg-secondary'}`;
        }
    },

    getStatusClass(status) {
        if (status === 'Completed') return 'bg-success';
        if (status.includes('Running')) return 'bg-warning';
        return 'bg-secondary';
    },

    stopMonitoring(jobId) {
        const intervalId = this.intervals.get(jobId);
        if (intervalId) {
            clearInterval(intervalId);
            this.intervals.delete(jobId);
        }
    },

    stopAllMonitoring() {
        this.intervals.forEach(intervalId => clearInterval(intervalId));
        this.intervals.clear();
    }
};

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    // Initialize managers based on current page
    const currentPath = window.location.pathname;

    if (currentPath.includes('vulnerabilities')) {
        VulnerabilityManager.init();
    }

    if (currentPath.includes('pentests')) {
        PentestMonitor.init();
    }

    // Global event listeners
    document.addEventListener('beforeunload', () => {
        PentestMonitor.stopAllMonitoring();
    });

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl));
});

// Export for global access
window.Utils = Utils;
window.API = API;
window.VulnerabilityManager = VulnerabilityManager;
window.PentestMonitor = PentestMonitor;