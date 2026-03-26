/**
 * Network Scanner - Frontend JavaScript
 */

const Scanner = {
    // Poll for scan completion
    pollScan: function(scanId, statusEl, interval = 3000) {
        const poll = setInterval(async () => {
            try {
                const resp = await fetch(`/api/scan/${scanId}/status`);
                const data = await resp.json();

                if (data.status === 'completed') {
                    clearInterval(poll);
                    if (statusEl) {
                        statusEl.innerHTML = `
                            <div class="alert alert-success">
                                Scan complete!
                                <a href="/results/${scanId}" class="btn btn-sm btn-primary ms-2">View Results</a>
                            </div>`;
                    } else {
                        window.location.href = `/results/${scanId}`;
                    }
                } else if (data.status === 'error') {
                    clearInterval(poll);
                    if (statusEl) {
                        statusEl.innerHTML = `<div class="alert alert-danger">Scan failed: ${data.error}</div>`;
                    }
                } else {
                    if (statusEl) {
                        statusEl.innerHTML = `
                            <div class="alert alert-info d-flex align-items-center gap-2">
                                <div class="spinner-border spinner-border-sm"></div>
                                <span>Scanning in progress... <a href="/results/${scanId}">Check results</a></span>
                            </div>`;
                    }
                }
            } catch (e) {
                clearInterval(poll);
                console.error('Poll error:', e);
            }
        }, interval);
        return poll;
    },

    // Start a scan via API
    startScan: async function(payload) {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.error || `HTTP ${resp.status}`);
        }
        return await resp.json();
    },

    // Fetch scan list
    listScans: async function(limit = 20) {
        const resp = await fetch(`/api/scans?limit=${limit}`);
        return await resp.json();
    },

    // Delete a scan
    deleteScan: async function(scanId) {
        const resp = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
        return await resp.json();
    },

    // Format duration
    formatDuration: function(seconds) {
        if (!seconds) return 'N/A';
        if (seconds < 60) return `${seconds.toFixed(1)}s`;
        const m = Math.floor(seconds / 60);
        const s = (seconds % 60).toFixed(0);
        return `${m}m ${s}s`;
    },

    // Format timestamp
    formatTime: function(isoStr) {
        if (!isoStr) return 'N/A';
        return new Date(isoStr).toLocaleString();
    },
};

// Auto-initialize filter inputs
document.addEventListener('DOMContentLoaded', function () {
    const filterInput = document.getElementById('filterInput');
    if (filterInput) {
        filterInput.addEventListener('input', function () {
            const val = this.value.toLowerCase();
            document.querySelectorAll('[data-search]').forEach(el => {
                const text = (el.dataset.search + ' ' + el.textContent).toLowerCase();
                el.style.display = text.includes(val) ? '' : 'none';
            });
        });
    }

    // Initialize tooltips
    const tooltipEls = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipEls.forEach(el => new bootstrap.Tooltip(el));
});
