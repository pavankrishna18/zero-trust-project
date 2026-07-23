// Auto-dismiss alerts
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.3s';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
});

// OTP input auto-submit
const otpInput = document.getElementById('otp');
if (otpInput) {
    otpInput.addEventListener('input', function(e) {
        if (e.target.value.length === 6) {
            e.target.form.submit();
        }
    });
}

// Confirmation for critical actions
const dangerButtons = document.querySelectorAll('.btn-danger');
dangerButtons.forEach(button => {
    button.addEventListener('click', function(e) {
        if (!confirm('Are you sure you want to perform this action?')) {
            e.preventDefault();
        }
    });
});

// REAL-TIME WEBSOCKET CONNECTION - STABILIZED
if (window.location.pathname.includes('/dashboard') || window.location.pathname.includes('/admin')) {
    
    // Connect to Socket.IO with better options
    const socket = io({
        transports: ['websocket', 'polling'],
        upgrade: true,
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
    });
    
    // Connection status indicator
    const statusIndicator = document.createElement('div');
    statusIndicator.id = 'connection-status';
    statusIndicator.style.cssText = `
        position: fixed;
        top: 70px;
        right: 20px;
        background: #28a745;
        color: white;
        padding: 8px 15px;
        border-radius: 5px;
        font-size: 0.9rem;
        z-index: 9999;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        transition: all 0.3s ease;
    `;
    statusIndicator.innerHTML = '🟡 Connecting...';
    document.body.appendChild(statusIndicator);
    
    let reconnectAttempts = 0;
    
    // Connection events
    socket.on('connect', function() {
        console.log('✅ WebSocket connected - Session ID:', socket.id);
        statusIndicator.style.background = '#28a745';
        statusIndicator.innerHTML = '🟢 Live';
        reconnectAttempts = 0;
        
        // Join appropriate dashboard room
        const userId = document.body.dataset.userId;
        const userRole = document.body.dataset.userRole;
        
        if (userId && userRole) {
            socket.emit('join_dashboard', {
                user_id: userId,
                role: userRole
            });
        }
    });
    
    socket.on('disconnect', function(reason) {
        console.log('❌ WebSocket disconnected:', reason);
        statusIndicator.style.background = '#ffc107';
        statusIndicator.innerHTML = '🟡 Reconnecting...';
    });
    
    socket.on('reconnect', function(attemptNumber) {
        console.log('🔄 Reconnected after', attemptNumber, 'attempts');
        statusIndicator.style.background = '#28a745';
        statusIndicator.innerHTML = '🟢 Live';
    });
    
    socket.on('reconnect_attempt', function() {
        reconnectAttempts++;
        console.log('🔄 Reconnect attempt:', reconnectAttempts);
        statusIndicator.innerHTML = `🟡 Reconnecting... (${reconnectAttempts})`;
    });
    
    socket.on('reconnect_error', function(error) {
        console.error('❌ Reconnection error:', error);
        statusIndicator.style.background = '#dc3545';
        statusIndicator.innerHTML = '🔴 Connection Error';
    });
    
    socket.on('reconnect_failed', function() {
        console.error('❌ Reconnection failed');
        statusIndicator.style.background = '#dc3545';
        statusIndicator.innerHTML = '🔴 Offline';
    });
    
    socket.on('connection_response', function(data) {
        console.log('📡 ' + data.message);
    });
    
    socket.on('joined', function(data) {
        console.log('✅ Joined room: ' + data.room);
    });
    
    // Real-time updates
    socket.on('metrics_update', function(data) {
        console.log('📊 Metrics updated:', data);
        updateMetrics(data);
        showNotification('📊 Metrics updated');
    });
    
    socket.on('activities_update', function(data) {
        console.log('📝 Activities updated');
        updateActivitiesTable(data);
    });
    
    socket.on('sessions_update', function(data) {
        console.log('🔑 Sessions updated');
        updateSessionsTable(data);
    });
    
    socket.on('pending_devices_update', function(data) {
        console.log('📱 Pending devices updated:', data);
        updatePendingDevicesTable(data);
        showNotification('📱 New device pending approval', 'warning');
    });
    
    socket.on('new_login_attempt', function(data) {
        console.log('🔐 New login attempt: ' + data.username);
        showNotification('🔐 Login attempt: ' + data.username, 'warning');
    });
    
    socket.on('new_login_success', function(data) {
        console.log('✅ User logged in: ' + data.username);
        showNotification('✅ ' + data.username + ' logged in', 'success');
    });
    
    socket.on('user_logout', function(data) {
        console.log('👋 User logged out: ' + data.username);
        showNotification('👋 ' + data.username + ' logged out', 'info');
    });
    
    socket.on('device_trusted', function(data) {
        console.log('✅ Device trusted for user: ' + data.user_id);
        showNotification('✅ Your device has been trusted!', 'success');
        setTimeout(() => location.reload(), 2000);
    });
    
    socket.on('session_terminated', function(data) {
        console.log('🚫 Session terminated');
        showNotification('🚫 Session terminated', 'warning');
    });
    
    // Update metrics with IDs
    function updateMetrics(metrics) {
        console.log('Updating metrics UI with:', metrics);
        
        const elements = {
            totalUsers: document.getElementById('metric-total-users'),
            activeSessions: document.getElementById('metric-active-sessions'),
            failedLogins: document.getElementById('metric-failed-logins'),
            accessDenials: document.getElementById('metric-access-denials'),
            lockedAccounts: document.getElementById('metric-locked-accounts')
        };
        
        if (elements.totalUsers) {
            elements.totalUsers.textContent = metrics.total_users || 0;
            animateElement(elements.totalUsers);
        }
        
        if (elements.activeSessions) {
            elements.activeSessions.textContent = metrics.active_sessions || 0;
            animateElement(elements.activeSessions);
        }
        
        if (elements.failedLogins) {
            elements.failedLogins.textContent = metrics.failed_logins_today || 0;
            animateElement(elements.failedLogins);
        }
        
        if (elements.accessDenials) {
            elements.accessDenials.textContent = metrics.access_denials_today || 0;
            animateElement(elements.accessDenials);
        }
        
        if (elements.lockedAccounts) {
            elements.lockedAccounts.textContent = metrics.locked_accounts || 0;
            animateElement(elements.lockedAccounts);
        }
    }
    
    // Animate element
    function animateElement(element) {
        element.style.animation = 'pulse 0.6s';
        element.style.color = '#ffd700';
        setTimeout(() => {
            element.style.animation = '';
            element.style.color = '';
        }, 600);
    }
    
    // Update activities table
    function updateActivitiesTable(activities) {
        const tbody = document.querySelector('#activities-table tbody');
        if (!tbody) return;
        
        const limitedActivities = activities.slice(0, 20);
        let html = '';
        
        limitedActivities.forEach(activity => {
            let statusBadge = 'badge-warning';
            if (activity.status === 'success') statusBadge = 'badge-success';
            if (activity.status === 'failed') statusBadge = 'badge-danger';
            
            html += `
                <tr style="animation: fadeIn 0.5s;">
                    <td>${activity.username || 'N/A'}</td>
                    <td>${activity.action}</td>
                    <td><span class="badge ${statusBadge}">${activity.status}</span></td>
                    <td>${activity.ip_address || 'N/A'}</td>
                    <td>${new Date(activity.timestamp).toLocaleString()}</td>
                </tr>
            `;
        });
        
        tbody.innerHTML = html;
    }
    
    // Update sessions table
    function updateSessionsTable(sessions) {
        const tbody = document.querySelector('#active-sessions-table tbody');
        if (!tbody) return;
        
        let html = '';
        if (sessions && sessions.length > 0) {
            sessions.forEach(session => {
                html += `
                    <tr style="animation: fadeIn 0.5s;">
                        <td>${session.username}</td>
                        <td>${session.ip_address}</td>
                        <td>${session.created_at}</td>
                        <td>${session.last_activity}</td>
                        <td>
                            <a href="/admin/terminate-session/${session.id}" class="btn btn-small btn-danger">Terminate</a>
                        </td>
                    </tr>
                `;
            });
        } else {
            html = '<tr><td colspan="5" style="text-align:center;">No active sessions</td></tr>';
        }
        
        tbody.innerHTML = html;
    }
    
    // Update pending devices table - ENHANCED WITH HIGHLIGHT
    function updatePendingDevicesTable(devices) {
        const tbody = document.querySelector('#pending-devices-table tbody');
        if (!tbody) return;
        
        console.log('Updating pending devices table with:', devices);
        
        let html = '';
        if (devices && devices.length > 0) {
            devices.forEach(device => {
                html += `
                    <tr style="animation: fadeIn 0.5s; background: #fff3cd;">
                        <td>${device.username}</td>
                        <td>${device.browser}</td>
                        <td>${device.os}</td>
                        <td>${device.ip_address}</td>
                        <td>
                            <a href="/admin/trust-device/${device.id}" class="btn btn-small btn-success">Trust</a>
                        </td>
                    </tr>
                `;
            });
        } else {
            html = '<tr><td colspan="5" style="text-align:center;">No pending devices</td></tr>';
        }
        
        tbody.innerHTML = html;
    }
    
    // Show notification
    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.textContent = message;
        
        let bgColor = '#667eea';
        if (type === 'success') bgColor = '#28a745';
        if (type === 'warning') bgColor = '#ffc107';
        if (type === 'danger') bgColor = '#dc3545';
        if (type === 'info') bgColor = '#17a2b8';
        
        notification.style.cssText = `
            position: fixed;
            top: 120px;
            right: 20px;
            background: ${bgColor};
            color: white;
            padding: 15px 20px;
            border-radius: 5px;
            z-index: 9998;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            animation: slideIn 0.3s ease-out;
            max-width: 300px;
            font-size: 0.95rem;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 4000);
    }
    
    // Prevent page unload from breaking connection
    window.addEventListener('beforeunload', function() {
        socket.disconnect();
    });
    
    console.log('🔄 Real-time updates initialized with stable connection');
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; background: #fffbcc; }
        to { opacity: 1; background: transparent; }
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.15); }
    }
    
    @keyframes slideIn {
        from { transform: translateX(400px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(400px); opacity: 0; }
    }
`;
document.head.appendChild(style);
