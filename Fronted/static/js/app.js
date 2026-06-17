document.addEventListener('DOMContentLoaded', () => {
    // Server se WebSocket connection establish karna
    const socket = io();

    const threatContainer = document.getElementById('threat-container');
    const timelineContainer = document.getElementById('timeline-container');
    const codeContainer = document.getElementById('code-container');

    // 1. Listen for new threats from server
    socket.on('new_threat', (data) => {
        const idleEl = document.getElementById('idle-threats');
        if (idleEl) idleEl.remove();

        threatContainer.innerHTML += `
            <div class="log-entry">
                <div class="log-header">
                    <span class="timestamp">${data.timestamp}</span>
                    <span class="severity" style="color: #da3633; font-weight:bold;">${data.severity}</span>
                </div>
                <div class="log-body">${data.message}</div>
            </div>
        `;
    });

    // 2. Listen for agent timeline updates from server
    socket.on('new_timeline_item', (data) => {
        const idleEl = document.getElementById('idle-timeline');
        if (idleEl) idleEl.remove();

        const completeClass = data.complete ? 'complete' : '';
        timelineContainer.innerHTML += `
            <div class="timeline-item ${completeClass}">
                <div class="timeline-time">${data.time}</div>
                <div class="timeline-status">${data.status}</div>
            </div>
        `;
    });

    // 3. Listen for final remediation output from server
    socket.on('remediation_ready', (data) => {
        // Timeline item clear and add final status
        timelineContainer.innerHTML += `
            <div class="timeline-item complete">
                <div class="timeline-time">${data.time}</div>
                <div class="timeline-status">${data.status}</div>
            </div>
        `;
        // Inject Terraform Code
        codeContainer.textContent = data.code;

        // Enable Approve & Deploy Button
        const btnDeploy = document.getElementById('btn-deploy');
        btnDeploy.disabled = false;
        btnDeploy.style.opacity = '1';
        btnDeploy.style.cursor = 'pointer';
    });

    // Handle manual simulation trigger
    window.simulateThreat = function() {
        const btnSimulate = document.getElementById('btn-simulate');
        btnSimulate.disabled = true;
        btnSimulate.textContent = "Simulating...";
        btnSimulate.style.opacity = '0.7';

        // Clear existing containers for a fresh run
        threatContainer.innerHTML = '';
        timelineContainer.innerHTML = '';
        codeContainer.textContent = '# Awaiting server deployment orchestrator commands...';

        const btnDeploy = document.getElementById('btn-deploy');
        btnDeploy.disabled = true;
        btnDeploy.style.opacity = '0.5';
        btnDeploy.style.cursor = 'not-allowed';

        socket.emit('trigger_scenario');
    };

    window.deployInfrastructure = function() {
        alert('Deploying Infrastructure via Terraform Server Pipeline... Threat Mitigated successfully!');
        const btnDeploy = document.getElementById('btn-deploy');
        btnDeploy.disabled = true;
        btnDeploy.textContent = "Deployed";
        btnDeploy.style.backgroundColor = "var(--border-color)";
    };
});