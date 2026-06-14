document.addEventListener('DOMContentLoaded', () => {
    // Server se WebSocket connection establish karna
    const socket = io();

    const threatContainer = document.getElementById('threat-container');
    const timelineContainer = document.getElementById('timeline-container');
    const codeContainer = document.getElementById('code-container');

    // 1. Listen for new threats from server
    socket.on('new_threat', (data) => {
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
    });
});