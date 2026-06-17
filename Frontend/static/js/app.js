document.addEventListener('DOMContentLoaded', () => {
    const socket = io();

    const threatContainer = document.getElementById('threat-container');
    const timelineContainer = document.getElementById('timeline-container');
    const codeContainer = document.getElementById('code-container');
    const btnDeploy = document.getElementById('btn-deploy');
    const btnSimulate = document.getElementById('btn-simulate');
    const approvalNotice = document.getElementById('approval-notice');
    const codeStatus = document.getElementById('code-status');

    const agentSteps = {
        'threat-hunter': timelineContainer.querySelector('[data-agent="threat-hunter"]'),
        'policy-checker': timelineContainer.querySelector('[data-agent="policy-checker"]'),
        'cloud-ops': timelineContainer.querySelector('[data-agent="cloud-ops"]'),
        'validator': timelineContainer.querySelector('[data-agent="validator"]')
    };

    const AGENT_DEFAULTS = {
        'threat-hunter': 'Standing by for telemetry ingestion...',
        'policy-checker': 'Awaiting forensics report...',
        'cloud-ops': 'Ready to generate Terraform...',
        'validator': 'Pending IaC safety audit...'
    };

    let timelineEventCount = 0;
    let threatReceived = false;
    let realTimeAlertActive = false;

    const PIPELINE_STATUS_MESSAGES = {
        MITIGATION_DEPLOYED: 'Remediation applied. System isolated successfully.',
        SAFE_TO_DEPLOY: 'No threats detected. Safe to deploy to production.'
    };

    function displayPipelineStatus(statusCode, colorClass) {
        if (!codeStatus) return;

        const message = PIPELINE_STATUS_MESSAGES[statusCode] || statusCode;
        codeStatus.textContent = message;
        codeStatus.className = `code-status pipeline-status ${colorClass}`;
    }

    function setAgentState(agentKey, state, statusText, time) {
        const step = agentSteps[agentKey];
        if (!step) return;

        const icon = step.querySelector('.step-icon');
        icon.classList.remove('step-icon--idle', 'step-icon--active', 'step-icon--complete');
        step.classList.remove('agent-step--active', 'agent-step--complete');

        if (state === 'active') {
            icon.classList.add('step-icon--active');
            step.classList.add('agent-step--active');
        } else if (state === 'complete') {
            icon.classList.add('step-icon--complete');
            step.classList.add('agent-step--complete');
        } else {
            icon.classList.add('step-icon--idle');
        }

        if (statusText) {
            const statusEl = step.querySelector('[data-status]');
            if (statusEl) statusEl.innerHTML = statusText;
        }

        if (time) {
            const timeEl = step.querySelector('[data-time]');
            if (timeEl) timeEl.textContent = time;
        }
    }

    function resetAgentTimeline() {
        Object.keys(agentSteps).forEach((key) => {
            setAgentState(key, 'idle', AGENT_DEFAULTS[key], '');
        });
    }

    function restoreTerminalIdle() {
        threatContainer.innerHTML = `
            <div class="terminal-idle" id="terminal-idle">
                <span class="idle-prefix">root@cloudguard:~$</span>
                <span class="idle-text">System Idle. Awaiting Network Telemetry...</span>
                <span class="blink-cursor">█</span>
            </div>
        `;
    }

    function lockDeployButton() {
        if (!btnDeploy) return;
        btnDeploy.disabled = true;
        btnDeploy.classList.remove('btn-deploy--unlocked');
        btnDeploy.classList.add('btn-deploy--locked');
        const deployText = btnDeploy.querySelector('.btn-deploy-text');
        if (deployText) deployText.textContent = 'Approve & Deploy';
        if (approvalNotice) approvalNotice.classList.remove('approval-notice--hidden');
    }

    function highlightLogMessage(message) {
        return message
            .replace(/(\[.*?\])/g, '<span class="hl-alert">$1</span>')
            .replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, '<span class="hl-ip">$1</span>')
            .replace(/\b(RCE|SQLi|CRITICAL|Unauthorized|AssumeRole|exploit|vulnerability)\b/gi, '<span class="hl-keyword">$1</span>');
    }

    function severityClass(severity) {
        const s = (severity || '').toUpperCase();
        if (s.includes('CRITICAL')) return 'severity--critical';
        if (s.includes('HIGH')) return 'severity--high';
        if (s.includes('MEDIUM') || s.includes('WARN')) return 'severity--medium';
        return 'severity--low';
    }

    function clearTerminalIdle() {
        const idleEl = document.getElementById('terminal-idle');
        if (idleEl && idleEl.parentNode) {
            idleEl.remove();
        }
    }

    function scrollToBottom(el) {
        if (el) {
            requestAnimationFrame(() => {
                el.scrollTop = el.scrollHeight;
            });
        }
    }

    function unlockDeployButton() {
        if (!btnDeploy) return;
        btnDeploy.disabled = false;
        btnDeploy.classList.remove('btn-deploy--locked');
        btnDeploy.classList.add('btn-deploy--unlocked');
        if (approvalNotice) approvalNotice.classList.add('approval-notice--hidden');
    }

    function handleTimelineProgress(data) {
        timelineEventCount += 1;

        if (timelineEventCount === 1) {
            setAgentState('threat-hunter', 'complete', data.status, data.time);
            setAgentState('policy-checker', 'active', 'Evaluating zero-trust compliance rules...', '');
            setTimeout(() => {
                setAgentState('policy-checker', 'complete', '<b>Policy Check:</b> PASSED — External threat confirmed. Proceeding to IaC generation.', data.time);
                setAgentState('cloud-ops', 'active', 'Generating Terraform remediation script...', '');
            }, 1200);
        } else if (timelineEventCount === 2) {
            setAgentState('cloud-ops', 'active', data.status, data.time);
        }
    }

    function resetDashboardForSimulation() {
        timelineEventCount = 0;
        threatReceived = false;
        realTimeAlertActive = false;

        restoreTerminalIdle();
        resetAgentTimeline();

        codeContainer.textContent = '# Awaiting server deployment orchestrator commands...';
        codeContainer.classList.remove('code-block--ready');

        if (codeStatus) {
            codeStatus.textContent = 'Awaiting orchestrator output...';
            codeStatus.className = 'code-status';
        }

        lockDeployButton();
    }

    window.simulateThreat = function () {
        if (!btnSimulate) return;

        btnSimulate.classList.add('btn-trigger--active');
        btnSimulate.disabled = true;
        setTimeout(() => btnSimulate.classList.remove('btn-trigger--active'), 400);

        resetDashboardForSimulation();
        socket.emit('trigger_scenario');

        setTimeout(() => {
            btnSimulate.disabled = false;
        }, 3000);
    };

    window.deployInfrastructure = function () {
        if (!btnDeploy || btnDeploy.disabled) return;

        alert('Deploying Infrastructure via Terraform Server Pipeline... Threat Mitigated successfully!');

        btnDeploy.disabled = true;
        btnDeploy.classList.remove('btn-deploy--unlocked');
        btnDeploy.classList.add('btn-deploy--locked');

        const deployText = btnDeploy.querySelector('.btn-deploy-text');
        if (deployText) deployText.textContent = 'Deployed';
    };

    if (btnSimulate) {
        btnSimulate.addEventListener('click', simulateThreat);
    }

    if (btnDeploy) {
        btnDeploy.addEventListener('click', deployInfrastructure);
    }

    // 1. Listen for new threats from server
    socket.on('new_threat', (data) => {
        realTimeAlertActive = true;

        if (!threatReceived) {
            clearTerminalIdle();
            threatReceived = true;
            setAgentState('threat-hunter', 'active', 'Analyzing incoming threat telemetry...', '');
        }

        threatContainer.innerHTML += `
            <div class="log-entry">
                <div class="log-header">
                    <span class="timestamp">${data.timestamp}</span>
                    <span class="severity ${severityClass(data.severity)}" style="color: #EF4444; font-weight:bold;">${data.severity}</span>
                </div>
                <div class="log-body">${highlightLogMessage(data.message)}</div>
            </div>
        `;
        scrollToBottom(threatContainer);
    });

    // 2. Listen for agent timeline updates from server
    socket.on('new_timeline_item', (data) => {
        handleTimelineProgress(data);
    });

    // 3. Listen for final remediation output from server
    socket.on('remediation_ready', (data) => {
        setAgentState('cloud-ops', 'complete', data.status, data.time);
        setAgentState('validator', 'active', 'Running CIDR safety audit and deployment validation...', '');

        setTimeout(() => {
            setAgentState('validator', 'complete', '<b>Validator:</b> SAFE_TO_DEPLOY — No dangerous CIDR blocks detected.', data.time);
            unlockDeployButton();

            if (realTimeAlertActive) {
                displayPipelineStatus('MITIGATION_DEPLOYED', 'warning-orange');
            } else {
                displayPipelineStatus('SAFE_TO_DEPLOY', 'success-green');
            }
        }, 1500);

        codeContainer.textContent = data.code;
        codeContainer.classList.add('code-block--ready');
    });
});
