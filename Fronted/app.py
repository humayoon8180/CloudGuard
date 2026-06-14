from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cloudguard_secret!'
# SocketIO initialize kiya taake real-time data stream ho sake
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

# Ek fake background thread jo real CrewAI agents ke logs ko simulate karega server se
def run_crewai_simulation():
    print("CrewAI Simulation Started Backend Par...")
    time.sleep(3) # Initial delay
    
    # 1. Threat Log Alert
    socketio.emit('new_threat', {
        'timestamp': time.strftime('%H:%M:%S'),
        'severity': 'CRITICAL',
        'message': '[REAL-TIME SERVER ALERT] Unauthorized AssumeRole detected for Admin-Execution-Role via Band API webhook.'
    })
    
    # 2. Scanner Agent Response
    time.sleep(3)
    socketio.emit('new_timeline_item', {
        'time': time.strftime('%H:%M:%S'),
        'status': '<b>Threat-Scanner Agent:</b> Incident broadcasted to Band Channel. Analysing impact score...',
        'complete': True
    })

    # 3. Forensics Agent Response
    time.sleep(4)
    socketio.emit('new_timeline_item', {
        'time': time.strftime('%H:%M:%S'),
        'status': '<b>Forensics Agent:</b> Mapped compromised IAM credentials to malicious IP 198.51.100.42.',
        'complete': True
    })

    # 4. DevOps Agent & Terraform Generation
    time.sleep(4)
    terraform_code = """# Auto-generated Remediation via Server CrewAI
resource "aws_iam_role_policy" "isolate_attacker" {
  name = "incident-isolation-policy"
  role = "Admin-Execution-Role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}"""
    socketio.emit('remediation_ready', {
        'code': terraform_code,
        'time': time.strftime('%H:%M:%S'),
        'status': '<b>DevOps-Shield Agent:</b> Terraform isolation script generated successfully.'
    })

# Jab user dashboard open karega, toh backend activity auto-start ho jayegi
@socketio.on('connect')
def handle_connect():
    print('Frontend client server se connect ho gaya!')
    # Background thread start karte hain taake Flask freeze na ho
    threading.Thread(target=run_crewai_simulation).start()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)