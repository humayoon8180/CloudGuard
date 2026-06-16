import sys
import os
sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

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

from band_layer.state_manager import run_pipeline

def send_alert_to_frontend(data):
    """Callback function to push real-time events to the frontend via SocketIO"""
    if data.get("type") == "remediation":
        socketio.emit('remediation_ready', {
            'code': data['code'],
            'time': time.strftime('%I:%M:%S %p PKT'),
            'status': data['status']
        })
    else:
        socketio.emit('new_timeline_item', {
            'time': time.strftime('%I:%M:%S %p PKT'),
            'status': data['status'],
            'complete': True
        })

def run_real_crewai_pipeline():
    print("Real CloudGuard AI Pipeline Started Backend Par...")
    
    # 1. Initial Threat Alert
    socketio.emit('new_threat', {
        'timestamp': time.strftime('%I:%M:%S %p PKT'),
        'severity': 'CRITICAL',
        'message': '[REAL-TIME SERVER ALERT] Unauthorized SQL Injection detected via WAF. Initiating AI Incident Response.'
    })
    
    # 2. Run real pipeline with callback
    run_pipeline(send_alert_to_frontend)

# Jab user dashboard open karega, toh backend activity auto-start ho jayegi
@socketio.on('connect')
def handle_connect():
    print('Frontend client server se connect ho gaya!')
    # Background thread start karte hain taake Flask freeze na ho
    socketio.start_background_task(run_real_crewai_pipeline)

if __name__ == '__main__':
    socketio.run(
        app,
        debug=True,
        port=5000,
        allow_unsafe_werkzeug=True
    )