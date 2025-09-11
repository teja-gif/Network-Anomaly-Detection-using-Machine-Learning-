# app.py

import os
import threading
import time
import csv
import re
import queue
from datetime import datetime
from collections import deque

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from flask import Flask, render_template_string
from flask_socketio import SocketIO

# --- Flask & SocketIO Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key!'
socketio = SocketIO(app, async_mode='threading')

# --- Configuration ---
UDP_TIMEOUT, ICMP_TIMEOUT, TCP_TIMEOUT = 10, 5, 120
CSV_FILENAME = "flow_features.csv"
MODEL_FILENAME = "final_model.pkl"

# --- FINAL, ACCURATE WAF Rules ---
WAF_RULES = {
    'SQL Injection': re.compile(r"(\'|\%27)\s*(or|and)\s*(\'|\%27)1(\'|\%27)\s*=\s*(\'|\%27)1|union\s+select|select\s+.*\s+from|--|#", re.IGNORECASE),
    'Cross-Site Scripting (XSS)': re.compile(r"<script>|<img\s+src\s*=|onerror\s*=|onload\s*=|alert\(", re.IGNORECASE),
    'Directory Traversal': re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    'Command Injection': re.compile(r"(/bin/bash|powershell|cmd\.exe|cat\s+/etc/passwd)", re.IGNORECASE),
    'Suspicious User-Agents': re.compile(r"(sqlmap|nmap|nikto|wget|curl|masscan)", re.IGNORECASE)
}


# --- State Management ---
flows, flow_history, prediction_buffer = {}, deque(maxlen=100), deque(maxlen=5)
flow_lock, csv_lock, metrics_lock = threading.Lock(), threading.Lock(), threading.Lock()
model = None
total_bytes_sec, total_packets_sec, error_packets_sec = 0, 0, 0
icmp_requests, latency_ms = {}, deque(maxlen=20)
http_packet_queue = queue.Queue()
blocked_ips = set() # <-- IP BLOCKING: Keep track of blocked IPs

# --- Feature & Label Definitions ---
MODEL_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]
CLASS_LABELS = ['normal', 'dos', 'probe', 'r2l', 'u2r']

# --- Model Loading ---
from tensorflow.keras.layers import LSTM
class CustomLSTM(LSTM):
    def __init__(self, *args, **kwargs):
        kwargs.pop('time_major', None)
        super(CustomLSTM, self).__init__(*args, **kwargs)
temp_model_filename = 'temp_model.h5'
try:
    model_data = joblib.load(MODEL_FILENAME)
    model_bytes = model_data['model_bytes']
    with open(temp_model_filename, 'wb') as f: f.write(model_bytes)
    model = tf.keras.models.load_model(temp_model_filename, custom_objects={'LSTM': CustomLSTM})
    print(f"Model from '{MODEL_FILENAME}' loaded successfully.")
except Exception as e:
    print(f"[!] An unexpected error occurred while loading the model: {e}")
    model = None
finally:
    if os.path.exists(temp_model_filename): os.remove(temp_model_filename)

ICMP_SERVICE_MAP = {(0, 0):'ecr_i', (3, 0):'urp_i', (3, 1):'urp_i', (3, 3):'urp_i', (8, 0):'eco_i', (11, 0):'tim_i'}

def get_flow_key(packet):
    if not packet.haslayer(IP): return None
    ip_layer = packet[IP]
    src_ip, dst_ip = (ip_layer.src, ip_layer.dst) if ip_layer.src < ip_layer.dst else (ip_layer.dst, ip_layer.src)
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        proto = 'tcp' if packet.haslayer(TCP) else 'udp'
        sport, dport = (packet.sport, packet.dport)
        if src_ip != ip_layer.src: sport, dport = dport, sport
        port1, port2 = (sport, dport) if sport < dport else (dport, sport)
        return (proto, src_ip, port1, dst_ip, port2)
    elif packet.haslayer(ICMP): return ('icmp', src_ip, 0, dst_ip, 0)
    return None

def predict_attack_type(sequence_array):
    if model is None: return "Error: Model not loaded", 0.0
    try:
        prediction_probs = model.predict(sequence_array, verbose=0)[0]
        predicted_index = np.argmax(prediction_probs)
        return CLASS_LABELS[predicted_index], float(prediction_probs[predicted_index])
    except Exception as e:
        print(f"[!] Error during prediction: {e}")
        return "Error", 0.0

def calculate_and_process_flow(flow, end_time):
    features = {
        'duration': end_time - flow['start_time'], 'protocol_type': flow['protocol'], 'service': str(flow['service']),
        'flag': flow['flag'], 'src_bytes': flow['src_bytes'], 'dst_bytes': flow['dst_bytes'],
        'land': 1 if flow['src_ip'] == flow['dst_ip'] and flow['src_port'] == flow['dst_port'] else 0,
        'wrong_fragment': 0, 'urgent': flow.get('urgent_packets', 0)
    }
    for f in ['hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login']:
        features[f] = 0
    history_snapshot = list(flow_history)
    count = sum(1 for old_flow in history_snapshot if old_flow['dst_ip'] == flow['dst_ip'])
    srv_count = sum(1 for old_flow in history_snapshot if old_flow['dst_ip'] == flow['dst_ip'] and old_flow['service'] == flow['service'])
    same_srv_rate = srv_count / count if count > 0 else 0.0
    diff_srv_rate = (count - srv_count) / count if count > 0 else 0.0
    serror_rate = 1.0 if features['flag'] == 'S0' else 0.0
    rerror_rate = 1.0 if features['flag'] == 'REJ' else 0.0
    features.update({
        'count': count, 'srv_count': srv_count, 'serror_rate': serror_rate, 'srv_serror_rate': serror_rate,
        'rerror_rate': rerror_rate, 'srv_rerror_rate': rerror_rate, 'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate, 'srv_diff_host_rate': 0.0, 'dst_host_count': count,
        'dst_host_srv_count': srv_count, 'dst_host_same_srv_rate': same_srv_rate, 'dst_host_diff_srv_rate': diff_srv_rate,
        'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': serror_rate,
        'dst_host_srv_serror_rate': serror_rate, 'dst_host_rerror_rate': rerror_rate, 'dst_host_srv_rerror_rate': rerror_rate
    })
    df = pd.DataFrame([features])
    df_aligned = pd.get_dummies(df).reindex(columns=MODEL_COLUMNS, fill_value=0)
    prediction_buffer.append(df_aligned.values)
    prediction, confidence = "Waiting for data...", 0.0
    if len(prediction_buffer) == 5:
        sequence = np.vstack(prediction_buffer)
        prediction, confidence = predict_attack_type(np.reshape(sequence, (1, 5, 41)))
    alert_data = {
        'timestamp': datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S'), 'src_ip': flow['src_ip'], 'dst_ip': flow['dst_ip'],
        'protocol': flow['protocol'].upper(), 'prediction': prediction, 'confidence': f"{confidence:.2%}" if confidence > 0 else "N/A"
    }
    socketio.emit('new_alert', alert_data)
    print(f"Flow: {flow['src_ip']} -> {flow['dst_ip']} | Prediction: {prediction.upper()} | Confidence: {alert_data['confidence']}")
    flow_history.append(flow)

def check_for_timeouts():
    while True:
        time.sleep(2)
        with flow_lock:
            timeouts = {'tcp':TCP_TIMEOUT, 'udp':UDP_TIMEOUT, 'icmp':ICMP_TIMEOUT}
            for k in [k for k, f in flows.items() if time.time()-f['last_seen']>timeouts.get(f['protocol'], 60)]:
                if k in flows:
                    calculate_and_process_flow(flows.pop(k), time.time())

def calculate_and_emit_metrics():
    while True:
        time.sleep(1)
        with metrics_lock:
            global total_bytes_sec, total_packets_sec, error_packets_sec
            metrics_data = {
                'throughput': f"{(total_bytes_sec*8)/(10**9):.4f} Gbps",
                'latency': f"{sum(latency_ms)/len(latency_ms):.2f} ms" if latency_ms else '-- ms',
                'packet_loss': f"{(error_packets_sec/total_packets_sec)*100:.2f} %" if total_packets_sec>0 else '0.00 %'
            }
            socketio.emit('update_metrics', metrics_data)
            total_bytes_sec, total_packets_sec, error_packets_sec = 0, 0, 0
            for key, ts in list(icmp_requests.items()):
                if time.time() - ts > 5: del icmp_requests[key]

# <-- MODIFIED: This WAF worker is now safe for cloud deployment -->
def waf_worker():
    """Pulls packets from the queue, inspects them, and logs blocking actions."""
    global blocked_ips
    while True:
        packet = http_packet_queue.get()
        if packet is None: continue

        try:
            # This logic assumes the traffic is HTTP. For HTTPS, you would need a different approach.
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                for attack_type, pattern in WAF_RULES.items():
                    if pattern.search(payload):
                        attacker_ip = packet[IP].src
                        
                        if attacker_ip not in blocked_ips:
                            # In a containerized environment like Render, you cannot modify the host's firewall.
                            # Instead of calling os.system, we log the action and add the IP to an in-memory set.
                            print(f"🚨 WAF ALERT: {attack_type} detected from {attacker_ip}. Logging and adding to internal block list.")
                            
                            # os.system(f'netsh advfirewall firewall add rule name="WAF Block {attacker_ip}" dir=in action=block remoteip={attacker_ip}') # This will fail
                            # os.system(f"iptables -A INPUT -s {attacker_ip} -j DROP") # This will also fail
                            
                            blocked_ips.add(attacker_ip)
                        
                        alert_data = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'src_ip': attacker_ip,
                            'dst_ip': packet[IP].dst,
                            'attack_type': attack_type,
                            'payload': payload[:100] + '...' if len(payload) > 100 else payload
                        }
                        socketio.emit('web_attack_alert', alert_data)
                        break 
        except Exception as e:
            # It's good practice to log the specific exception
            print(f"[WAF-WORKER-ERROR] An error occurred: {e}")
            pass

def process_packet(packet):
    with metrics_lock:
        global total_bytes_sec, total_packets_sec, error_packets_sec
        total_bytes_sec += len(packet)
        total_packets_sec += 1
        if packet.haslayer(ICMP):
            if packet[ICMP].type == 8: icmp_requests[(packet[IP].src, packet[IP].dst, packet[ICMP].id, packet[ICMP].seq)] = packet.time
            elif packet[ICMP].type == 0:
                key = (packet[IP].dst, packet[IP].src, packet[ICMP].id, packet[ICMP].seq)
                if key in icmp_requests: latency_ms.append((packet.time - icmp_requests.pop(key)) * 1000)
            if packet[ICMP].type == 3: error_packets_sec += 1
        if packet.haslayer(TCP) and 'R' in packet[TCP].flags: error_packets_sec += 1

    # The WAF worker will only process HTTP traffic on port 80.
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
        http_packet_queue.put(packet)

    key = get_flow_key(packet)
    if not key: return
    with flow_lock:
        current_time = packet.time
        if key not in flows:
            flow={'start_time':current_time,'protocol':key[0],'src_ip':packet[IP].src,'dst_ip':packet[IP].dst,'src_port':0,'dst_port':0,'src_bytes':0,'dst_bytes':0,'flag':'OTH',}
            if packet.haslayer(TCP) or packet.haslayer(UDP): flow.update({'src_port': packet.sport, 'dst_port': packet.dport})
            if flow['protocol']=='tcp': flow.update({'tcp_flags':set(), 'urgent_packets':0, 'service':packet[TCP].dport})
            elif flow['protocol']=='udp': flow.update({'flag':'SF', 'service':packet[UDP].dport})
            elif flow['protocol']=='icmp': flow.update({'flag':'SF', 'service':ICMP_SERVICE_MAP.get((packet[ICMP].type,packet[ICMP].code),'OTH')})
            flows[key] = flow
        flow = flows[key]
        flow['last_seen'] = current_time
        flow['src_bytes' if packet[IP].src==flow['src_ip'] else 'dst_bytes']+=len(packet.payload)
        if flow['protocol']=='tcp':
            flags = packet[TCP].flags
            flow['tcp_flags'].add(str(flags))
            if 'U' in flags: flow['urgent_packets']+=1
            if 'S' in flags and 'F' in flags and 'A' in flags: flow['flag'] = 'SF'
            elif 'R' in flags: flow['flag'] = 'REJ'
            elif 'S' in flags and len(flow['tcp_flags'])==1: flow['flag'] = 'S0'

@app.route('/')
def index():
    try:
        # Ensure index.html is in the same directory as app.py
        with open('index.html', 'r') as f: return render_template_string(f.read())
    except FileNotFoundError:
        return "Error: index.html not found.", 404

def packet_sniffer_thread():
    # --- CRITICAL DEPLOYMENT NOTE ---
    # The sniff() function requires root privileges to capture network packets,
    # which are not available in standard cloud deployment containers like Render.
    # This thread will likely fail to start and the core NIDS functionality
    # will not work in a deployed environment. This code is for local testing only.
    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("\n[!] PermissionError: Cannot sniff packets without root/administrator privileges.")
        print("[!] This is expected on platforms like Render. The NIDS part of the app will not function.")
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")

if __name__ == "__main__":
    if model:
        print("Starting real-time network anomaly detection server...")
        
        # Start the background threads
        threading.Thread(target=check_for_timeouts, daemon=True).start()
        threading.Thread(target=calculate_and_emit_metrics, daemon=True).start()
        
        # Start the packet sniffer. Note the limitation mentioned above.
        threading.Thread(target=packet_sniffer_thread, daemon=True).start()
        
        # Start the WAF worker
        threading.Thread(target=waf_worker, daemon=True).start()

        # <-- MODIFIED: Use environment variable for port, default to 5000 -->
        port = int(os.environ.get('PORT', 5000))
        print(f"Dashboard available at http://0.0.0.0:{port}")
        # The host must be '0.0.0.0' to be accessible in a container
        socketio.run(app, host='0.0.0.0', port=port, debug=False)
    else:
        print("[!] Script halted because the model could not be loaded.")
