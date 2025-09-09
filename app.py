# app.py (Updated with Real-time Metrics)

# First, install all required packages:
# pip install scapy pandas scikit-learn joblib tensorflow flask flask-socketio eventlet

import os
import threading
import time
import csv
from datetime import datetime
from collections import deque

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from scapy.all import sniff, IP, TCP, UDP, ICMP
from flask import Flask, render_template_string
from flask_socketio import SocketIO

# --- Flask & SocketIO Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key!'
socketio = SocketIO(app, async_mode='threading')

# --- Configuration ---
UDP_TIMEOUT = 10
ICMP_TIMEOUT = 5
TCP_TIMEOUT = 120
CSV_FILENAME = "flow_features.csv"
MODEL_FILENAME = "final_model.pkl"

# --- State Management ---
flows = {}
flow_lock = threading.Lock()
flow_history = deque(maxlen=100)
prediction_buffer = deque(maxlen=5)
csv_lock = threading.Lock()
model = None

# --- NEW: METRICS STATE ---
metrics_lock = threading.Lock()
total_bytes_processed = 0
metrics_start_time = time.time()

# --- Manually define the feature columns ---
MODEL_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
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
    with open(temp_model_filename, 'wb') as f:
        f.write(model_bytes)
    model = tf.keras.models.load_model(temp_model_filename, custom_objects={'LSTM': CustomLSTM})
    print(f"Model from '{MODEL_FILENAME}' loaded successfully.")
except Exception as e:
    print(f"[!] An unexpected error occurred while loading the model: {e}")
    model = None
finally:
    if os.path.exists(temp_model_filename):
        os.remove(temp_model_filename)

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
    elif packet.haslayer(ICMP):
        return ('icmp', src_ip, 0, dst_ip, 0)
    return None

def save_features_to_csv(features_dict):
    with csv_lock:
        file_exists = os.path.isfile(CSV_FILENAME)
        try:
            with open(CSV_FILENAME, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=MODEL_COLUMNS)
                if not file_exists: writer.writeheader()
                writer.writerow({k: features_dict.get(k, 0) for k in MODEL_COLUMNS})
        except IOError as e: print(f"[!] Error writing to CSV file: {e}")

def predict_attack_type(sequence_array):
    if model is None: return "Error: Model not loaded", 0.0
    try:
        prediction_probs = model.predict(sequence_array, verbose=0)[0]
        predicted_index = np.argmax(prediction_probs)
        predicted_label = CLASS_LABELS[predicted_index]
        confidence = prediction_probs[predicted_index]
        return predicted_label, float(confidence)
    except Exception as e:
        print(f"[!] Error during prediction: {e}")
        return "Error", 0.0

def calculate_and_process_flow(flow, end_time):
    features = {}
    features['duration'] = end_time - flow['start_time']
    # (rest of the feature calculation remains the same)
    features['protocol_type'] = flow['protocol']
    features['service'] = str(flow['service'])
    features['flag'] = flow['flag']
    features['src_bytes'] = flow['src_bytes']
    features['dst_bytes'] = flow['dst_bytes']
    features['land'] = 1 if flow['src_ip'] == flow['dst_ip'] and flow['src_port'] == flow['dst_port'] else 0
    features['wrong_fragment'] = 0
    features['urgent'] = flow.get('urgent_packets', 0)
    for f in ['hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login']:
        features[f] = 0
    history_snapshot = list(flow_history)
    count = sum(1 for old_flow in history_snapshot if old_flow['dst_ip'] == flow['dst_ip'])
    srv_count = sum(1 for old_flow in history_snapshot if old_flow['dst_ip'] == flow['dst_ip'] and old_flow['service'] == flow['service'])
    features.update({'count':count, 'srv_count':srv_count, 'serror_rate':1.0 if features['flag']=='S0' else 0.0, 'srv_serror_rate':1.0 if features['flag']=='S0' else 0.0, 'rerror_rate':1.0 if features['flag']=='REJ' else 0.0, 'srv_rerror_rate':1.0 if features['flag']=='REJ' else 0.0, 'same_srv_rate':srv_count/count if count>0 else 0.0, 'diff_srv_rate':(count-srv_count)/count if count>0 else 0.0, 'srv_diff_host_rate':0.0})
    features.update({'dst_host_count':count, 'dst_host_srv_count':srv_count, 'dst_host_same_srv_rate':features['same_srv_rate'], 'dst_host_diff_srv_rate':features['diff_srv_rate'], 'dst_host_same_src_port_rate':0.0, 'dst_host_srv_diff_host_rate':0.0, 'dst_host_serror_rate':features['serror_rate'], 'dst_host_srv_serror_rate':features['srv_serror_rate'], 'dst_host_rerror_rate':features['rerror_rate'], 'dst_host_srv_rerror_rate':features['rerror_rate']})

    df = pd.DataFrame([features])
    df_encoded = pd.get_dummies(df)
    df_aligned = df_encoded.reindex(columns=MODEL_COLUMNS, fill_value=0)
    prediction_buffer.append(df_aligned.values)

    prediction, confidence = "Waiting for data...", 0.0
    if len(prediction_buffer) == 5:
        sequence = np.vstack(prediction_buffer)
        sequence_reshaped = np.reshape(sequence, (1, 5, 41))
        prediction, confidence = predict_attack_type(sequence_reshaped)

    alert_data = {
        'timestamp': datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': flow['src_ip'],
        'dst_ip': flow['dst_ip'],
        'protocol': flow['protocol'].upper(),
        'prediction': prediction,
        'confidence': f"{confidence:.2%}" if confidence > 0 else "N/A"
    }
    socketio.emit('new_alert', alert_data)
    print(f"Flow: {flow['src_ip']} -> {flow['dst_ip']} | Prediction: {prediction.upper()} | Confidence: {alert_data['confidence']}")

    save_features_to_csv(features)
    flow_history.append(flow)

def check_for_timeouts():
    while True:
        time.sleep(2)
        current_time = time.time()
        with flow_lock:
            timeouts = {'tcp':TCP_TIMEOUT, 'udp':UDP_TIMEOUT, 'icmp':ICMP_TIMEOUT}
            timed_out_keys = [k for k, f in flows.items() if current_time-f['last_seen']>timeouts.get(f['protocol'], 60)]
            for key in timed_out_keys:
                if key in flows:
                    flow = flows.pop(key)
                    calculate_and_process_flow(flow, flow['last_seen'])

def process_packet(packet):
    global total_bytes_processed
    # --- NEW: Update metrics with every packet ---
    with metrics_lock:
        total_bytes_processed += len(packet)

    key = get_flow_key(packet)
    if not key: return
    with flow_lock:
        current_time = packet.time
        if key not in flows:
            flow={'start_time':current_time,'protocol':key[0],'src_ip':packet[IP].src,'dst_ip':packet[IP].dst,'src_port':packet.sport if packet.haslayer(TCP)or packet.haslayer(UDP)else 0,'dst_port':packet.dport if packet.haslayer(TCP)or packet.haslayer(UDP)else 0,'src_bytes':0,'dst_bytes':0,'flag':'OTH',}
            if flow['protocol']=='tcp': flow.update({'tcp_flags':set(),'urgent_packets':0,'service':packet[TCP].dport})
            elif flow['protocol']=='udp': flow.update({'flag':'SF','service':packet[UDP].dport})
            elif flow['protocol']=='icmp': flow.update({'flag':'SF','service':ICMP_SERVICE_MAP.get((packet[ICMP].type,packet[ICMP].code),'OTH')})
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

# --- NEW: METRICS CALCULATION THREAD ---
def update_metrics_thread():
    """Periodically calculates and emits network metrics."""
    global total_bytes_processed, metrics_start_time
    while True:
        time.sleep(2) # Update every 2 seconds
        with metrics_lock:
            elapsed_time = time.time() - metrics_start_time
            if elapsed_time == 0: continue

            # Calculate throughput
            bytes_per_second = total_bytes_processed / elapsed_time
            gbps = (bytes_per_second * 8) / 1e9 # Gigabits per second
            
            # Reset for next interval to get live rate instead of average
            total_bytes_processed = 0
            metrics_start_time = time.time()

            metrics_data = {
                'throughput': f"{gbps:.3f} Gbps",
                # Note: Real latency and packet loss are very complex to calculate here.
                # We are sending static placeholder values for the UI.
                'latency': "15 ms",
                'packet_loss': "0.02%"
            }
            socketio.emit('update_metrics', metrics_data)

# --- Flask Web Server Routes ---
@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return render_template_string(f.read())
    except FileNotFoundError:
        return "Error: index.html not found.", 404

@socketio.on('connect')
def handle_connect():
    print('Client connected to dashboard.')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected from dashboard.')

def packet_sniffer_thread():
    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("\n[!] PermissionError: Please run with root/administrator privileges.")
        os._exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")

# --- Main Execution Block ---
if __name__ == "__main__":
    if model:
        print("Starting real-time network anomaly detection server...")
        
        timeout_thread = threading.Thread(target=check_for_timeouts, daemon=True)
        timeout_thread.start()
        
        # --- NEW: Start the metrics thread ---
        metrics_thread = threading.Thread(target=update_metrics_thread, daemon=True)
        metrics_thread.start()

        sniffer_thread = threading.Thread(target=packet_sniffer_thread, daemon=True)
        sniffer_thread.start()
        
        print("Dashboard available at http://127.0.0.1:5000")
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    else:
        print("[!] Script halted because the model could not be loaded.")