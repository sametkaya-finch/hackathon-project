import socket
import json
import hmac
import hashlib
import sqlite3
import os
import time
from collections import deque
import numpy as np

#config
LISTEN_IP = "0.0.0.0"
UDP_PORT = 5005
DB_PATH = "/app/data/network_logs.db"
WINDOW_SIZE = 10

ALLOWED_KEYS = {
    "KEY_ALPHA": b"bkzs_secret_key_2026",
    "KEY_BETA": b"anahtar_istasyon_beta_99"
}

packet_buffer = deque(maxlen=WINDOW_SIZE)

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;") #es zamanli okuma yazma icin wal modu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sat_id TEXT,
            lat REAL,
            lon REAL,
            rssi REAL,
            delta_t REAL,
            rssi_var REAL,
            status TEXT,
            label_code INTEGER,
            key_used TEXT
        )
    ''')
    conn.commit()
    return conn

def verify_hmac_multi(data_dict, received_sig):
    temp_dict = data_dict.copy()
    temp_dict.pop("signature", None)
    data_string = json.dumps(temp_dict, sort_keys=True)
    
    for key_name, key_val in ALLOWED_KEYS.items():
        expected_sig = hmac.new(key_val, data_string.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_sig, received_sig):
            return True, key_name
            
    return False, "UNKNOWN_OR_INVALID_KEY"

def calculate_features(server_receive_time, current_rssi):
    #delta t hesaplanmasinda sunucu saati dikkate alinir
    packet_buffer.append({"ts": server_receive_time, "rssi": current_rssi})
    
    if len(packet_buffer) < 2:
        return 0.0, 0.0
    
    times = [p["ts"] for p in packet_buffer]
    #negatif zaman farkliliklarinin onune gecilir
    delta_ts = np.abs(np.diff(times))
    avg_delta_t = float(np.mean(delta_ts))
    
    rssis = [p["rssi"] for p in packet_buffer]
    rssi_var = float(np.var(rssis))
    
    return avg_delta_t, rssi_var

def main():
    print("M2: Validator ve Anomali Tespit Sistemi Başlatıldı...")
    conn = init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        receive_time = time.time() #paketin sunucuya ulastigi an
        
        try:
            packet = json.loads(data.decode())
            received_sig = packet.get("signature", "")
            
            is_valid_sig, used_key = verify_hmac_multi(packet, received_sig)
            
            #payload time yerine recieved time kullaniyoruz
            dt, rvar = calculate_features(receive_time, packet["rssi"])
            
            status = "NORMAL_TRAFFIC"
            label_code = 0 
            is_attacker_packet = (packet.get("rssi") == -45.0)
            
            if not is_valid_sig:
                status = "ATTACK: INVALID_SIGNATURE"
                label_code = 1
            elif dt > 0.0 and dt < 0.8 and is_attacker_packet:
                status = "ATTACK: HIGH_FREQUENCY_DDOS"
                label_code = 3
            elif is_attacker_packet:
                status = "ATTACK: SPOOFING_MANIPULATION"
                label_code = 2

            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO logs (timestamp, sat_id, lat, lon, rssi, delta_t, rssi_var, status, label_code, key_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (packet["timestamp"], packet["id"], packet["lat"], packet["lon"], 
                  packet["rssi"], dt, rvar, status, label_code, used_key))
            conn.commit()
            
            print(f"[{addr[0]}] Durum: {status} | dt: {dt:.3f} | r_var: {rvar:.4f}")

        except Exception as e:
            print(f"Paket işleme hatası: {e}")

if __name__ == "__main__":
    main()