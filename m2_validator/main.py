import socket
import json
import hmac
import hashlib
import sqlite3
import os
import time
import threading
from datetime import datetime
from collections import deque
import numpy as np
import joblib
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

#config
LISTEN_IP = "0.0.0.0"
UDP_PORT = 5005
M1_IP = "10.0.0.11" #tcp pingi atacagimiz hedefin ipsi
TCP_PORT = 5006     #tcp handshake portu
DB_PATH = "/app/data/network_logs.db"
WINDOW_SIZE = 10

MODEL_PATH = "bkzs_ysa_model.pkl"
SCALER_PATH = "bkzs_scaler.pkl"

ALLOWED_KEYS = {
    "KEY_ALPHA": b"bkzs_secret_key_2026",
    "KEY_BETA": b"anahtar_istasyon_beta_99"
}

packet_buffer = deque(maxlen=WINDOW_SIZE)

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;") 
    
    #log tablosu
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
            key_used TEXT,
            action TEXT 
        )
    ''')
    
    #handshake tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS heartbeat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            status TEXT
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
    packet_buffer.append({"ts": server_receive_time, "rssi": current_rssi})
    if len(packet_buffer) < 2:
        return 0.0, 0.0
    times = [p["ts"] for p in packet_buffer]
    delta_ts = np.abs(np.diff(times))
    avg_delta_t = float(np.mean(delta_ts))
    rssis = [p["rssi"] for p in packet_buffer]
    rssi_var = float(np.var(rssis))
    return avg_delta_t, rssi_var

#her on saniyede bir tcp ile baglanti durumu kontrolu
def tcp_ping_loop():
    while True:
        status = "OFFLINE"
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0) #2 saniye icinde cevap gelmezse koptu sayilacak
            client.connect((M1_IP, TCP_PORT))
            data = client.recv(1024)
            if data == b"ALIVE":
                status = "ONLINE"
            client.close()
        except Exception:
            status = "OFFLINE"
            
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO heartbeat (timestamp, status) VALUES (?, ?)", 
                           (datetime.now().isoformat(), status))
            conn.commit()
            conn.close()
        except Exception as e:
            print("Heartbeat DB yazma hatası:", e)
            
        time.sleep(10) #on saniyede bir kontrol edilecek

def main():
    print("M2: IPS, YSA Anomali Tespiti ve TCP Ping Sistemi Başlatıldı...")
    
    try:
        ysa_model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("✅ YSA Modeli ve Scaler başarıyla belleğe yüklendi!")
    except Exception as e:
        print(f"❌ Kritik Hata: Model dosyaları bulunamadı! {e}")
        return

    conn = init_db()
    
    #tcp ping dongusu arka planda baslar
    threading.Thread(target=tcp_ping_loop, daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        receive_time = time.time() 
        
        try:
            packet = json.loads(data.decode())
            received_sig = packet.get("signature", "")
            
            is_valid_sig, used_key = verify_hmac_multi(packet, received_sig)
            dt, rvar = calculate_features(receive_time, packet["rssi"])
            
            features = np.array([[packet["lat"], packet["lon"], packet["rssi"], dt, rvar]])
            features_scaled = scaler.transform(features)
            prediction = int(ysa_model.predict(features_scaled)[0])
            
            label_map = {
                0: "✅ NORMAL TRAFİK",
                1: "🚨 KAYNAK ANOMALİSİ (ŞÜPHELİ SİNYAL)", 
                2: "🛰️ VERİ MANİPÜLASYONU (GPS SPOOFING)",
                3: "⚡ SİNYAL BOĞMA (DDOS/JAMMING)"
            }
            
            action_taken = "DROP"
            
            if not is_valid_sig:
                status = "⛔ REDDEDİLDİ: GEÇERSİZ ŞİFRE"
                label_code = 1
                action_taken = "DROP"
            else:
                status = label_map.get(prediction, "BİLİNMEYEN ANOMALİ")
                label_code = prediction
                if prediction == 0:
                    action_taken = "ACCEPT"
                else:
                    action_taken = "DROP"

            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO logs (timestamp, sat_id, lat, lon, rssi, delta_t, rssi_var, status, label_code, key_used, action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (packet["timestamp"], packet["id"], packet["lat"], packet["lon"], 
                  packet["rssi"], dt, rvar, status, label_code, used_key, action_taken))
            conn.commit()
            
            print(f"[{addr[0]}] Karar: {status} | Aksiyon: {action_taken}")

        except Exception as e:
            print(f"Paket işleme hatası: {e}")

if __name__ == "__main__":
    main()