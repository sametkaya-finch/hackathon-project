import socket
import time
import json
import hmac
import hashlib
import random
import math
import threading
from datetime import datetime
from skyfield.api import Topos, load

#config
UDP_IP = "10.0.0.12"  
UDP_PORT = 5005
TCP_PORT = 5006 #tcp handshake portu
SECRET_KEY = b"bkzs_secret_key_2026"
SATELLITE_URL = 'https://celestrak.org/NORAD/elements/gp.php?GROUP=stations&FORMAT=tle'

ANKARA = Topos('39.9334 N', '32.8597 E')

def get_satellite_data():
    try:
        satellites = load.tle_file(SATELLITE_URL, filename='tle_data.txt')
        by_name = {sat.name: sat for sat in satellites}
        return by_name['ISS (ZARYA)']
    except Exception as e:
        print(f"Veri çekme hatası: {e}")
        return None

def calculate_rssi(distance_km):
    base_rssi = -30
    reference_dist = 100.0
    distance_km = max(distance_km, 0.1) 
    path_loss = 10 * 2 * math.log10(distance_km / reference_dist)
    noise = random.uniform(-2, 2)
    return round(base_rssi - path_loss + noise, 2)

def create_hmac(data_string):
    return hmac.new(SECRET_KEY, data_string.encode(), hashlib.sha256).hexdigest()

#tcp handshake sunucusu
def tcp_heartbeat_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", TCP_PORT))
    server.listen(5)
    print(f"M1: TCP Heartbeat Sunucusu {TCP_PORT} portunda dinliyor...")
    while True:
        try:
            conn, addr = server.accept()
            conn.sendall(b"ALIVE") #baglanana hayattayim mesaji
            conn.close()
        except Exception:
            pass

def main():
    print("M1: BKZS Sinyal Üretici Başlatıldı (NASA ISS Verisi)...")
    satellite = get_satellite_data()
    
    if not satellite:
        print("Uydu verisi alınamadı, sistem durduruluyor.")
        return

    #udp akisi devam ediyorken tcp arka planda baslatiliyor
    threading.Thread(target=tcp_heartbeat_server, daemon=True).start()

    ts = load.timescale()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        try:
            now = ts.now()
            geocentric = satellite.at(now)
            subpoint = geocentric.subpoint()
            
            difference = satellite - ANKARA
            topocentric = difference.at(now)
            alt_deg, az_deg, distance = topocentric.altaz()
            
            rssi = calculate_rssi(distance.km)

            packet_data = {
                "id": "SAT-ISS-01",
                "timestamp": datetime.now().isoformat(),
                "lat": round(subpoint.latitude.degrees, 6),
                "lon": round(subpoint.longitude.degrees, 6),
                "alt": round(subpoint.elevation.km, 2),
                "velocity_km_s": 7.66,
                "rssi": rssi
            }

            json_data = json.dumps(packet_data, sort_keys=True)
            packet_data["signature"] = create_hmac(json_data)

            final_packet = json.dumps(packet_data).encode()
            sock.sendto(final_packet, (UDP_IP, UDP_PORT))
            
            print(f"[{packet_data['timestamp']}] M1 Gönderdi -> Mesafe: {distance.km:.0f}km | RSSI: {rssi} dBm")
        
        except Exception as e:
            print(f"İletim hatası: {e}")
            
        time.sleep(2)

if __name__ == "__main__":
    main()