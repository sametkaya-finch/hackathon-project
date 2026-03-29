import streamlit as st
import pandas as pd
import sqlite3
import requests
import plotly.express as px

#config
DB_PATH = "/app/data/network_logs.db"
HACKER_API = "http://10.0.1.13:8000"

st.set_page_config(page_title="BKZS IPS Monitörü", page_icon="🛡️", layout="wide")

# soc uzay komuta merkezi tasarimi

st.markdown("""
<style>
    /* 1.sidebar arkaplani*/
    [data-testid="stSidebar"] {
        background-color: #0F172A !important;
        border-right: 1px solid #1E293B;
    }
    
    /* 2.sidebar yazi renkleri*/
    [data-testid="stSidebar"] * {
        color: #CBD5E1 !important;
    }

    /* 3.soc buton tasarimi*/
    [data-testid="stSidebar"] div.stButton > button {
        background-color: #1E293B !important; 
        color: #38BDF8 !important;           
        border: 1px solid #334155 !important; 
        border-radius: 6px !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        width: 100%;
    }
    
    /* 4.buton hover efekti*/
    [data-testid="stSidebar"] div.stButton > button:hover {
        background-color: #0B1120 !important; 
        border-color: #38BDF8 !important;
        color: #FFFFFF !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.4) !important;
        transform: translateY(-2px);
    }

    /* 5.ana baslik rengi/
    h1, .stMarkdown h1 {
        color: #000000 !important;
        font-weight: 800 !important;
    }
</style>
""", unsafe_allow_html=True)


st.title("🛡️ BKZS Aktif Savunma ve YSA Karar Paneli")
st.markdown("ISS (Uluslararası Uzay İstasyonu) ağından gelen telemetri paketleri **Yapay Sinir Ağı** tarafından analiz edilmekte ve zararlı paketler **IPS** tarafından anında düşürülmektedir (DROP).")

#api istek fonksiyonu
def send_attack_command(endpoint, success_msg):
    try:
        response = requests.post(f"{HACKER_API}{endpoint}", timeout=2)
        if response.status_code == 200:
            st.sidebar.success(success_msg)
    except requests.exceptions.RequestException:
        st.sidebar.error("M3 (Hacker) API'sine ulaşılamıyor. Sistemin çalıştığından emin olun.")

#sidebar saldiri kontrolu
st.sidebar.header("☢️ YSA Test Senaryoları (M3)")

if st.sidebar.button("🟢 Sinyali Normale Çevir"):
    send_attack_command("/attack/stop", "Trafik normalleşiyor...")
if st.sidebar.button("🔴 Geçersiz İmza Testi"):
    send_attack_command("/attack/invalid_sig/start", "Geçersiz şifre saldırısı devrede.")
if st.sidebar.button("🟠 Veri Spoofing Testi"):
    send_attack_command("/attack/manipulation/start", "GPS/Sinyal manipülasyonu devrede.")
if st.sidebar.button("💀 DDoS / Jamming Testi"):
    send_attack_command("/attack/jamming/start", "Sinyal boğma saldırısı devrede.")

#veri cekme fonksiyonlari
def get_data():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC LIMIT 50", conn)
        conn.close()
        return df
    except Exception as e:
        return pd.DataFrame()

def get_total_dropped():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs WHERE action = 'DROP'")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0

def get_tcp_heartbeat():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM heartbeat ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "BEKLENİYOR"
    except Exception:
        return "HATA"

#canli veri paneli
@st.fragment(run_every="2s")
def live_dashboard():
    df = get_data()
    total_dropped = get_total_dropped()
    heartbeat_status = get_tcp_heartbeat() 

    if not df.empty:
        last_record = df.iloc[0]
        
        recent_10 = df.head(10)
        attack_packets = recent_10[recent_10['action'] == 'DROP']
        attack_count = len(attack_packets)
        dropped_in_last_50 = len(df[df['action'] == 'DROP'])
        
        r0_c1, r0_c2, r0_c3, r0_c4 = st.columns(4)
        
        with r0_c1:
            if heartbeat_status == "ONLINE":
                st.metric("📡 ISS Bağlantısı", "✅ AKTİF", delta="Bağlantı Kuruldu", delta_color="normal")
            elif heartbeat_status == "BEKLENİYOR":
                st.metric("📡 ISS Bağlantısı", "⏳ Bekleniyor", delta="Sinyal Aranıyor", delta_color="off")
            else:
                st.metric("📡 ISS Bağlantısı", "❌ KOPTU", delta="TCP Cevap Vermiyor", delta_color="inverse")

        with r0_c2:
            st.metric("Ağ Gecikmesi", f"{last_record['delta_t']:.3f} sn")
            
        with r0_c3:
            st.metric("Sinyal Gücü", f"{last_record['rssi']} dBm")

        with r0_c4:
            if attack_count == 0:
                st.metric("🚨 SİSTEM DURUMU", "✅ GÜVENLİ", delta="Son 10 Paket Temiz", delta_color="normal")
            else:
                primary_threat = attack_packets['status'].mode()[0] if not attack_packets.empty else "BİLİNMEYEN"
                st.metric("🚨 SİSTEM DURUMU", "⚠️ SALDIRI ALTINDA", delta=f"{attack_count}/10 Riskli", delta_color="inverse")
        
        st.write("") 

    
        r1_c1, r1_c2, r1_c3, r1_c4 = st.columns(4)
        
        with r1_c1:
            if dropped_in_last_50 > 0:
                st.metric("🛡️ IPS (Son 50)", f"{dropped_in_last_50} Paket", delta="İmha Edildi", delta_color="normal")
            else:
                st.metric("🛡️ IPS (Son 50)", "0 Paket", delta="Temiz", delta_color="off")
                
        with r1_c2:
            if total_dropped > 0:
                st.metric("🧱 IPS (Tüm)", f"{total_dropped} Paket", delta="Bloklandı", delta_color="normal")
            else:
                st.metric("🧱 IPS (Tüm)", "0 Paket", delta="Sistem Aktif", delta_color="off")

        st.markdown("---")

        
        #canli iss radari
       
        st.subheader("🌍 ISS Yörünge Takibi ve Spoofing Radarı")
        
        df_plot = df.iloc[::-1].reset_index(drop=True)
        
        df_plot['color'] = df_plot['action'].map({'ACCEPT': '#10B981', 'DROP': '#EF553B'})
        sizes = [100] * (len(df_plot) - 1) + [500] if not df_plot.empty else []
        df_plot['size'] = sizes

        st.map(
            df_plot,
            latitude="lat",
            longitude="lon",
            color="color",
            size="size",
            zoom=1, 
            use_container_width=True
        )
        st.markdown("---")

        #grafikler
        c1, c2, c3 = st.columns([1.5, 1.5, 1])
        
        with c1:
            st.subheader("Hız (DDoS) Analizi")
            fig_dt = px.area(df_plot, y="delta_t", color_discrete_sequence=["#FF8C00"], template="plotly_dark")
            fig_dt.update_layout(xaxis_title="Son Paketler", yaxis_title="Saniye", margin=dict(l=0,r=0,t=0,b=0), height=250, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_dt, use_container_width=True)
            
        with c2:
            st.subheader("Uzamsal (Spoofing) Analizi")
            fig_lat = px.line(df_plot, y="lat", markers=True, color_discrete_sequence=["#38BDF8"], template="plotly_dark")
            fig_lat.update_layout(xaxis_title="Son Paketler", yaxis_title="Enlem (Latitude)", margin=dict(l=0,r=0,t=0,b=0), height=250, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_lat, use_container_width=True)
            
        with c3:
            st.subheader("Tehdit Dağılımı")
            status_counts = df['status'].value_counts().reset_index()
            status_counts.columns = ['Durum', 'Adet']
            fig_pie = px.pie(status_counts, values='Adet', names='Durum', hole=0.4, template="plotly_dark")
            fig_pie.update_layout(showlegend=False, margin=dict(l=0,r=0,t=0,b=0), height=250, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_pie, use_container_width=True)

        #tablo
        st.subheader("🔍 Son 10 YSA Değerlendirmesi ve IPS Aksiyonu")
        
        def color_action_cell(val):
            if pd.isna(val): return ''
            if val == "ACCEPT":
                return 'background-color: rgba(16, 185, 129, 0.15); color: #34D399; font-weight: bold; border-left: 3px solid #10B981;'
            return 'background-color: rgba(225, 29, 72, 0.15); color: #FB7185; font-weight: bold; border-left: 3px solid #E11D48;'

        df_display = df[['timestamp', 'lat', 'lon', 'rssi', 'status', 'action']].head(10)
        styled_df = df_display.style.map(color_action_cell, subset=['action'])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
    else:
        st.info("Log bekleniyor... Model henüz trafik analizi yapmadı.")

live_dashboard()