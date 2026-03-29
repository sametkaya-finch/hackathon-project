import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib

#veriyi yukleme
print("Veri seti yükleniyor...")
df = pd.read_csv('logs.csv')

#gereksiz sutunlari temizleme
X = df[['lat', 'lon', 'rssi', 'delta_t', 'rssi_var']]
y = df['label_code']

#veri setini %20 test %80 egitim icin ayirma
#stratify=y parametresi siniflarin dengeli dagilmasi icin kullanildi
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

#veri Standardizasyonu
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

#ysa modelini kurma ve egitme
print("YSA Eğitimi Başlıyor (Bu işlem birkaç saniye sürebilir)...")
#32 ve 16 noronlu 2 gizli katman
ysa_model = MLPClassifier(
    hidden_layer_sizes=(32, 16), 
    activation='relu', 
    solver='adam', 
    max_iter=500, 
    random_state=42
)

#egitim
ysa_model.fit(X_train_scaled, y_train)

#tahmin ve basari
y_pred = ysa_model.predict(X_test_scaled)
dogruluk = accuracy_score(y_test, y_pred)

print(f"\n✅ Eğitim Tamamlandı! Model Doğruluk Oranı (Accuracy): %{dogruluk * 100:.2f}\n")
print("--- Detaylı Sınıflandırma Raporu ---")
print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Geçersiz İmza (1)', 'Spoofing (2)', 'DDoS (3)']))

#modeli m2 makinesi icin kaydetme
joblib.dump(ysa_model, 'bkzs_ysa_model.pkl')
joblib.dump(scaler, 'bkzs_scaler.pkl')
print("\n🚀 Model ve Scaler başarıyla 'bkzs_ysa_model.pkl' ve 'bkzs_scaler.pkl' olarak kaydedildi!")