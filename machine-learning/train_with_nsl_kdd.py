import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import json
from datetime import datetime
import os

print("=" * 60)
print("🎯 ENTRENAMIENTO CON NSL-KDD DATASET")
print("=" * 60)

column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

print("\n📊 Cargando NSL-KDD Dataset...")

train_path = '../data/NSL_KDD-master/KDDTrain+.csv'
test_path = '../data/NSL_KDD-master/KDDTest+.csv'

if not os.path.exists(train_path):
    print(f"❌ No se encontró: {train_path}")
    print("💡 Asegúrate de estar en el directorio 'backend/'")
    exit(1)

train_df = pd.read_csv(train_path, names=column_names, header=None)
test_df = pd.read_csv(test_path, names=column_names, header=None)

print(f"✅ Train: {train_df.shape[0]:,} muestras, {train_df.shape[1]} features")
print(f"✅ Test:  {test_df.shape[0]:,} muestras, {test_df.shape[1]} features")

X_train = train_df.drop(['label', 'difficulty'], axis=1)
y_train = train_df['label']

X_test = test_df.drop(['label', 'difficulty'], axis=1)
y_test = test_df['label']

print(f"\n📋 Clases en el dataset: {y_train.nunique()}")
print(f"   Top 10 clases más comunes:")
for label, count in y_train.value_counts().head(10).items():
    print(f"   - {label}: {count:,}")

print("\n🔧 Codificando variables categóricas...")
label_encoders = {}
categorical_cols = ['protocol_type', 'service', 'flag']

for col in categorical_cols:
    le = LabelEncoder()
    X_train[col] = le.fit_transform(X_train[col])
    
    X_test[col] = X_test[col].apply(
        lambda x: x if x in le.classes_ else le.classes_[0]
    )
    X_test[col] = le.transform(X_test[col])
    
    label_encoders[col] = le
    print(f"   ✓ {col}: {len(le.classes_)} categorías")

print("\n🏷️ Codificando etiquetas...")
label_encoder_y = LabelEncoder()
y_train_encoded = label_encoder_y.fit_transform(y_train)
y_test_encoded = label_encoder_y.transform(y_test)
print(f"   ✓ {len(label_encoder_y.classes_)} clases únicas")

print("\n📏 Escalando características...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("   ✓ Escalado completado")

print("\n🤖 Entrenando Random Forest Classifier...")
print("   Parámetros:")
print("   - n_estimators: 150")
print("   - max_depth: 25")
print("   - class_weight: balanced")
print("   - n_jobs: -1 (todos los cores)")

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=25,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
    verbose=1
)

model.fit(X_train_scaled, y_train_encoded)
print("\n✅ Entrenamiento completado")

print("\n📊 Evaluando modelo...")
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test_encoded, y_pred)

print(f"\n{'='*60}")
print(f"🎯 RESULTADOS")
print(f"{'='*60}")
print(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Clases detectadas: {len(label_encoder_y.classes_)}")

print(f"\n📋 Clases en el modelo:")
for i, cls in enumerate(label_encoder_y.classes_[:10], 1):
    print(f"   {i}. {cls}")
if len(label_encoder_y.classes_) > 10:
    print(f"   ... y {len(label_encoder_y.classes_) - 10} más")

print("\n💾 Guardando modelo...")
model_data = {
    'model': model,
    'scaler': scaler,
    'label_encoders': label_encoders,
    'label_encoder_y': label_encoder_y,
    'feature_names': X_train.columns.tolist(),
    'metadata': {
        'accuracy': float(accuracy),
        'n_features': X_train.shape[1],
        'n_classes': len(label_encoder_y.classes_),
        'classes': label_encoder_y.classes_.tolist(),
        'timestamp': datetime.now().isoformat(),
        'dataset': 'NSL-KDD'
    }
}

model_filename = 'nsl_kdd_model.pkl'
joblib.dump(model_data, model_filename, compress=3)
print(f"   ✓ Modelo guardado en: {model_filename}")

metadata_filename = 'nsl_kdd_metadata.json'
with open(metadata_filename, 'w') as f:
    json.dump(model_data['metadata'], f, indent=2)
print(f"   ✓ Metadata guardada en: {metadata_filename}")

print(f"\n📊 Classification Report (Top 10 clases más comunes):")
top_classes = y_train.value_counts().head(10).index.tolist()
top_class_indices = [label_encoder_y.transform([cls])[0] for cls in top_classes]

mask = np.isin(y_test_encoded, top_class_indices)
y_test_top = y_test_encoded[mask]
y_pred_top = y_pred[mask]

print(classification_report(
    y_test_top, 
    y_pred_top,
    labels=top_class_indices,
    target_names=top_classes,
    zero_division=0
))

print(f"\n{'='*60}")
print("✅ ¡ENTRENAMIENTO COMPLETADO CON ÉXITO!")
print(f"{'='*60}")
print(f"\n💡 Para usar este modelo en main.py:")
print(f"   1. Renombra '{model_filename}' a 'real_traffic_model.pkl'")
print(f"   2. O modifica main.py para cargar '{model_filename}'")
print(f"\n🚀 El modelo está listo para producción")
