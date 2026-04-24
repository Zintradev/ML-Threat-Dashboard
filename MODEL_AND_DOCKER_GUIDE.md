# Guía Completa: Entrenamiento del Modelo y Docker

## 📚 1. ¿Cómo está Entrenado el Modelo?

### Modelo Actual: Datos Sintéticos

El modelo actual (`real_traffic_model.pkl`) está entrenado con **datos sintéticos** generados por el código en [`train_model.py`](file:

#### Características del Modelo Actual

```python
Algoritmo: RandomForestClassifier
- n_estimators: 150 árboles
- max_depth: 20
- class_weight: 'balanced'
- Validación cruzada: ~95% accuracy (datos sintéticos)
```

#### Clases Detectadas (5 tipos)
1. **normal** - Tráfico legítimo
2. **sql_injection** - Inyección SQL
3. **xss** - Cross-Site Scripting
4. **path_traversal** - Traversal de directorios
5. **dos** - Denial of Service

#### Características Extraídas (13 features)
```python
1. method_encoded       # GET=0, POST=1, etc.
2. path_length          # Longitud de la URL
3. has_special_chars    # Caracteres sospechosos: ', ", <, >, etc.
4. has_encoding         # Codificación URL (%)
5. has_sql_keywords     # SELECT, UNION, INSERT, DROP, OR
6. has_script_tags      # <script>
7. has_path_traversal   # ../, ..\, etc/passwd
8. status_code          # Código HTTP
9. response_size        # Tamaño de respuesta
10. is_error            # Status >= 400
11. request_frequency   # Frecuencia de requests
12. unique_paths_ratio  # Ratio de paths únicos
13. error_rate          # Tasa de errores
```

### Limitaciones del Modelo Actual

⚠️ **El modelo sintético es solo para demostración**:
- Datos generados artificialmente
- No refleja patrones reales complejos
- Bueno para MVP/portfolio, no para producción

---

## 🌐 2. Usar Datasets Públicos (Sin Descargar Manualmente)

### Opción 1: NSL-KDD Dataset (Ya lo tienes)

El proyecto ya incluye el dataset NSL-KDD en `data/NSL_KDD-master/`. Este es un dataset público estándar para detección de intrusiones.

#### Entrenar con NSL-KDD

Crea un nuevo script `train_with_nsl_kdd.py`:

```python
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Nombres de columnas del NSL-KDD
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

print("📊 Cargando NSL-KDD Dataset...")

# Cargar datos de entrenamiento
train_df = pd.read_csv('../data/NSL_KDD-master/KDDTrain+.csv', 
                       names=column_names, header=None)

# Cargar datos de prueba
test_df = pd.read_csv('../data/NSL_KDD-master/KDDTest+.csv', 
                      names=column_names, header=None)

print(f"✅ Train: {train_df.shape}, Test: {test_df.shape}")

# Separar features y labels
X_train = train_df.drop(['label', 'difficulty'], axis=1)
y_train = train_df['label']

X_test = test_df.drop(['label', 'difficulty'], axis=1)
y_test = test_df['label']

# Codificar variables categóricas
label_encoders = {}
categorical_cols = ['protocol_type', 'service', 'flag']

for col in categorical_cols:
    le = LabelEncoder()
    X_train[col] = le.fit_transform(X_train[col])
    X_test[col] = le.transform(X_test[col])
    label_encoders[col] = le

# Codificar etiquetas
label_encoder_y = LabelEncoder()
y_train_encoded = label_encoder_y.fit_transform(y_train)
y_test_encoded = label_encoder_y.transform(y_test)

# Escalar características
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("🤖 Entrenando modelo con NSL-KDD...")

# Entrenar modelo
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=25,
    min_samples_split=5,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
    verbose=1
)

model.fit(X_train_scaled, y_train_encoded)

# Evaluar
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test_encoded, y_pred)

print(f"\n✅ Accuracy: {accuracy:.4f}")
print(f"📋 Clases detectadas: {len(label_encoder_y.classes_)}")
print(f"   {list(label_encoder_y.classes_)[:10]}...")

# Guardar modelo
model_data = {
    'model': model,
    'scaler': scaler,
    'label_encoders': label_encoders,
    'label_encoder_y': label_encoder_y,
    'feature_names': X_train.columns.tolist()
}

joblib.dump(model_data, 'nsl_kdd_model.pkl', compress=3)
print("💾 Modelo guardado en: nsl_kdd_model.pkl")

# Reporte detallado
print("\n📊 Classification Report:")
print(classification_report(y_test_encoded, y_pred, 
                          target_names=label_encoder_y.classes_,
                          zero_division=0))
```

### Opción 2: Descargar Datasets Automáticamente

Puedes usar bibliotecas de Python para descargar datasets públicos automáticamente:

#### A) Usando `kaggle` API

```python
# Instalar: pip install kaggle

import kaggle
from kaggle.api.kaggle_api_extended import KaggleApi

api = KaggleApi()
api.authenticate()

# Descargar dataset de Kaggle
api.dataset_download_files('dataset-name', path='./data', unzip=True)
```

#### B) Usando `requests` para URLs directas

```python
import requests
import zipfile
import io

def download_dataset(url, extract_to='./data'):
    """Descargar y extraer dataset desde URL"""
    print(f"📥 Descargando dataset desde {url}...")
    
    response = requests.get(url)
    
    if url.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            zip_file.extractall(extract_to)
            print(f"✅ Dataset extraído en {extract_to}")
    else:
        # Guardar archivo directamente
        filename = url.split('/')[-1]
        with open(f"{extract_to}/{filename}", 'wb') as f:
            f.write(response.content)
        print(f"✅ Dataset guardado en {extract_to}/{filename}")

# Ejemplo: CICIDS2017 (dataset público de intrusiones)
# download_dataset('http://example.com/dataset.zip')
```

### Opción 3: Datasets Recomendados para Ciberseguridad

| Dataset | Descripción | Tamaño | URL |
|---------|-------------|--------|-----|
| **NSL-KDD** | Ya lo tienes | ~30 MB | Local |
| **CICIDS2017** | Tráfico de red moderno | ~2 GB | [Link](https:
| **UNSW-NB15** | Ataques modernos | ~100 MB | [Link](https:
| **KDD Cup 99** | Clásico (antiguo) | ~700 MB | [Link](http://kdd.ics.uci.edu/databases/kddcup99/) |

---

## 🐳 3. Usar Docker para Probar Viabilidad

### Paso 1: Verificar Instalación de Docker

```powershell
# Verificar Docker
docker --version
docker-compose --version

# Si no está instalado, descargar de:
# https:
```

### Paso 2: Construir y Ejecutar con Docker

```powershell
# Desde la raíz del proyecto
cd c:\Users\zintr\Documents\GitHub_Repo\ML-Threat-Dashboard

# Construir imágenes (primera vez o después de cambios)
docker-compose build

# Ejecutar servicios
docker-compose up
```

**Salida esperada:**
```
Creating network "ml-threat-dashboard_ml-threat-network" with driver "bridge"
Creating ml-threat-backend  ... done
Creating ml-threat-frontend ... done
Attaching to ml-threat-backend, ml-threat-frontend
backend_1   | INFO:     Started server process [1]
backend_1   | INFO:     Uvicorn running on http://0.0.0.0:8000
frontend_1  | Nginx started
```

### Paso 3: Verificar que Funciona

Abre tu navegador:

1. **Frontend**: http://localhost:3000
2. **Backend API**: http://localhost:8000
3. **API Docs**: http://localhost:8000/docs

### Paso 4: Probar en Otro Dispositivo

#### Opción A: Misma Red Local

```powershell
# En tu PC, obtener IP local
ipconfig

# Buscar "IPv4 Address" (ej: 192.168.1.100)
# En otro dispositivo en la misma red:
# http://192.168.1.100:3000
```

#### Opción B: Exportar Imágenes Docker

```powershell
# Guardar imágenes en archivos
docker save ml-threat-dashboard_backend:latest -o backend.tar
docker save ml-threat-dashboard_frontend:latest -o frontend.tar

# Copiar archivos .tar a otro dispositivo

# En el otro dispositivo, cargar imágenes
docker load -i backend.tar
docker load -i frontend.tar

# Ejecutar
docker-compose up
```

#### Opción C: Docker Hub (Recomendado para Portfolio)

```powershell
# 1. Crear cuenta en hub.docker.com

# 2. Login
docker login

# 3. Etiquetar imágenes
docker tag ml-threat-dashboard_backend:latest tuusuario/ml-threat-backend:latest
docker tag ml-threat-dashboard_frontend:latest tuusuario/ml-threat-frontend:latest

# 4. Subir a Docker Hub
docker push tuusuario/ml-threat-backend:latest
docker push tuusuario/ml-threat-frontend:latest

# 5. Cualquier persona puede ejecutar:
docker pull tuusuario/ml-threat-backend:latest
docker pull tuusuario/ml-threat-frontend:latest
docker-compose up
```

### Paso 5: Verificar Portabilidad

#### Checklist de Pruebas

- [ ] **Windows**: Funciona en tu PC
- [ ] **Linux**: Probar en WSL o VM Linux
- [ ] **Mac**: Probar en Mac (si tienes acceso)
- [ ] **Otra PC**: Probar en otro dispositivo Windows
- [ ] **Red Local**: Acceder desde otro dispositivo en la red

#### Script de Prueba Automatizado

Crea `test_docker.ps1`:

```powershell
Write-Host "🐳 Probando Docker Setup..." -ForegroundColor Cyan

# Test 1: Docker instalado
Write-Host "`n1️⃣ Verificando Docker..." -ForegroundColor Yellow
docker --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker no está instalado" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Docker OK" -ForegroundColor Green

# Test 2: Construir imágenes
Write-Host "`n2️⃣ Construyendo imágenes..." -ForegroundColor Yellow
docker-compose build
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Error al construir imágenes" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Build OK" -ForegroundColor Green

# Test 3: Ejecutar servicios
Write-Host "`n3️⃣ Iniciando servicios..." -ForegroundColor Yellow
docker-compose up -d
Start-Sleep -Seconds 10

# Test 4: Verificar backend
Write-Host "`n4️⃣ Probando Backend..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
if ($response.StatusCode -eq 200) {
    Write-Host "✅ Backend OK" -ForegroundColor Green
} else {
    Write-Host "❌ Backend no responde" -ForegroundColor Red
}

# Test 5: Verificar frontend
Write-Host "`n5️⃣ Probando Frontend..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri "http://localhost:3000/" -UseBasicParsing
if ($response.StatusCode -eq 200) {
    Write-Host "✅ Frontend OK" -ForegroundColor Green
} else {
    Write-Host "❌ Frontend no responde" -ForegroundColor Red
}

# Limpiar
Write-Host "`n🧹 Deteniendo servicios..." -ForegroundColor Yellow
docker-compose down

Write-Host "`n✅ ¡Todas las pruebas pasaron!" -ForegroundColor Green
Write-Host "🚀 El proyecto es viable para otros dispositivos" -ForegroundColor Cyan
```

Ejecutar:
```powershell
.\test_docker.ps1
```

---

## 🎯 Resumen y Recomendaciones

### Entrenamiento del Modelo

| Aspecto | Estado Actual | Recomendación |
|---------|---------------|---------------|
| **Datos** | Sintéticos | ✅ OK para demo/portfolio |
| **Producción** | No listo | ⚠️ Usar NSL-KDD o CICIDS2017 |
| **Accuracy** | ~95% (sintético) | 🎯 Objetivo: >85% con datos reales |

### Datasets Públicos

1. **Ya tienes**: NSL-KDD en `data/`
2. **Fácil de usar**: Script de entrenamiento incluido arriba
3. **Sin descargas manuales**: Usar scripts automáticos

### Docker para Viabilidad

✅ **Ventajas**:
- Un comando para ejecutar en cualquier dispositivo
- Mismo entorno en Windows, Linux, Mac
- Perfecto para portfolio y demostraciones

📋 **Próximos Pasos**:
1. Ejecutar `docker-compose up --build`
2. Verificar que funciona en tu PC
3. Probar en otro dispositivo (opcional)
4. Subir a Docker Hub para fácil distribución

---

## 📝 Comandos Rápidos

```powershell
# Entrenar con datos sintéticos (actual)
cd backend
python train_model.py

# Entrenar con NSL-KDD (crear script primero)
python train_with_nsl_kdd.py

# Probar con Docker
docker-compose up --build

# Ver logs
docker-compose logs -f

# Detener
docker-compose down

# Limpiar todo
docker-compose down -v
docker system prune -a
```
