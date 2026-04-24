# ML Threat Dashboard 🛡️

Dashboard de detección de amenazas ML con análisis de tráfico de red en tiempo real usando Machine Learning.

## 📋 Descripción

Sistema de detección de amenazas que analiza tráfico de red HTTP/HTTPS en tiempo real, clasifica ataques usando ML y mapea las amenazas detectadas al framework MITRE ATT&CK.

### Características

- ✅ Detección de amenazas en tiempo real usando Machine Learning
- ✅ Análisis de tráfico HTTP/HTTPS con MITMProxy
- ✅ Clasificación de ataques (DDoS, SQL Injection, XSS, etc.)
- ✅ Mapeo a MITRE ATT&CK Framework
- ✅ Dashboard interactivo con React y TypeScript
- ✅ API REST con FastAPI
- ✅ Dockerizado para fácil despliegue

## 🚀 Inicio Rápido con Docker (Recomendado)

### Prerequisitos
- [Docker](https:
- [Docker Compose](https:

### Ejecución

```bash
# Clonar repositorio
git clone https:
cd ML-Threat-Dashboard

# Ejecutar con Docker Compose
docker-compose up --build
```

**Accede a:**
- 🌐 Frontend: http://localhost:3000
- 🔧 Backend API: http://localhost:8000
- 📚 API Docs: http://localhost:8000/docs

### Detener servicios

```bash
docker-compose down
```

## 🛠️ Desarrollo Local (Sin Docker)

### Backend

```bash
cd backend

# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar servidor
python main.py
```

Backend disponible en: http://localhost:8000

### Frontend

```bash
cd frontend/ml-threat-dashboard

# Instalar dependencias
npm install

# Ejecutar en modo desarrollo
npm start
```

Frontend disponible en: http://localhost:3000

## 📊 Tecnologías

### Backend
- **Python 3.11**
- **FastAPI** - Framework web moderno y rápido
- **scikit-learn** - Machine Learning
- **MITMProxy** - Interceptación de tráfico
- **joblib** - Serialización de modelos

### Frontend
- **React 18** con TypeScript
- **CSS3** con diseño moderno

### Machine Learning
- **Algoritmo**: Random Forest Classifier
- **Dataset**: NSL-KDD (Network Security Dataset)
- **Características**: Análisis de patrones de tráfico HTTP/HTTPS

### DevOps
- **Docker** - Containerización
- **Docker Compose** - Orquestación
- **Nginx** - Servidor web para frontend

## 📁 Estructura del Proyecto

```
ML-Threat-Dashboard/
├── backend/                    # Backend FastAPI
│   ├── main.py                # Servidor principal
│   ├── train_model.py         # Entrenamiento (datos sintéticos)
│   ├── train_with_nsl_kdd.py  # Entrenamiento (datos reales NSL-KDD)
│   ├── generate_attacks.py    # Generador de ataques simulados
│   ├── mitmproxy_addon.py     # Addon para MITMProxy
│   ├── requirements.txt       # Dependencias Python
│   ├── real_traffic_model.pkl # Modelo ML entrenado
│   └── *.pkl                  # Encoders y scalers
├── frontend/                   # Frontend React
│   └── ml-threat-dashboard/
│       ├── src/
│       ├── public/
│       └── package.json
├── data/                       # Datasets
│   └── NSL_KDD-master/        # Dataset NSL-KDD
├── notebooks/                  # Jupyter notebooks
│   └── exploratory_analysis.ipynb
├── Dockerfile.backend          # Dockerfile para backend
├── Dockerfile.frontend         # Dockerfile para frontend
├── docker-compose.yml          # Orquestación Docker
├── nginx.conf                  # Configuración Nginx
├── .dockerignore              # Archivos excluidos de Docker
├── .gitignore                 # Archivos excluidos de Git
└── README.md                  # Este archivo
```

## 🔧 Configuración

### Variables de Entorno

Puedes configurar las siguientes variables en `docker-compose.yml`:

```yaml
environment:
  - PYTHONUNBUFFERED=1
  - LOG_LEVEL=INFO
```

### Modelos ML

El proyecto incluye los siguientes modelos pre-entrenados:
- `real_traffic_model.pkl` - Modelo principal de clasificación
- `label_encoder_y.pkl` - Encoder para etiquetas
- `label_encoders.pkl` - Encoders para características
- `scaler.pkl` - Scaler para normalización

## 📈 Uso

### 1. Iniciar el Sistema

```bash
docker-compose up -d
```

### 2. Generar Tráfico de Prueba

```bash
# Desde el directorio backend
python generate_attacks.py
```

### 3. Ver Detecciones en el Dashboard

Abre http://localhost:3000 y observa las detecciones en tiempo real.

### 4. API Endpoints

- `GET /` - Estado del sistema
- `GET /status` - Estado detallado con estadísticas
- `POST /scan` - Iniciar escaneo
- `POST /capture` - Capturar request
- `GET /results` - Obtener resultados del análisis
- `POST /stop` - Detener escaneo

## 🧪 Testing

### Backend

```bash
cd backend
pytest
```

### Frontend

```bash
cd frontend/ml-threat-dashboard
npm test
```

## 📝 Notas Importantes

- El entorno virtual (`ml_threat_dashboard/`) está excluido del repositorio
- Los modelos grandes no utilizados fueron eliminados para optimizar el tamaño
- El proyecto usa `.gitignore` y `.dockerignore` para mantener el repo limpio
- Para producción, considera usar variables de entorno para configuración sensible

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo `LICENSE` para más detalles.

## 👤 Autor

**Tu Nombre**
- GitHub: [@tuusuario](https:
- LinkedIn: [Tu Perfil](https:

## 🙏 Agradecimientos

- Dataset NSL-KDD por proporcionar datos de entrenamiento
- MITRE ATT&CK Framework por la taxonomía de amenazas
- Comunidad de FastAPI y React por las excelentes herramientas

---

⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub!
