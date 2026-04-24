# Guía de Configuración: Entorno Virtual y Docker

## 📍 Ubicación Actual del Entorno Virtual

Actualmente, tu entorno virtual está en:
```
c:\Users\zintr\Documents\GitHub_Repo\ML-Threat-Dashboard\ml_threat_dashboard\
```

### ⚠️ Problema Actual

**El entorno virtual NO debe estar en el repositorio de GitHub** por las siguientes razones:
1. **Tamaño**: Contiene ~16,784 archivos que inflan el repositorio
2. **Portabilidad**: Los entornos virtuales son específicos del sistema operativo y la máquina
3. **Buenas prácticas**: Los entornos virtuales se recrean localmente, no se versionan

## ✅ Solución Recomendada

### Opción 1: Mover el Entorno Virtual (Recomendado)

Mueve el entorno virtual fuera del directorio del proyecto:

```powershell
# Desde la raíz del proyecto
cd c:\Users\zintr\Documents\GitHub_Repo\ML-Threat-Dashboard

# Crear nuevo entorno virtual fuera del proyecto
python -m venv c:\Users\zintr\venvs\ml-threat-dashboard

# Activar el nuevo entorno
c:\Users\zintr\venvs\ml-threat-dashboard\Scripts\Activate.ps1

# Instalar dependencias
pip install -r backend\requirements.txt

# Opcional: eliminar el entorno virtual antiguo del proyecto
# Remove-Item -Path ml_threat_dashboard -Recurse -Force
```

### Opción 2: Renombrar a Convención Estándar

Si prefieres mantenerlo en el proyecto (aunque no es recomendado):

```powershell
# Renombrar a un nombre estándar que ya está en .gitignore
Rename-Item -Path "ml_threat_dashboard" -NewName "venv"
```

**Nota**: El `.gitignore` ya incluye `venv/`, por lo que no se subirá a GitHub.

## 🐳 Dockerización del Proyecto

Para hacer el proyecto portable y usable en varios equipos, aquí está la configuración de Docker:

### Estructura de Archivos Docker

```
ML-Threat-Dashboard/
├── Dockerfile.backend
├── Dockerfile.frontend
├── docker-compose.yml
└── .dockerignore
```

### 1. Dockerfile para Backend

Crea `Dockerfile.backend`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements
COPY backend/requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código del backend
COPY backend/ .

# Exponer puerto
EXPOSE 8000

# Comando para ejecutar
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 2. Dockerfile para Frontend

Crea `Dockerfile.frontend`:

```dockerfile
FROM node:18-alpine AS builder

WORKDIR /app

# Copiar package files
COPY frontend/ml-threat-dashboard/package*.json ./

# Instalar dependencias
RUN npm ci

# Copiar código fuente
COPY frontend/ml-threat-dashboard/ .

# Build de producción
RUN npm run build

# Etapa de producción con nginx
FROM nginx:alpine

# Copiar build al servidor nginx
COPY --from=builder /app/build /usr/share/nginx/html

# Copiar configuración de nginx (opcional)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### 3. Docker Compose

Crea `docker-compose.yml`:

```yaml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    container_name: ml-threat-backend
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app
      - ./data:/data
    environment:
      - PYTHONUNBUFFERED=1
    networks:
      - ml-threat-network
    restart: unless-stopped

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    container_name: ml-threat-frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
    networks:
      - ml-threat-network
    restart: unless-stopped

networks:
  ml-threat-network:
    driver: bridge
```

### 4. .dockerignore

Crea `.dockerignore`:

```
# Entornos virtuales
ml_threat_dashboard/
venv/
env/
.venv/

# Node modules
node_modules/
frontend/ml-threat-dashboard/node_modules/

# Build artifacts
frontend/ml-threat-dashboard/build/
dist/

# Logs
*.log

# Git
.git/
.gitignore

# IDE
.vscode/
.idea/

# Python cache
__pycache__/
*.pyc
*.pyo

# Jupyter
.ipynb_checkpoints/

# Temporary files
*.tmp
resultados_*.json

# Large unused models
backend/network_traffic_model.pkl
backend/rf_model.pkl
backend/rf_model_nsl_kdd.pkl
```

## 🚀 Comandos para Usar Docker

### Desarrollo Local

```powershell
# Construir y ejecutar todos los servicios
docker-compose up --build

# Ejecutar en segundo plano
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener servicios
docker-compose down
```

### Para GitHub Portfolio

```powershell
# Construir imágenes
docker-compose build

# Subir a Docker Hub (opcional)
docker tag ml-threat-dashboard_backend:latest tuusuario/ml-threat-backend:latest
docker tag ml-threat-dashboard_frontend:latest tuusuario/ml-threat-frontend:latest

docker push tuusuario/ml-threat-backend:latest
docker push tuusuario/ml-threat-frontend:latest
```

## 📝 README para GitHub

Actualiza tu `README.md` con instrucciones de Docker:

```markdown
# ML Threat Dashboard

Dashboard de detección de amenazas ML con análisis de tráfico de red en tiempo real.

## 🚀 Inicio Rápido con Docker

### Prerequisitos
- Docker
- Docker Compose

### Ejecución

\`\`\`bash
# Clonar repositorio
git clone https:
cd ML-Threat-Dashboard

# Ejecutar con Docker Compose
docker-compose up --build
\`\`\`

Accede a:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000

## 🛠️ Desarrollo Local (Sin Docker)

### Backend

\`\`\`bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
python main.py
\`\`\`

### Frontend

\`\`\`bash
cd frontend/ml-threat-dashboard
npm install
npm start
\`\`\`

## 📊 Características

- Detección de amenazas en tiempo real usando ML
- Análisis de tráfico HTTP/HTTPS con MITMProxy
- Clasificación de ataques con mapeo a MITRE ATT&CK
- Dashboard interactivo con React

## 🔧 Tecnologías

- **Backend**: Python, FastAPI, scikit-learn
- **Frontend**: React, TypeScript
- **ML**: Random Forest Classifier
- **Dataset**: NSL-KDD
\`\`\`

## ✅ Checklist para GitHub

- [ ] Crear archivos Docker (Dockerfile.backend, Dockerfile.frontend, docker-compose.yml)
- [ ] Crear .dockerignore
- [ ] Actualizar README.md con instrucciones de Docker
- [ ] Verificar que .gitignore excluye ml_threat_dashboard/
- [ ] Probar que docker-compose funciona localmente
- [ ] Hacer commit y push a GitHub
- [ ] Opcional: Configurar GitHub Actions para CI/CD
- [ ] Opcional: Publicar imágenes en Docker Hub

## 🎯 Ventajas de Docker para Portfolio

1. **Portabilidad**: Funciona en cualquier sistema con Docker
2. **Reproducibilidad**: Mismo entorno en todos los equipos
3. **Profesionalismo**: Demuestra conocimiento de DevOps
4. **Fácil demostración**: Un solo comando para ejecutar todo
5. **Sin conflictos**: Dependencias aisladas del sistema host

## 📌 Notas Importantes

- El entorno virtual `ml_threat_dashboard/` ya está en `.gitignore` y no se subirá a GitHub
- Los modelos activos (`real_traffic_model.pkl`, etc.) SÍ se incluyen en el repo
- Los modelos grandes no utilizados fueron eliminados para reducir el tamaño del repo
- Docker maneja todas las dependencias automáticamente
