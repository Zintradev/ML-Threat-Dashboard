# 🚀 QUICK START GUIDE

## 📋 Prerequisitos
- **Docker** (opcional, recomendado para despliegue rápido)
- **Python 3.9+** y entorno virtual
- **Node.js** (para el frontend)

## 🛠️ Backend (ya corregido)
El archivo `backend/main.py` está corregido y listo para ejecutarse. No necesitas hacer cambios manuales.

## � Opción 1: Ejecutar con Docker (recomendado)
```powershell
# Desde la raíz del proyecto
docker-compose up --build
```
- **Frontend:** http://localhost:3000
- **Backend:** http://localhost:8000

## 💻 Opción 2: Ejecutar localmente
### Backend
```powershell
cd backend
# Activar entorno virtual (ajusta la ruta si es necesario)
.\ml_threat_dashboard\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```
### Frontend
```powershell
cd frontend/ml-threat-dashboard
npm install
npm start
```

## ✅ Verificar que funciona
1. **Backend**: Navega a `http://localhost:8000` y deberías ver
   ```json
   {"message":"Real Traffic ML Detection v2.2","status":"operational"}
   ```
2. **Frontend**: Abre `http://localhost:3000` y el dashboard debería cargar.
3. **Documentación API**: `http://localhost:8000/docs` muestra la UI interactiva.

## � Próximos pasos
- Entrenar el modelo con datos reales: `python backend/train_model.py`
- Explorar la API y personalizar reglas.

## 🛠️ Solución de problemas
- **Model file not found**: Ejecuta el script de entrenamiento para generar `real_traffic_model.pkl`.
- **Port 3000 already in use**: Cambia el puerto en `docker-compose.yml` o libera el puerto.
- **Docker no está instalado**: Instala Docker Desktop desde https:
