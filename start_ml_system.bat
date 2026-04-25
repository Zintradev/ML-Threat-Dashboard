@echo off
chcp 65001
echo ========================================
echo    ML THREAT - REAL TRAFFIC CAPTURE
echo ========================================
echo.

echo 🔧 Cerrando procesos anteriores...
taskkill /f /im python.exe >nul 2>&1
taskkill /f /im mitmproxy.exe >nul 2>&1
taskkill /f /im mitmdump.exe >nul 2>&1
timeout /t 3

echo 🚀 Iniciando Backend con captura REAL...
start "BACKEND" cmd /k "cd /d %CD%\backend && ..\ml_threat_dashboard\Scripts\activate && python main.py"

echo ⏳ Esperando backend (10 segundos)...
timeout /t 10

echo 🎨 Iniciando Frontend...
start "FRONTEND" cmd /k "cd /d %CD%\frontend\ml-threat-dashboard && set BROWSER=none && npm start"

echo ⏳ Esperando frontend (8 segundos)...
timeout /t 8

echo 🌐 ACTIVANDO PROXY SISTEMA CON EXCEPCIONES...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:8080" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "localhost;127.0.0.1;*.local" /f

echo 📊 Abriendo Dashboard...
timeout /t 3
start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" "http://localhost:3000"

echo.
echo ✅ SISTEMA LISTO PARA TRÁFICO REAL!
echo.
echo 🎯 INSTRUCCIONES:
echo 1. En el dashboard, haz clic en "Start MITMProxy & Scan"
echo 2. En el MISMO Chrome, abre nueva pestaña
echo 3. Ve a: http://testphp.vulnweb.com
echo 4. Para probar detecciones:
echo    - Recarga RÁPIDO 20 veces (DoS)
echo    - Navega por muchos enlaces (Probing)  
echo    - Usa URLs con parámetros extraños
echo 5. El ML detectará patrones REALES
echo.
echo 💡 También puedes usar POST /attack/simulate para pruebas
echo.
pause