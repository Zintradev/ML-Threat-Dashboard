@echo off
chcp 65001
echo Desactivando proxy del sistema...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
echo ✅ Proxy DESACTIVADO
echo 🎯 Ahora puedes navegar normalmente
pause