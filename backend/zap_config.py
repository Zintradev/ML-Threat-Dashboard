ZAP_CONFIG = {
    'api_key': 'your-api-key-here',
    'proxy_address': '127.0.0.1',
    'proxy_port': 8080,
    'timeout': 300  # 5 minutos para escaneos largos
}

# Iniciar ZAP automáticamente
def start_zap_daemon():
    import subprocess
    subprocess.Popen(['zap.sh', '-daemon', '-port', '8080', '-host', '127.0.0.1', '-config', 'api.disablekey=true'])