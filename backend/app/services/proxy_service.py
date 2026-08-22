import subprocess
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class ProxyService:
    def __init__(self):
        self.proxy: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        self.stop()
        try:
            self.proxy = subprocess.Popen([
                "mitmdump", "-p", "8080", "--set", "listen_host=0.0.0.0", "-s", "mitmproxy_addon.py", "-q"
            ])
            time.sleep(2)
            if self.proxy.poll() is not None:
                logger.error("Failed to start mitmdump process.")
                return False
            logger.info("Proxy started successfully on 0.0.0.0:8080")
            return True
        except Exception as e:
            logger.error(f"Error starting proxy service: {e}")
            return False

    def stop(self) -> None:
        if self.proxy:
            try:
                self.proxy.terminate()
                self.proxy.wait(timeout=5)
                logger.info("Proxy stopped.")
            except Exception as e:
                logger.error(f"Error stopping proxy: {e}")
            finally:
                self.proxy = None

    def is_running(self) -> bool:
        return self.proxy is not None and self.proxy.poll() is None
