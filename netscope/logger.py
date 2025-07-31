"""
Radar Digital - Logger Module
Módulo para registro de logs com timestamp e diferentes níveis de severidade.
"""

import logging
import os
from datetime import datetime
from typing import Dict, Any

class Logger:
    """
    Gerenciador de logs para o projeto Radar Digital.
    
    Configura loggers para diferentes propósitos:
    - Log principal do sistema
    - Log de resultados de varredura
    - Log de alertas de segurança
    """
    
    def __init__(self, log_dir: str = "logs"):
        """
        Inicializa o logger.
        
        Args:
            log_dir: Diretório onde os arquivos de log serão salvos.
        """
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        
        self._setup_main_logger()
        self._setup_scan_logger()
        self._setup_threat_logger()
        
    def _setup_main_logger(self):
        """
        Configura o logger principal do sistema.
        """
        self.main_logger = logging.getLogger("main_logger")
        self.main_logger.setLevel(logging.INFO)
        
        if not self.main_logger.handlers:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler = logging.FileHandler(os.path.join(self.log_dir, "radar_digital.log"))
            file_handler.setFormatter(formatter)
            self.main_logger.addHandler(file_handler)
            
            # Adiciona handler para console também
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            self.main_logger.addHandler(stream_handler)
            
    def _setup_scan_logger(self):
        """
        Configura o logger para resultados de varredura.
        """
        self.scan_logger = logging.getLogger("scan_logger")
        self.scan_logger.setLevel(logging.INFO)
        
        if not self.scan_logger.handlers:
            formatter = logging.Formatter(
                '%(asctime)s - %(message)s'
            )
            file_handler = logging.FileHandler(os.path.join(self.log_dir, "scan_results.log"))
            file_handler.setFormatter(formatter)
            self.scan_logger.addHandler(file_handler)
            
    def _setup_threat_logger(self):
        """
        Configura o logger para alertas de segurança.
        """
        self.threat_logger = logging.getLogger("threat_logger")
        self.threat_logger.setLevel(logging.WARNING)
        
        if not self.threat_logger.handlers:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler = logging.FileHandler(os.path.join(self.log_dir, "threats.log"))
            file_handler.setFormatter(formatter)
            self.threat_logger.addHandler(file_handler)
            
    def log_info(self, message: str):
        """
        Registra uma mensagem informativa no log principal.
        """
        self.main_logger.info(message)
        
    def log_warning(self, message: str):
        """
        Registra uma mensagem de aviso no log principal.
        """
        self.main_logger.warning(message)
        
    def log_error(self, message: str):
        """
        Registra uma mensagem de erro no log principal.
        """
        self.main_logger.error(message)
        
    def log_scan_result(self, result: Dict[str, Any]):
        """
        Registra um resultado de varredura.
        """
        self.scan_logger.info(f"SCAN_RESULT: {result}")
        
    def log_threat_alert(self, alert: Dict[str, Any]):
        """
        Registra um alerta de ameaça.
        """
        self.threat_logger.warning(f"THREAT_ALERT: {alert}")


def main():
    """Função de teste para o módulo logger."""
    logger = Logger()
    
    print("=== Radar Digital - Logger Test ===")
    
    logger.log_info("Iniciando teste do logger.")
    logger.log_warning("Esta é uma mensagem de aviso.")
    logger.log_error("Este é um erro simulado.")
    
    test_scan_data = {
        "ip": "192.168.1.1",
        "open_ports": [
            {"port": 80, "service": "HTTP"},
            {"port": 443, "service": "HTTPS"}
        ]
    }
    logger.log_scan_result(test_scan_data)
    
    test_alert_data = {
        "type": "SUSPICIOUS_PORT",
        "severity": "HIGH",
        "port": 135,
        "description": "Porta RPC aberta"
    }
    logger.log_threat_alert(test_alert_data)
    
    logger.log_info("Teste do logger concluído.")


if __name__ == "__main__":
    main()

