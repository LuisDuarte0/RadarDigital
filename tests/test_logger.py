"""
Testes unitários para o módulo logger.py
"""

import unittest
import tempfile
import shutil
import os
import sys
from unittest.mock import patch, MagicMock

# Adiciona o diretório pai ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscope.logger import Logger


class TestLogger(unittest.TestCase):
    """Testes para a classe Logger."""
    
    def setUp(self):
        """Configuração inicial para os testes."""
        # Cria diretório temporário para os testes
        self.test_dir = tempfile.mkdtemp()
        self.logger = Logger(log_dir=self.test_dir)
    
    def tearDown(self):
        """Limpeza após os testes."""
        # Remove diretório temporário
        shutil.rmtree(self.test_dir)
    
    def test_init(self):
        """Testa a inicialização do logger."""
        # Verifica se o diretório foi criado
        self.assertTrue(os.path.exists(self.test_dir))
        
        # Verifica se os loggers foram configurados
        self.assertIsNotNone(self.logger.main_logger)
        self.assertIsNotNone(self.logger.scan_logger)
        self.assertIsNotNone(self.logger.threat_logger)
        
        # Verifica se os arquivos de log existem após primeira escrita
        self.logger.log_info("Test message")
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "radar_digital.log")))
    
    def test_log_info(self):
        """Testa logging de mensagens informativas."""
        test_message = "Test info message"
        self.logger.log_info(test_message)
        
        # Verifica se a mensagem foi escrita no arquivo
        log_file = os.path.join(self.test_dir, "radar_digital.log")
        self.assertTrue(os.path.exists(log_file))
        
        with open(log_file, 'r') as f:
            content = f.read()
            self.assertIn(test_message, content)
            self.assertIn("INFO", content)
    
    def test_log_warning(self):
        """Testa logging de mensagens de aviso."""
        test_message = "Test warning message"
        self.logger.log_warning(test_message)
        
        # Verifica se a mensagem foi escrita no arquivo
        log_file = os.path.join(self.test_dir, "radar_digital.log")
        with open(log_file, 'r') as f:
            content = f.read()
            self.assertIn(test_message, content)
            self.assertIn("WARNING", content)
    
    def test_log_error(self):
        """Testa logging de mensagens de erro."""
        test_message = "Test error message"
        self.logger.log_error(test_message)
        
        # Verifica se a mensagem foi escrita no arquivo
        log_file = os.path.join(self.test_dir, "radar_digital.log")
        with open(log_file, 'r') as f:
            content = f.read()
            self.assertIn(test_message, content)
            self.assertIn("ERROR", content)
    
    def test_log_scan_result(self):
        """Testa logging de resultados de varredura."""
        test_result = {
            "ip": "192.168.1.100",
            "open_ports": [
                {"port": 80, "service": "HTTP"},
                {"port": 443, "service": "HTTPS"}
            ]
        }
        
        self.logger.log_scan_result(test_result)
        
        # Verifica se o resultado foi escrito no arquivo
        log_file = os.path.join(self.test_dir, "scan_results.log")
        self.assertTrue(os.path.exists(log_file))
        
        with open(log_file, 'r') as f:
            content = f.read()
            self.assertIn("SCAN_RESULT", content)
            self.assertIn("192.168.1.100", content)
    
    def test_log_threat_alert(self):
        """Testa logging de alertas de ameaça."""
        test_alert = {
            "type": "SUSPICIOUS_PORT",
            "severity": "HIGH",
            "port": 135,
            "description": "Porta RPC aberta"
        }
        
        self.logger.log_threat_alert(test_alert)
        
        # Verifica se o alerta foi escrito no arquivo
        log_file = os.path.join(self.test_dir, "threats.log")
        self.assertTrue(os.path.exists(log_file))
        
        with open(log_file, 'r') as f:
            content = f.read()
            self.assertIn("THREAT_ALERT", content)
            self.assertIn("SUSPICIOUS_PORT", content)
            self.assertIn("WARNING", content)  # Nível do threat_logger
    
    def test_multiple_log_entries(self):
        """Testa múltiplas entradas de log."""
        messages = ["Message 1", "Message 2", "Message 3"]
        
        for msg in messages:
            self.logger.log_info(msg)
        
        log_file = os.path.join(self.test_dir, "radar_digital.log")
        with open(log_file, 'r') as f:
            content = f.read()
            for msg in messages:
                self.assertIn(msg, content)
    
    def test_log_file_format(self):
        """Testa o formato das entradas de log."""
        test_message = "Format test message"
        self.logger.log_info(test_message)
        
        log_file = os.path.join(self.test_dir, "radar_digital.log")
        with open(log_file, 'r') as f:
            content = f.read().strip()
            
            # Verifica se contém timestamp, logger name, level e message
            self.assertRegex(content, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}')  # Timestamp
            self.assertIn("main_logger", content)  # Logger name
            self.assertIn("INFO", content)  # Level
            self.assertIn(test_message, content)  # Message
    
    def test_scan_log_format(self):
        """Testa o formato do log de varreduras."""
        test_result = {"test": "data"}
        self.logger.log_scan_result(test_result)
        
        log_file = os.path.join(self.test_dir, "scan_results.log")
        with open(log_file, 'r') as f:
            content = f.read().strip()
            
            # Verifica formato mais simples (apenas timestamp e message)
            self.assertRegex(content, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}')  # Timestamp
            self.assertIn("SCAN_RESULT", content)
    
    def test_threat_log_format(self):
        """Testa o formato do log de ameaças."""
        test_alert = {"type": "TEST_ALERT"}
        self.logger.log_threat_alert(test_alert)
        
        log_file = os.path.join(self.test_dir, "threats.log")
        with open(log_file, 'r') as f:
            content = f.read().strip()
            
            # Verifica formato com timestamp, level e message
            self.assertRegex(content, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}')  # Timestamp
            self.assertIn("WARNING", content)  # Level
            self.assertIn("THREAT_ALERT", content)
    
    def test_log_directory_creation(self):
        """Testa criação automática do diretório de logs."""
        # Testa com diretório que não existe
        non_existent_dir = os.path.join(self.test_dir, "new_logs")
        self.assertFalse(os.path.exists(non_existent_dir))
        
        # Cria logger com diretório inexistente
        logger = Logger(log_dir=non_existent_dir)
        
        # Verifica se o diretório foi criado
        self.assertTrue(os.path.exists(non_existent_dir))
        
        # Testa se funciona normalmente
        logger.log_info("Test message")
        log_file = os.path.join(non_existent_dir, "radar_digital.log")
        self.assertTrue(os.path.exists(log_file))
    
    def test_logger_handlers_not_duplicated(self):
        """Testa se handlers não são duplicados em múltiplas instâncias."""
        # Primeira instância
        logger1 = Logger(log_dir=self.test_dir)
        initial_handlers = len(logger1.main_logger.handlers)
        
        # Segunda instância (mesmo diretório)
        logger2 = Logger(log_dir=self.test_dir)
        final_handlers = len(logger2.main_logger.handlers)
        
        # Handlers não devem ser duplicados
        self.assertEqual(initial_handlers, final_handlers)
    
    def test_complex_data_logging(self):
        """Testa logging de dados complexos."""
        complex_scan_result = {
            "ip": "192.168.1.100",
            "hostname": "test-server",
            "is_alive": True,
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "HTTP",
                    "response_time": 2.5
                },
                {
                    "port": 443,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "HTTPS",
                    "response_time": 3.1
                }
            ],
            "scan_time": 1234567890
        }
        
        complex_alert = {
            "type": "MULTIPLE_VULNERABILITIES",
            "severity": "CRITICAL",
            "host": "192.168.1.100",
            "vulnerabilities": [
                {"port": 135, "service": "RPC", "risk": "HIGH"},
                {"port": 445, "service": "SMB", "risk": "CRITICAL"}
            ],
            "timestamp": "2024-01-01T12:00:00Z",
            "recommendations": [
                "Fechar porta 135",
                "Atualizar SMB",
                "Implementar firewall"
            ]
        }
        
        # Testa logging de dados complexos
        self.logger.log_scan_result(complex_scan_result)
        self.logger.log_threat_alert(complex_alert)
        
        # Verifica se os dados foram escritos corretamente
        scan_log = os.path.join(self.test_dir, "scan_results.log")
        threat_log = os.path.join(self.test_dir, "threats.log")
        
        with open(scan_log, 'r') as f:
            scan_content = f.read()
            self.assertIn("test-server", scan_content)
            self.assertIn("HTTP", scan_content)
            self.assertIn("HTTPS", scan_content)
        
        with open(threat_log, 'r') as f:
            threat_content = f.read()
            self.assertIn("MULTIPLE_VULNERABILITIES", threat_content)
            self.assertIn("CRITICAL", threat_content)
            self.assertIn("SMB", threat_content)


class TestLoggerIntegration(unittest.TestCase):
    """Testes de integração para Logger."""
    
    def setUp(self):
        """Configuração inicial para os testes de integração."""
        self.test_dir = tempfile.mkdtemp()
        self.logger = Logger(log_dir=self.test_dir)
    
    def tearDown(self):
        """Limpeza após os testes."""
        shutil.rmtree(self.test_dir)
    
    def test_real_world_logging_scenario(self):
        """Testa cenário real de logging."""
        # Simula uma sequência de eventos de varredura
        self.logger.log_info("Iniciando varredura de rede 192.168.1.0/24")
        
        # Simula resultados de varredura
        scan_results = [
            {
                "ip": "192.168.1.1",
                "hostname": "router",
                "is_alive": True,
                "open_ports": [{"port": 80, "service": "HTTP"}]
            },
            {
                "ip": "192.168.1.100",
                "hostname": "server",
                "is_alive": True,
                "open_ports": [
                    {"port": 22, "service": "SSH"},
                    {"port": 135, "service": "RPC"}
                ]
            }
        ]
        
        for result in scan_results:
            self.logger.log_scan_result(result)
        
        # Simula alertas de ameaça
        alerts = [
            {
                "type": "SUSPICIOUS_PORT",
                "severity": "HIGH",
                "host": "192.168.1.100",
                "port": 135,
                "description": "Porta RPC suspeita detectada"
            }
        ]
        
        for alert in alerts:
            self.logger.log_threat_alert(alert)
        
        self.logger.log_info("Varredura concluída")
        
        # Verifica se todos os arquivos foram criados
        main_log = os.path.join(self.test_dir, "radar_digital.log")
        scan_log = os.path.join(self.test_dir, "scan_results.log")
        threat_log = os.path.join(self.test_dir, "threats.log")
        
        self.assertTrue(os.path.exists(main_log))
        self.assertTrue(os.path.exists(scan_log))
        self.assertTrue(os.path.exists(threat_log))
        
        # Verifica conteúdo dos logs
        with open(main_log, 'r') as f:
            main_content = f.read()
            self.assertIn("Iniciando varredura", main_content)
            self.assertIn("Varredura concluída", main_content)
        
        with open(scan_log, 'r') as f:
            scan_content = f.read()
            self.assertIn("192.168.1.1", scan_content)
            self.assertIn("192.168.1.100", scan_content)
            self.assertIn("router", scan_content)
            self.assertIn("server", scan_content)
        
        with open(threat_log, 'r') as f:
            threat_content = f.read()
            self.assertIn("SUSPICIOUS_PORT", threat_content)
            self.assertIn("192.168.1.100", threat_content)
            self.assertIn("RPC suspeita", threat_content)
    
    def test_concurrent_logging(self):
        """Testa logging concorrente (simulado)."""
        import threading
        import time
        
        def log_worker(worker_id):
            for i in range(10):
                self.logger.log_info(f"Worker {worker_id} - Message {i}")
                time.sleep(0.01)  # Pequena pausa
        
        # Cria múltiplas threads para simular logging concorrente
        threads = []
        for i in range(3):
            thread = threading.Thread(target=log_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Aguarda todas as threads terminarem
        for thread in threads:
            thread.join()
        
        # Verifica se todas as mensagens foram escritas
        log_file = os.path.join(self.test_dir, "radar_digital.log")
        with open(log_file, 'r') as f:
            content = f.read()
            
            # Verifica se há mensagens de todos os workers
            for worker_id in range(3):
                self.assertIn(f"Worker {worker_id}", content)
            
            # Conta o número total de mensagens
            message_count = content.count("Worker")
            self.assertEqual(message_count, 30)  # 3 workers * 10 messages each


if __name__ == '__main__':
    # Executa os testes
    unittest.main(verbosity=2)

