"""
Testes unitários para o módulo scanner.py
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
import subprocess
import sys
import os

# Adiciona o diretório pai ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscope.scanner import NetworkScanner


class TestNetworkScanner(unittest.TestCase):
    """Testes para a classe NetworkScanner."""
    
    def setUp(self):
        """Configuração inicial para os testes."""
        self.scanner = NetworkScanner(timeout=0.5, max_threads=10)
    
    def test_init(self):
        """Testa a inicialização do scanner."""
        self.assertEqual(self.scanner.timeout, 0.5)
        self.assertEqual(self.scanner.max_threads, 10)
        self.assertIsInstance(self.scanner.common_ports, list)
        self.assertIsInstance(self.scanner.service_map, dict)
        self.assertIn(80, self.scanner.common_ports)
        self.assertEqual(self.scanner.service_map[80], "HTTP")
    
    @patch('subprocess.run')
    def test_ping_host_success(self, mock_run):
        """Testa ping bem-sucedido."""
        mock_run.return_value.returncode = 0
        result = self.scanner.ping_host("127.0.0.1")
        self.assertTrue(result)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_ping_host_failure(self, mock_run):
        """Testa ping que falha."""
        mock_run.return_value.returncode = 1
        result = self.scanner.ping_host("192.168.999.999")
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_ping_host_timeout(self, mock_run):
        """Testa ping com timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("ping", 1)
        result = self.scanner.ping_host("127.0.0.1")
        self.assertFalse(result)
    
    @patch('socket.socket')
    def test_scan_tcp_port_open(self, mock_socket):
        """Testa varredura de porta TCP aberta."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        
        result = self.scanner.scan_tcp_port("127.0.0.1", 80)
        
        self.assertIsNotNone(result)
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["service"], "HTTP")
        self.assertIn("response_time", result)
    
    @patch('socket.socket')
    def test_scan_tcp_port_closed(self, mock_socket):
        """Testa varredura de porta TCP fechada."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1  # Conexão recusada
        
        result = self.scanner.scan_tcp_port("127.0.0.1", 12345)
        
        self.assertIsNone(result)
    
    @patch('socket.socket')
    def test_scan_tcp_port_exception(self, mock_socket):
        """Testa varredura de porta TCP com exceção."""
        mock_socket.side_effect = socket.error("Network error")
        
        result = self.scanner.scan_tcp_port("127.0.0.1", 80)
        
        self.assertIsNone(result)
    
    @patch('socket.gethostbyaddr')
    def test_get_hostname_success(self, mock_gethostbyaddr):
        """Testa resolução de hostname bem-sucedida."""
        mock_gethostbyaddr.return_value = ("localhost", [], ["127.0.0.1"])
        
        hostname = self.scanner._get_hostname("127.0.0.1")
        
        self.assertEqual(hostname, "localhost")
    
    @patch('socket.gethostbyaddr')
    def test_get_hostname_failure(self, mock_gethostbyaddr):
        """Testa resolução de hostname que falha."""
        mock_gethostbyaddr.side_effect = socket.herror("Host not found")
        
        hostname = self.scanner._get_hostname("192.168.999.999")
        
        self.assertIsNone(hostname)
    
    @patch('socket.socket')
    def test_get_network_info(self, mock_socket):
        """Testa obtenção de informações da rede."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
        
        with patch('socket.gethostname', return_value="test-host"):
            network_info = self.scanner.get_network_info()
        
        self.assertEqual(network_info["local_ip"], "192.168.1.100")
        self.assertEqual(network_info["suggested_network"], "192.168.1.0/24")
        self.assertEqual(network_info["hostname"], "test-host")
    
    def test_scan_network_invalid_format(self):
        """Testa varredura com formato de rede inválido."""
        with self.assertRaises(ValueError):
            self.scanner.scan_network("invalid_network")
    
    @patch.object(NetworkScanner, 'scan_host_ports')
    def test_scan_network_valid(self, mock_scan_host):
        """Testa varredura de rede válida."""
        # Mock para retornar um host ativo
        mock_scan_host.return_value = {
            "ip": "192.168.1.1",
            "hostname": "router",
            "is_alive": True,
            "open_ports": [{"port": 80, "service": "HTTP"}],
            "scan_time": 1234567890
        }
        
        results = self.scanner.scan_network("192.168.1.1/32")
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip"], "192.168.1.1")
        self.assertTrue(results[0]["is_alive"])
    
    @patch.object(NetworkScanner, 'ping_host')
    @patch.object(NetworkScanner, 'scan_tcp_port')
    @patch.object(NetworkScanner, '_get_hostname')
    def test_scan_host_ports(self, mock_hostname, mock_tcp_scan, mock_ping):
        """Testa varredura de portas de um host."""
        mock_ping.return_value = True
        mock_hostname.return_value = "test-host"
        mock_tcp_scan.return_value = {
            "port": 80, "protocol": "TCP", "state": "open", 
            "service": "HTTP", "response_time": 5.0
        }
        
        result = self.scanner.scan_host_ports("192.168.1.1", [80])
        
        self.assertEqual(result["ip"], "192.168.1.1")
        self.assertEqual(result["hostname"], "test-host")
        self.assertTrue(result["is_alive"])
        self.assertEqual(len(result["open_ports"]), 1)
        self.assertEqual(result["open_ports"][0]["port"], 80)
    
    def test_scan_port_range(self):
        """Testa varredura de range de portas."""
        with patch.object(self.scanner, 'scan_host_ports') as mock_scan:
            mock_scan.return_value = {
                "open_ports": [
                    {"port": 80, "service": "HTTP"},
                    {"port": 443, "service": "HTTPS"}
                ]
            }
            
            result = self.scanner.scan_port_range("127.0.0.1", 80, 443)
            
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["port"], 80)
            self.assertEqual(result[1]["port"], 443)


class TestNetworkScannerIntegration(unittest.TestCase):
    """Testes de integração para NetworkScanner."""
    
    def setUp(self):
        """Configuração inicial para os testes de integração."""
        self.scanner = NetworkScanner(timeout=0.1, max_threads=5)
    
    def test_scan_localhost(self):
        """Testa varredura do localhost (teste de integração real)."""
        result = self.scanner.scan_host_ports("127.0.0.1", [80, 443, 22])
        
        self.assertEqual(result["ip"], "127.0.0.1")
        self.assertIsInstance(result["is_alive"], bool)
        self.assertIsInstance(result["open_ports"], list)
        self.assertIn("scan_time", result)
    
    def test_get_network_info_real(self):
        """Testa obtenção real de informações da rede."""
        network_info = self.scanner.get_network_info()
        
        self.assertIn("local_ip", network_info)
        self.assertIn("suggested_network", network_info)
        self.assertIn("hostname", network_info)
        
        # Verifica se o IP local é válido
        import ipaddress
        try:
            ipaddress.ip_address(network_info["local_ip"])
        except ValueError:
            self.fail("IP local inválido")


if __name__ == '__main__':
    # Executa os testes
    unittest.main(verbosity=2)

