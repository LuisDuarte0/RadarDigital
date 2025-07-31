"""
Testes unitários para o módulo analyzer.py
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
from datetime import datetime

# Adiciona o diretório pai ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscope.analyzer import ThreatAnalyzer


class TestThreatAnalyzer(unittest.TestCase):
    """Testes para a classe ThreatAnalyzer."""
    
    def setUp(self):
        """Configuração inicial para os testes."""
        self.analyzer = ThreatAnalyzer()
        
        # Dados de teste para um host
        self.test_host_data = {
            "ip": "192.168.1.100",
            "hostname": "test-server",
            "is_alive": True,
            "open_ports": [
                {"port": 22, "protocol": "TCP", "state": "open", "service": "SSH", "response_time": 5.2},
                {"port": 80, "protocol": "TCP", "state": "open", "service": "HTTP", "response_time": 2.1}
            ],
            "scan_time": 1234567890
        }
        
        # Dados de teste para host com vulnerabilidades
        self.vulnerable_host_data = {
            "ip": "192.168.1.200",
            "hostname": "vulnerable-server",
            "is_alive": True,
            "open_ports": [
                {"port": 135, "protocol": "TCP", "state": "open", "service": "RPC", "response_time": 10.5},
                {"port": 445, "protocol": "TCP", "state": "open", "service": "SMB", "response_time": 8.3},
                {"port": 3389, "protocol": "TCP", "state": "open", "service": "RDP", "response_time": 15.7},
                {"port": 23, "protocol": "TCP", "state": "open", "service": "Telnet", "response_time": 12.1}
            ],
            "scan_time": 1234567890
        }
    
    def test_init(self):
        """Testa a inicialização do analisador."""
        self.assertIsInstance(self.analyzer.suspicious_ports, dict)
        self.assertIsInstance(self.analyzer.high_risk_services, dict)
        self.assertIsInstance(self.analyzer.uncommon_ports, set)
        self.assertIsInstance(self.analyzer.baseline_data, dict)
        self.assertIsInstance(self.analyzer.alert_history, list)
        
        # Verifica se algumas portas suspeitas estão definidas
        self.assertIn(135, self.analyzer.suspicious_ports)
        self.assertIn(445, self.analyzer.suspicious_ports)
        
        # Verifica se alguns serviços de alto risco estão definidos
        self.assertIn("Telnet", self.analyzer.high_risk_services)
        self.assertIn("SMB", self.analyzer.high_risk_services)
    
    def test_analyze_host_safe(self):
        """Testa análise de host seguro."""
        analysis = self.analyzer.analyze_host(self.test_host_data)
        
        self.assertEqual(analysis["ip"], "192.168.1.100")
        self.assertEqual(analysis["hostname"], "test-server")
        self.assertEqual(analysis["risk_level"], "LOW")
        self.assertIsInstance(analysis["alerts"], list)
        self.assertIsInstance(analysis["vulnerabilities"], list)
        self.assertIsInstance(analysis["recommendations"], list)
        self.assertIsInstance(analysis["security_score"], int)
        self.assertGreaterEqual(analysis["security_score"], 0)
        self.assertLessEqual(analysis["security_score"], 100)
    
    def test_analyze_host_vulnerable(self):
        """Testa análise de host vulnerável."""
        analysis = self.analyzer.analyze_host(self.vulnerable_host_data)
        
        self.assertEqual(analysis["ip"], "192.168.1.200")
        self.assertIn(analysis["risk_level"], ["MEDIUM", "HIGH", "CRITICAL"])
        self.assertGreater(len(analysis["alerts"]), 0)
        self.assertGreater(len(analysis["vulnerabilities"]), 0)
        self.assertLess(analysis["security_score"], 100)
        
        # Verifica se alertas específicos foram gerados
        alert_types = [alert["type"] for alert in analysis["alerts"]]
        self.assertIn("SUSPICIOUS_PORT", alert_types)
        self.assertIn("HIGH_RISK_SERVICE", alert_types)
    
    def test_analyze_host_no_ports(self):
        """Testa análise de host sem portas abertas."""
        host_data = {
            "ip": "192.168.1.50",
            "hostname": "secure-host",
            "is_alive": True,
            "open_ports": [],
            "scan_time": 1234567890
        }
        
        analysis = self.analyzer.analyze_host(host_data)
        
        self.assertEqual(analysis["risk_level"], "LOW")
        self.assertEqual(len(analysis["alerts"]), 0)
        self.assertEqual(len(analysis["vulnerabilities"]), 0)
        self.assertEqual(analysis["security_score"], 100)
        self.assertIn("Host sem portas abertas", analysis["recommendations"][0])
    
    def test_analyze_suspicious_ports(self):
        """Testa análise de portas suspeitas."""
        open_ports = [
            {"port": 135, "service": "RPC"},
            {"port": 445, "service": "SMB"}
        ]
        
        findings = self.analyzer._analyze_suspicious_ports(open_ports)
        
        self.assertEqual(len(findings["alerts"]), 2)
        self.assertEqual(len(findings["vulnerabilities"]), 2)
        
        # Verifica se os alertas têm a estrutura correta
        for alert in findings["alerts"]:
            self.assertIn("type", alert)
            self.assertIn("severity", alert)
            self.assertIn("port", alert)
            self.assertIn("description", alert)
            self.assertEqual(alert["type"], "SUSPICIOUS_PORT")
    
    def test_analyze_high_risk_services(self):
        """Testa análise de serviços de alto risco."""
        open_ports = [
            {"port": 23, "service": "Telnet"},
            {"port": 21, "service": "FTP"}
        ]
        
        findings = self.analyzer._analyze_high_risk_services(open_ports)
        
        self.assertGreater(len(findings["alerts"]), 0)
        self.assertGreater(len(findings["vulnerabilities"]), 0)
        
        # Verifica se Telnet foi marcado como crítico
        telnet_alerts = [a for a in findings["alerts"] if a["service"] == "Telnet"]
        self.assertEqual(len(telnet_alerts), 1)
        self.assertEqual(telnet_alerts[0]["severity"], "CRITICAL")
    
    def test_analyze_uncommon_ports(self):
        """Testa análise de portas incomuns."""
        # Muitas portas incomuns
        open_ports = [
            {"port": 12345, "service": "Unknown"},
            {"port": 54321, "service": "Unknown"},
            {"port": 9999, "service": "Unknown"},
            {"port": 8888, "service": "Unknown"}
        ]
        
        findings = self.analyzer._analyze_uncommon_ports(open_ports)
        
        self.assertEqual(len(findings["alerts"]), 1)
        self.assertEqual(findings["alerts"][0]["type"], "MULTIPLE_UNCOMMON_PORTS")
        self.assertEqual(findings["alerts"][0]["severity"], "MEDIUM")
    
    def test_analyze_service_configuration(self):
        """Testa análise de configuração de serviços."""
        # HTTP sem HTTPS
        open_ports = [{"port": 80, "service": "HTTP"}]
        recommendations = self.analyzer._analyze_service_configuration(open_ports)
        self.assertTrue(any("HTTPS" in rec for rec in recommendations))
        
        # Banco de dados exposto
        open_ports = [{"port": 3306, "service": "MySQL"}]
        recommendations = self.analyzer._analyze_service_configuration(open_ports)
        self.assertTrue(any("Bancos de dados" in rec for rec in recommendations))
        
        # SSH na porta padrão
        open_ports = [{"port": 22, "service": "SSH"}]
        recommendations = self.analyzer._analyze_service_configuration(open_ports)
        self.assertTrue(any("porta padrão" in rec for rec in recommendations))
    
    def test_calculate_risk_level(self):
        """Testa cálculo do nível de risco."""
        # Risco crítico
        critical_alerts = [{"severity": "CRITICAL"}]
        risk = self.analyzer._calculate_risk_level(critical_alerts, [])
        self.assertEqual(risk, "CRITICAL")
        
        # Risco alto
        high_alerts = [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "HIGH"}]
        risk = self.analyzer._calculate_risk_level(high_alerts, [])
        self.assertEqual(risk, "HIGH")
        
        # Risco médio
        medium_alerts = [{"severity": "HIGH"}]
        risk = self.analyzer._calculate_risk_level(medium_alerts, [])
        self.assertEqual(risk, "MEDIUM")
        
        # Risco baixo
        low_alerts = [{"severity": "LOW"}]
        risk = self.analyzer._calculate_risk_level(low_alerts, [])
        self.assertEqual(risk, "LOW")
    
    def test_calculate_security_score(self):
        """Testa cálculo do score de segurança."""
        # Score máximo (sem alertas)
        score = self.analyzer._calculate_security_score([], [])
        self.assertEqual(score, 100)
        
        # Score com alertas críticos
        critical_alerts = [{"severity": "CRITICAL"}]
        score = self.analyzer._calculate_security_score(critical_alerts, [])
        self.assertEqual(score, 75)  # 100 - 25
        
        # Score com múltiplos alertas
        mixed_alerts = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"}
        ]
        score = self.analyzer._calculate_security_score(mixed_alerts, [])
        self.assertEqual(score, 50)  # 100 - 25 - 15 - 10
        
        # Score mínimo (não pode ser negativo)
        many_alerts = [{"severity": "CRITICAL"}] * 10
        score = self.analyzer._calculate_security_score(many_alerts, [])
        self.assertEqual(score, 0)
    
    def test_analyze_network(self):
        """Testa análise de rede completa."""
        scan_results = [self.test_host_data, self.vulnerable_host_data]
        
        network_analysis = self.analyzer.analyze_network(scan_results)
        
        self.assertEqual(network_analysis["total_hosts"], 2)
        self.assertEqual(network_analysis["active_hosts"], 2)
        self.assertGreater(network_analysis["total_open_ports"], 0)
        self.assertIsInstance(network_analysis["risk_distribution"], dict)
        self.assertIsInstance(network_analysis["top_vulnerabilities"], list)
        self.assertIsInstance(network_analysis["network_alerts"], list)
        self.assertIsInstance(network_analysis["host_analyses"], list)
        self.assertEqual(len(network_analysis["host_analyses"]), 2)
        
        # Verifica distribuição de risco
        risk_dist = network_analysis["risk_distribution"]
        total_risk_hosts = sum(risk_dist.values())
        self.assertEqual(total_risk_hosts, 2)
    
    def test_analyze_network_patterns(self):
        """Testa análise de padrões de rede."""
        # Hosts com muitas portas
        many_ports_host = {
            "ip": "192.168.1.10",
            "is_alive": True,
            "open_ports": [{"port": i, "service": "Unknown"} for i in range(1, 15)]
        }
        
        scan_results = [many_ports_host]
        alerts = self.analyzer._analyze_network_patterns(scan_results)
        
        self.assertGreater(len(alerts), 0)
        self.assertTrue(any(alert["type"] == "HOSTS_WITH_MANY_PORTS" for alert in alerts))
    
    def test_generate_recommendations(self):
        """Testa geração de recomendações."""
        # Análise de alto risco
        high_risk_analysis = {
            "risk_level": "HIGH",
            "security_score": 60,
            "vulnerabilities": [{"type": "test"}] * 6
        }
        
        recommendations = self.analyzer._generate_recommendations(high_risk_analysis)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("URGENTE" in rec for rec in recommendations))
        self.assertTrue(any("firewall" in rec for rec in recommendations))
        self.assertTrue(any("Score de segurança baixo" in rec for rec in recommendations))
        self.assertTrue(any("Múltiplas vulnerabilidades" in rec for rec in recommendations))
    
    def test_generate_report(self):
        """Testa geração de relatório."""
        network_analysis = {
            "analysis_time": datetime.now().isoformat(),
            "total_hosts": 2,
            "active_hosts": 2,
            "total_open_ports": 6,
            "risk_distribution": {"LOW": 1, "HIGH": 1, "MEDIUM": 0, "CRITICAL": 0},
            "top_vulnerabilities": [
                {"vulnerability": "Porta Suspeita 135", "count": 1},
                {"vulnerability": "Serviço de Alto Risco: SMB", "count": 1}
            ],
            "network_alerts": [
                {"severity": "MEDIUM", "description": "Teste de alerta de rede"}
            ],
            "host_analyses": [
                {
                    "ip": "192.168.1.100",
                    "risk_level": "CRITICAL",
                    "security_score": 25,
                    "vulnerabilities": [
                        {"type": "Porta Suspeita 135", "description": "RPC exposto"},
                        {"type": "Serviço de Alto Risco: SMB", "description": "SMB vulnerável"}
                    ]
                }
            ]
        }
        
        report = self.analyzer.generate_report(network_analysis)
        
        self.assertIsInstance(report, str)
        self.assertIn("RADAR DIGITAL", report)
        self.assertIn("Total de Hosts: 2", report)
        self.assertIn("Hosts Ativos: 2", report)
        self.assertIn("DISTRIBUIÇÃO DE RISCO", report)
        self.assertIn("TOP VULNERABILIDADES", report)
        self.assertIn("HOSTS CRÍTICOS", report)


class TestThreatAnalyzerIntegration(unittest.TestCase):
    """Testes de integração para ThreatAnalyzer."""
    
    def setUp(self):
        """Configuração inicial para os testes de integração."""
        self.analyzer = ThreatAnalyzer()
    
    def test_full_analysis_workflow(self):
        """Testa o fluxo completo de análise."""
        # Simula resultados de varredura
        scan_results = [
            {
                "ip": "192.168.1.1",
                "hostname": "router",
                "is_alive": True,
                "open_ports": [
                    {"port": 80, "protocol": "TCP", "state": "open", "service": "HTTP", "response_time": 2.1},
                    {"port": 443, "protocol": "TCP", "state": "open", "service": "HTTPS", "response_time": 3.5}
                ],
                "scan_time": 1234567890
            },
            {
                "ip": "192.168.1.100",
                "hostname": "server",
                "is_alive": True,
                "open_ports": [
                    {"port": 22, "protocol": "TCP", "state": "open", "service": "SSH", "response_time": 5.2},
                    {"port": 135, "protocol": "TCP", "state": "open", "service": "RPC", "response_time": 10.5},
                    {"port": 445, "protocol": "TCP", "state": "open", "service": "SMB", "response_time": 8.3}
                ],
                "scan_time": 1234567890
            }
        ]
        
        # Executa análise completa
        network_analysis = self.analyzer.analyze_network(scan_results)
        
        # Verifica estrutura do resultado
        self.assertIn("analysis_time", network_analysis)
        self.assertIn("total_hosts", network_analysis)
        self.assertIn("active_hosts", network_analysis)
        self.assertIn("total_open_ports", network_analysis)
        self.assertIn("risk_distribution", network_analysis)
        self.assertIn("top_vulnerabilities", network_analysis)
        self.assertIn("network_alerts", network_analysis)
        self.assertIn("host_analyses", network_analysis)
        
        # Verifica que a análise detectou vulnerabilidades
        self.assertGreater(len(network_analysis["top_vulnerabilities"]), 0)
        
        # Verifica que pelo menos um host tem risco elevado
        risk_levels = [h["risk_level"] for h in network_analysis["host_analyses"]]
        self.assertTrue(any(level in ["MEDIUM", "HIGH", "CRITICAL"] for level in risk_levels))
        
        # Gera relatório
        report = self.analyzer.generate_report(network_analysis)
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 100)


if __name__ == '__main__':
    # Executa os testes
    unittest.main(verbosity=2)

