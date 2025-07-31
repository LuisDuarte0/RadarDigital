"""
Radar Digital - Threat Analyzer Module
Módulo para análise de ameaças, detecção de vulnerabilidades e geração de alertas.
"""

import time
from typing import List, Dict, Set, Tuple
from datetime import datetime, timedelta
import json


class ThreatAnalyzer:
    """
    Analisador de ameaças para identificar comportamentos suspeitos e vulnerabilidades.
    
    Realiza análises baseadas em:
    - Portas abertas incomuns
    - Serviços potencialmente vulneráveis
    - Padrões de comportamento suspeitos
    - Comparação com baselines de segurança
    """
    
    def __init__(self):
        """Inicializa o analisador de ameaças."""
        self.suspicious_ports = {
            # Portas comumente exploradas
            135: "RPC - Frequentemente explorado",
            139: "NetBIOS - Vulnerável a ataques SMB",
            445: "SMB - Alto risco de exploração",
            1433: "SQL Server - Alvo comum de ataques",
            1521: "Oracle DB - Banco de dados exposto",
            3389: "RDP - Alvo de força bruta",
            5432: "PostgreSQL - Banco de dados exposto",
            5900: "VNC - Acesso remoto inseguro",
            6379: "Redis - Frequentemente mal configurado",
            27017: "MongoDB - Banco NoSQL exposto"
        }
        
        self.high_risk_services = {
            "Telnet": "Protocolo não criptografado - CRÍTICO",
            "FTP": "Protocolo não criptografado - ALTO",
            "RPC": "Serviço frequentemente explorado - ALTO",
            "NetBIOS": "Vulnerável a ataques de rede - ALTO",
            "SMB": "Alto risco de exploração - CRÍTICO",
            "VNC": "Acesso remoto potencialmente inseguro - MÉDIO",
            "RDP": "Alvo comum de ataques - MÉDIO"
        }
        
        self.uncommon_ports = set(range(1024, 65536)) - {
            # Remove portas comuns conhecidas
            1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9090
        }
        
        self.baseline_data = {}
        self.alert_history = []
    
    def analyze_host(self, host_data: Dict) -> Dict[str, any]:
        """
        Analisa um host específico em busca de ameaças.
        
        Args:
            host_data: Dados do host retornados pelo scanner
            
        Returns:
            Dicionário com análise de segurança do host
        """
        analysis = {
            "ip": host_data["ip"],
            "hostname": host_data.get("hostname"),
            "analysis_time": datetime.now().isoformat(),
            "risk_level": "LOW",
            "alerts": [],
            "vulnerabilities": [],
            "recommendations": [],
            "security_score": 100
        }
        
        if not host_data["open_ports"]:
            analysis["recommendations"].append("Host sem portas abertas detectadas - Configuração segura")
            return analysis
        
        # Análise de portas suspeitas
        suspicious_findings = self._analyze_suspicious_ports(host_data["open_ports"])
        analysis["alerts"].extend(suspicious_findings["alerts"])
        analysis["vulnerabilities"].extend(suspicious_findings["vulnerabilities"])
        
        # Análise de serviços de alto risco
        service_findings = self._analyze_high_risk_services(host_data["open_ports"])
        analysis["alerts"].extend(service_findings["alerts"])
        analysis["vulnerabilities"].extend(service_findings["vulnerabilities"])
        
        # Análise de portas incomuns
        uncommon_findings = self._analyze_uncommon_ports(host_data["open_ports"])
        analysis["alerts"].extend(uncommon_findings["alerts"])
        
        # Análise de configuração de serviços
        config_findings = self._analyze_service_configuration(host_data["open_ports"])
        analysis["recommendations"].extend(config_findings)
        
        # Calcula nível de risco e score
        analysis["risk_level"] = self._calculate_risk_level(analysis["alerts"], analysis["vulnerabilities"])
        analysis["security_score"] = self._calculate_security_score(analysis["alerts"], analysis["vulnerabilities"])
        
        # Adiciona recomendações gerais
        analysis["recommendations"].extend(self._generate_recommendations(analysis))
        
        return analysis
    
    def analyze_network(self, scan_results: List[Dict]) -> Dict[str, any]:
        """
        Analisa uma rede completa em busca de ameaças.
        
        Args:
            scan_results: Lista de resultados de varredura
            
        Returns:
            Análise consolidada da rede
        """
        network_analysis = {
            "analysis_time": datetime.now().isoformat(),
            "total_hosts": len(scan_results),
            "active_hosts": len([h for h in scan_results if h["is_alive"]]),
            "total_open_ports": sum(len(h["open_ports"]) for h in scan_results),
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "top_vulnerabilities": [],
            "network_alerts": [],
            "host_analyses": []
        }
        
        vulnerability_counter = {}
        
        # Analisa cada host
        for host_data in scan_results:
            if host_data["is_alive"]:
                host_analysis = self.analyze_host(host_data)
                network_analysis["host_analyses"].append(host_analysis)
                
                # Conta distribuição de risco
                risk_level = host_analysis["risk_level"]
                network_analysis["risk_distribution"][risk_level] += 1
                
                # Conta vulnerabilidades
                for vuln in host_analysis["vulnerabilities"]:
                    vuln_type = vuln["type"]
                    vulnerability_counter[vuln_type] = vulnerability_counter.get(vuln_type, 0) + 1
        
        # Identifica top vulnerabilidades
        network_analysis["top_vulnerabilities"] = [
            {"vulnerability": vuln, "count": count}
            for vuln, count in sorted(vulnerability_counter.items(), 
                                    key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Análises específicas da rede
        network_analysis["network_alerts"].extend(self._analyze_network_patterns(scan_results))
        
        return network_analysis
    
    def _analyze_suspicious_ports(self, open_ports: List[Dict]) -> Dict[str, List]:
        """Analisa portas suspeitas."""
        findings = {"alerts": [], "vulnerabilities": []}
        
        for port_info in open_ports:
            port = port_info["port"]
            
            if port in self.suspicious_ports:
                alert = {
                    "type": "SUSPICIOUS_PORT",
                    "severity": "HIGH",
                    "port": port,
                    "service": port_info["service"],
                    "description": self.suspicious_ports[port],
                    "timestamp": datetime.now().isoformat()
                }
                findings["alerts"].append(alert)
                
                vulnerability = {
                    "type": f"Porta Suspeita {port}",
                    "severity": "HIGH",
                    "description": self.suspicious_ports[port],
                    "port": port,
                    "service": port_info["service"]
                }
                findings["vulnerabilities"].append(vulnerability)
        
        return findings
    
    def _analyze_high_risk_services(self, open_ports: List[Dict]) -> Dict[str, List]:
        """Analisa serviços de alto risco."""
        findings = {"alerts": [], "vulnerabilities": []}
        
        for port_info in open_ports:
            service = port_info["service"]
            
            if service in self.high_risk_services:
                severity = "CRITICAL" if "CRÍTICO" in self.high_risk_services[service] else "HIGH"
                
                alert = {
                    "type": "HIGH_RISK_SERVICE",
                    "severity": severity,
                    "port": port_info["port"],
                    "service": service,
                    "description": self.high_risk_services[service],
                    "timestamp": datetime.now().isoformat()
                }
                findings["alerts"].append(alert)
                
                vulnerability = {
                    "type": f"Serviço de Alto Risco: {service}",
                    "severity": severity,
                    "description": self.high_risk_services[service],
                    "port": port_info["port"],
                    "service": service
                }
                findings["vulnerabilities"].append(vulnerability)
        
        return findings
    
    def _analyze_uncommon_ports(self, open_ports: List[Dict]) -> Dict[str, List]:
        """Analisa portas incomuns."""
        findings = {"alerts": []}
        
        uncommon_found = []
        for port_info in open_ports:
            port = port_info["port"]
            if port > 1024 and port_info["service"] == "Unknown":
                uncommon_found.append(port)
        
        if len(uncommon_found) > 3:  # Muitas portas incomuns
            alert = {
                "type": "MULTIPLE_UNCOMMON_PORTS",
                "severity": "MEDIUM",
                "ports": uncommon_found,
                "description": f"Múltiplas portas incomuns abertas: {uncommon_found}",
                "timestamp": datetime.now().isoformat()
            }
            findings["alerts"].append(alert)
        
        return findings
    
    def _analyze_service_configuration(self, open_ports: List[Dict]) -> List[str]:
        """Analisa configuração de serviços."""
        recommendations = []
        
        services_found = [p["service"] for p in open_ports]
        
        # Verifica se há serviços HTTP sem HTTPS
        if "HTTP" in services_found and "HTTPS" not in services_found:
            recommendations.append("Considere implementar HTTPS para segurança adicional")
        
        # Verifica serviços de banco de dados expostos
        db_services = ["MySQL", "PostgreSQL", "MongoDB", "Redis"]
        exposed_dbs = [s for s in db_services if s in services_found]
        if exposed_dbs:
            recommendations.append(f"Bancos de dados expostos detectados: {', '.join(exposed_dbs)}. Verifique se é necessário acesso externo")
        
        # Verifica SSH em porta padrão
        ssh_ports = [p["port"] for p in open_ports if p["service"] == "SSH"]
        if 22 in ssh_ports:
            recommendations.append("SSH na porta padrão (22). Considere alterar para porta não padrão")
        
        return recommendations
    
    def _analyze_network_patterns(self, scan_results: List[Dict]) -> List[Dict]:
        """Analisa padrões suspeitos na rede."""
        alerts = []
        
        # Conta hosts com muitas portas abertas
        hosts_many_ports = [
            h for h in scan_results 
            if len(h["open_ports"]) > 10
        ]
        
        if hosts_many_ports:
            alert = {
                "type": "HOSTS_WITH_MANY_PORTS",
                "severity": "MEDIUM",
                "count": len(hosts_many_ports),
                "hosts": [h["ip"] for h in hosts_many_ports],
                "description": f"{len(hosts_many_ports)} host(s) com muitas portas abertas detectados",
                "timestamp": datetime.now().isoformat()
            }
            alerts.append(alert)
        
        # Verifica padrões de serviços similares
        service_patterns = {}
        for host in scan_results:
            for port in host["open_ports"]:
                service = port["service"]
                if service not in service_patterns:
                    service_patterns[service] = []
                service_patterns[service].append(host["ip"])
        
        # Identifica serviços muito comuns (possível configuração padrão)
        for service, hosts in service_patterns.items():
            if len(hosts) > len(scan_results) * 0.8:  # 80% dos hosts
                alert = {
                    "type": "WIDESPREAD_SERVICE",
                    "severity": "LOW",
                    "service": service,
                    "host_count": len(hosts),
                    "description": f"Serviço {service} encontrado em {len(hosts)} hosts - Verifique se é configuração intencional",
                    "timestamp": datetime.now().isoformat()
                }
                alerts.append(alert)
        
        return alerts
    
    def _calculate_risk_level(self, alerts: List[Dict], vulnerabilities: List[Dict]) -> str:
        """Calcula o nível de risco baseado em alertas e vulnerabilidades."""
        critical_count = len([a for a in alerts if a["severity"] == "CRITICAL"])
        high_count = len([a for a in alerts if a["severity"] == "HIGH"])
        medium_count = len([a for a in alerts if a["severity"] == "MEDIUM"])
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 2:
            return "HIGH"
        elif high_count > 0 or medium_count > 3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_security_score(self, alerts: List[Dict], vulnerabilities: List[Dict]) -> int:
        """Calcula um score de segurança (0-100)."""
        score = 100
        
        for alert in alerts:
            if alert["severity"] == "CRITICAL":
                score -= 25
            elif alert["severity"] == "HIGH":
                score -= 15
            elif alert["severity"] == "MEDIUM":
                score -= 10
            else:
                score -= 5
        
        return max(0, score)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Gera recomendações baseadas na análise."""
        recommendations = []
        
        if analysis["risk_level"] in ["HIGH", "CRITICAL"]:
            recommendations.append("URGENTE: Revisar imediatamente as vulnerabilidades críticas identificadas")
            recommendations.append("Implementar firewall para restringir acesso às portas expostas")
        
        if analysis["security_score"] < 70:
            recommendations.append("Score de segurança baixo - Revisar configurações de rede")
        
        if len(analysis["vulnerabilities"]) > 5:
            recommendations.append("Múltiplas vulnerabilidades detectadas - Priorizar correções")
        
        recommendations.append("Realizar varreduras regulares para monitoramento contínuo")
        recommendations.append("Manter logs de segurança e implementar monitoramento em tempo real")
        
        return recommendations
    
    def generate_report(self, network_analysis: Dict) -> str:
        """
        Gera um relatório detalhado da análise de segurança.
        
        Args:
            network_analysis: Resultado da análise de rede
            
        Returns:
            Relatório em formato texto
        """
        report = []
        report.append("=" * 60)
        report.append("RADAR DIGITAL - RELATÓRIO DE SEGURANÇA")
        report.append("=" * 60)
        report.append(f"Data/Hora: {network_analysis['analysis_time']}")
        report.append(f"Total de Hosts: {network_analysis['total_hosts']}")
        report.append(f"Hosts Ativos: {network_analysis['active_hosts']}")
        report.append(f"Total de Portas Abertas: {network_analysis['total_open_ports']}")
        report.append("")
        
        # Distribuição de risco
        report.append("DISTRIBUIÇÃO DE RISCO:")
        for risk, count in network_analysis['risk_distribution'].items():
            if count > 0:
                report.append(f"  {risk}: {count} host(s)")
        report.append("")
        
        # Top vulnerabilidades
        if network_analysis['top_vulnerabilities']:
            report.append("TOP VULNERABILIDADES:")
            for vuln in network_analysis['top_vulnerabilities'][:5]:
                report.append(f"  - {vuln['vulnerability']}: {vuln['count']} ocorrência(s)")
            report.append("")
        
        # Alertas de rede
        if network_analysis['network_alerts']:
            report.append("ALERTAS DE REDE:")
            for alert in network_analysis['network_alerts']:
                report.append(f"  [{alert['severity']}] {alert['description']}")
            report.append("")
        
        # Hosts críticos
        critical_hosts = [h for h in network_analysis['host_analyses'] if h['risk_level'] == 'CRITICAL']
        if critical_hosts:
            report.append("HOSTS CRÍTICOS:")
            for host in critical_hosts:
                report.append(f"  - {host['ip']} (Score: {host['security_score']})")
                for vuln in host['vulnerabilities'][:3]:
                    report.append(f"    * {vuln['type']}: {vuln['description']}")
            report.append("")
        
        report.append("=" * 60)
        report.append("Fim do Relatório")
        report.append("=" * 60)
        
        return "\n".join(report)


def main():
    """Função de teste para o módulo analyzer."""
    # Dados de teste simulados
    test_host_data = {
        "ip": "192.168.1.100",
        "hostname": "test-server",
        "is_alive": True,
        "open_ports": [
            {"port": 22, "protocol": "TCP", "state": "open", "service": "SSH", "response_time": 5.2},
            {"port": 80, "protocol": "TCP", "state": "open", "service": "HTTP", "response_time": 2.1},
            {"port": 135, "protocol": "TCP", "state": "open", "service": "RPC", "response_time": 10.5},
            {"port": 445, "protocol": "TCP", "state": "open", "service": "SMB", "response_time": 8.3},
            {"port": 3389, "protocol": "TCP", "state": "open", "service": "RDP", "response_time": 15.7}
        ],
        "scan_time": time.time()
    }
    
    analyzer = ThreatAnalyzer()
    
    print("=== Radar Digital - Threat Analyzer ===")
    print("Analisando host de teste...")
    
    analysis = analyzer.analyze_host(test_host_data)
    
    print(f"\nHost: {analysis['ip']}")
    print(f"Nível de Risco: {analysis['risk_level']}")
    print(f"Score de Segurança: {analysis['security_score']}/100")
    print(f"Alertas: {len(analysis['alerts'])}")
    print(f"Vulnerabilidades: {len(analysis['vulnerabilities'])}")
    
    if analysis['alerts']:
        print("\nAlertas encontrados:")
        for alert in analysis['alerts']:
            print(f"  [{alert['severity']}] {alert['description']}")
    
    if analysis['recommendations']:
        print("\nRecomendações:")
        for rec in analysis['recommendations'][:3]:
            print(f"  - {rec}")


if __name__ == "__main__":
    main()

