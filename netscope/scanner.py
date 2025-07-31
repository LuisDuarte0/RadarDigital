"""
Radar Digital - Network Scanner Module
Módulo principal para varredura de rede, detecção de IPs ativos e portas abertas.
"""

import socket
import threading
import time
import ipaddress
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import platform


class NetworkScanner:
    """
    Scanner de rede para detecção de hosts ativos e portas abertas.
    
    Utiliza múltiplas técnicas de varredura para máxima eficiência:
    - ICMP ping (quando disponível)
    - TCP connect scan
    - UDP scan básico
    """
    
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        """
        Inicializa o scanner de rede.
        
        Args:
            timeout: Timeout para conexões em segundos
            max_threads: Número máximo de threads para varredura paralela
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 9090
        ]
        self.service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "HTTP-Admin"
        }
    
    def ping_host(self, ip: str) -> bool:
        """
        Verifica se um host está ativo usando ping ICMP.
        
        Args:
            ip: Endereço IP para testar
            
        Returns:
            True se o host responder ao ping, False caso contrário
        """
        try:
            # Determina o comando ping baseado no sistema operacional
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def scan_tcp_port(self, ip: str, port: int) -> Dict[str, any]:
        """
        Escaneia uma porta TCP específica.
        
        Args:
            ip: Endereço IP
            port: Porta para escanear
            
        Returns:
            Dicionário com informações da porta
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((ip, port))
            response_time = (time.time() - start_time) * 1000  # em ms
            
            sock.close()
            
            if result == 0:
                service = self.service_map.get(port, "Unknown")
                return {
                    "port": port,
                    "protocol": "TCP",
                    "state": "open",
                    "service": service,
                    "response_time": round(response_time, 2)
                }
        except socket.error:
            pass
        
        return None
    
    def scan_udp_port(self, ip: str, port: int) -> Dict[str, any]:
        """
        Escaneia uma porta UDP específica (básico).
        
        Args:
            ip: Endereço IP
            port: Porta para escanear
            
        Returns:
            Dicionário com informações da porta ou None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Envia um pacote UDP vazio
            sock.sendto(b'', (ip, port))
            
            try:
                # Tenta receber resposta
                sock.recvfrom(1024)
                service = self.service_map.get(port, "Unknown")
                return {
                    "port": port,
                    "protocol": "UDP",
                    "state": "open|filtered",
                    "service": service,
                    "response_time": 0
                }
            except socket.timeout:
                # Timeout pode indicar porta filtrada ou aberta
                return None
            
        except socket.error:
            pass
        finally:
            sock.close()
        
        return None
    
    def scan_host_ports(self, ip: str, ports: List[int] = None, 
                       include_udp: bool = False) -> Dict[str, any]:
        """
        Escaneia todas as portas de um host específico.
        
        Args:
            ip: Endereço IP para escanear
            ports: Lista de portas (usa common_ports se None)
            include_udp: Se deve incluir varredura UDP
            
        Returns:
            Dicionário com informações do host
        """
        if ports is None:
            ports = self.common_ports
        
        host_info = {
            "ip": ip,
            "hostname": self._get_hostname(ip),
            "is_alive": self.ping_host(ip),
            "open_ports": [],
            "scan_time": time.time()
        }
        
        if not host_info["is_alive"]:
            # Tenta TCP connect mesmo se ping falhar (firewall pode bloquear ICMP)
            tcp_test = self.scan_tcp_port(ip, 80)  # Testa porta comum
            if not tcp_test:
                tcp_test = self.scan_tcp_port(ip, 443)  # Testa HTTPS
            
            if tcp_test:
                host_info["is_alive"] = True
        
        if host_info["is_alive"]:
            # Escaneia portas TCP
            with ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
                tcp_futures = {
                    executor.submit(self.scan_tcp_port, ip, port): port 
                    for port in ports
                }
                
                for future in as_completed(tcp_futures):
                    result = future.result()
                    if result:
                        host_info["open_ports"].append(result)
                
                # Escaneia portas UDP se solicitado
                if include_udp:
                    udp_ports = [53, 67, 68, 69, 123, 161, 162]  # Portas UDP comuns
                    udp_futures = {
                        executor.submit(self.scan_udp_port, ip, port): port 
                        for port in udp_ports
                    }
                    
                    for future in as_completed(udp_futures):
                        result = future.result()
                        if result:
                            host_info["open_ports"].append(result)
        
        return host_info
    
    def scan_network(self, network: str, include_udp: bool = False) -> List[Dict[str, any]]:
        """
        Escaneia uma rede completa.
        
        Args:
            network: Rede no formato CIDR (ex: 192.168.1.0/24)
            include_udp: Se deve incluir varredura UDP
            
        Returns:
            Lista com informações de todos os hosts
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            
            # Limita o número de hosts para evitar varreduras muito longas
            if len(hosts) > 254:
                hosts = hosts[:254]
            
            results = []
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(self.scan_host_ports, str(host), None, include_udp): host 
                    for host in hosts
                }
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result["is_alive"] or result["open_ports"]:
                            results.append(result)
                    except Exception as e:
                        print(f"Erro ao escanear host: {e}")
            
            return sorted(results, key=lambda x: ipaddress.ip_address(x["ip"]))
            
        except ValueError as e:
            raise ValueError(f"Formato de rede inválido: {e}")
    
    def scan_port_range(self, ip: str, start_port: int, end_port: int) -> List[Dict[str, any]]:
        """
        Escaneia um range de portas em um host específico.
        
        Args:
            ip: Endereço IP
            start_port: Porta inicial
            end_port: Porta final
            
        Returns:
            Lista com portas abertas encontradas
        """
        ports = list(range(start_port, end_port + 1))
        host_info = self.scan_host_ports(ip, ports)
        return host_info["open_ports"]
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """
        Tenta resolver o hostname de um IP.
        
        Args:
            ip: Endereço IP
            
        Returns:
            Hostname se encontrado, None caso contrário
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            return None
    
    def get_network_info(self) -> Dict[str, str]:
        """
        Obtém informações da rede local.
        
        Returns:
            Dicionário com informações da rede
        """
        try:
            # Obtém IP local
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            
            # Calcula rede baseada no IP local (assume /24)
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return {
                "local_ip": local_ip,
                "suggested_network": network,
                "hostname": socket.gethostname()
            }
        except Exception:
            return {
                "local_ip": "127.0.0.1",
                "suggested_network": "127.0.0.1/32",
                "hostname": "localhost"
            }


def main():
    """Função de teste para o módulo scanner."""
    scanner = NetworkScanner()
    
    print("=== Radar Digital - Network Scanner ===")
    print("Obtendo informações da rede local...")
    
    network_info = scanner.get_network_info()
    print(f"IP Local: {network_info['local_ip']}")
    print(f"Hostname: {network_info['hostname']}")
    print(f"Rede Sugerida: {network_info['suggested_network']}")
    
    # Teste básico de varredura
    print(f"\nTestando varredura no host local...")
    result = scanner.scan_host_ports(network_info['local_ip'])
    
    print(f"Host: {result['ip']}")
    print(f"Ativo: {result['is_alive']}")
    print(f"Portas abertas: {len(result['open_ports'])}")
    
    for port in result['open_ports']:
        print(f"  - {port['port']}/{port['protocol']} ({port['service']}) - {port['response_time']}ms")


if __name__ == "__main__":
    main()

