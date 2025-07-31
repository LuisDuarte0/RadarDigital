# Radar Digital 🛡️

Um sistema completo de **Cibersegurança e Threat Intelligence** desenvolvido em Python, focado em varredura de rede, análise de vulnerabilidades e apresentação de dados através de um dashboard interativo.

## 🎯 Objetivo

O Radar Digital é uma ferramenta profissional para análise de segurança de redes que permite:
- Varredura de IPs ativos na rede
- Detecção de portas abertas e serviços em execução
- Identificação de possíveis vulnerabilidades
- Registro detalhado de logs com timestamp
- Sistema de alertas para comportamentos suspeitos
- Dashboard web interativo para visualização em tempo real

## 🚀 Funcionalidades

### Scanner de Rede
- Detecção automática de IPs ativos
- Varredura de portas TCP/UDP
- Identificação de serviços comuns
- Análise de tempo de resposta

### Sistema de Análise
- Detecção de portas incomuns
- Identificação de serviços potencialmente vulneráveis
- Geração de alertas de segurança
- Análise de padrões de tráfego

### Dashboard Interativo
- Interface web responsiva com Streamlit
- Visualização em tempo real dos resultados
- Gráficos e tabelas interativas
- Exportação de relatórios

## 📁 Estrutura do Projeto

```
RadarDigital/
├── netscope/
│   ├── __init__.py
│   ├── scanner.py      # Módulo principal de varredura
│   ├── analyzer.py     # Análise e detecção de ameaças
│   └── logger.py       # Sistema de logging
├── dashboard/
│   └── app.py          # Interface Streamlit
├── tests/
│   ├── test_scanner.py
│   ├── test_analyzer.py
│   └── test_logger.py
├── logs/               # Diretório para arquivos de log
├── requirements.txt
└── README.md
```

## 🛠️ Instalação

### Pré-requisitos
- Python 3.12+ (testado com Python 3.11+)
- Windows/Linux/macOS
- Privilégios de administrador (para algumas funcionalidades de rede)

### Passos de Instalação

1. **Clone ou baixe o projeto**
```bash
# Se usando git
git clone <repository-url>
cd RadarDigital

# Ou extraia o arquivo ZIP baixado
```

2. **Instale as dependências**
```bash
pip install -r requirements.txt
```

3. **Execute o dashboard**
```bash
streamlit run dashboard/app.py
```

4. **Acesse o sistema**
- Abra seu navegador em: `http://localhost:8501`

## 🔧 Uso

### Via Dashboard Web
1. Execute o comando `streamlit run dashboard/app.py`
2. Acesse `http://localhost:8501` no navegador
3. Configure o range de IPs para varredura na barra lateral
4. Ajuste as configurações (timeout, threads, UDP)
5. Clique em "🔍 Iniciar Scan" para executar a varredura
6. Acompanhe os resultados em tempo real nas diferentes abas

### Via Linha de Comando
```python
from netscope.scanner import NetworkScanner
from netscope.analyzer import ThreatAnalyzer

# Criar instância do scanner
scanner = NetworkScanner()

# Executar varredura
results = scanner.scan_network("192.168.1.0/24")

# Analisar resultados
analyzer = ThreatAnalyzer()
network_analysis = analyzer.analyze_network(results)

# Gerar relatório
report = analyzer.generate_report(network_analysis)
print(report)
```

### Testando os Módulos Individualmente
```bash
# Testar scanner
python netscope/scanner.py

# Testar analyzer
python netscope/analyzer.py

# Testar logger
python netscope/logger.py

# Executar todos os testes
python -m pytest tests/ -v
```

## 📊 Recursos do Dashboard

### 📊 Dashboard Principal
- Métricas em tempo real (hosts ativos, portas abertas, ameaças)
- Gráficos de distribuição de risco
- Top vulnerabilidades encontradas
- Status da rede local

### 🔍 Resultados da Varredura
- Lista detalhada de todos os hosts encontrados
- Filtros por status, número de portas e nível de risco
- Informações de portas abertas e serviços
- Tempos de resposta

### ⚠️ Alertas de Segurança
- Alertas de rede em tempo real
- Alertas específicos por host
- Classificação por severidade (LOW, MEDIUM, HIGH, CRITICAL)
- Descrições detalhadas das ameaças

### 📈 Análises Detalhadas
- Relatório completo de segurança
- Análise temporal (histórico de varreduras)
- Recomendações de segurança
- Download de relatórios

### 📋 Logs do Sistema
- Logs principais do sistema
- Logs específicos de varreduras
- Logs de alertas de ameaças
- Download de arquivos de log

## ⚠️ Considerações de Segurança

- **Use apenas em redes próprias ou com autorização explícita**
- Algumas funcionalidades requerem privilégios administrativos
- Logs podem conter informações sensíveis - proteja adequadamente
- Respeite as leis locais sobre segurança cibernética
- O sistema detecta portas e serviços comuns, mas não substitui ferramentas especializadas

## 🧪 Testes

Execute os testes unitários com:
```bash
# Todos os testes
python -m pytest tests/ -v

# Testes específicos
python -m pytest tests/test_scanner.py -v
python -m pytest tests/test_analyzer.py -v
python -m pytest tests/test_logger.py -v
```

### Cobertura de Testes
- **Scanner**: 16 testes (inicialização, ping, varredura TCP/UDP, resolução DNS)
- **Analyzer**: 15 testes (análise de ameaças, cálculo de risco, relatórios)
- **Logger**: Testes de logging em múltiplos arquivos e formatos

## 📝 Logs

Os logs são salvos automaticamente em:
- `logs/radar_digital.log` - Log principal do sistema
- `logs/scan_results.log` - Resultados detalhados de varreduras
- `logs/threats.log` - Alertas de segurança e ameaças

## 🔧 Configurações Avançadas

### Personalizando o Scanner
```python
# Scanner com configurações customizadas
scanner = NetworkScanner(
    timeout=2.0,        # Timeout de 2 segundos
    max_threads=200     # Máximo de 200 threads
)

# Portas customizadas
custom_ports = [21, 22, 23, 80, 443, 3389, 5900]
results = scanner.scan_host_ports("192.168.1.1", custom_ports)
```

### Personalizando o Analyzer
```python
# Analyzer com detecção customizada
analyzer = ThreatAnalyzer()

# Adicionar portas suspeitas customizadas
analyzer.suspicious_ports[8080] = "HTTP alternativo suspeito"
analyzer.high_risk_services["Custom"] = "Serviço customizado - ALTO"
```

## 🚀 Recursos Técnicos

### Tecnologias Utilizadas
- **Python 3.11+**: Linguagem principal
- **Streamlit**: Interface web interativa
- **Plotly**: Gráficos e visualizações
- **Pandas**: Manipulação de dados
- **Scapy**: Análise de rede avançada
- **Socket**: Varredura de portas nativa
- **Threading**: Processamento paralelo
- **Logging**: Sistema de logs robusto

### Arquitetura
- **Modular**: Cada funcionalidade em módulo separado
- **Testável**: Cobertura completa de testes unitários
- **Escalável**: Suporte a threading e processamento paralelo
- **Configurável**: Parâmetros ajustáveis via interface
- **Logging**: Registro detalhado de todas as operações

### Performance
- **Threading**: Varredura paralela para máxima velocidade
- **Timeout configurável**: Balanceamento entre velocidade e precisão
- **Caching**: Resultados mantidos em sessão para análise
- **Streaming**: Interface responsiva em tempo real

## 🤝 Contribuição

Este projeto foi desenvolvido como portfólio de **Cibersegurança e Threat Intelligence**, demonstrando:

### Conhecimentos Técnicos
- Segurança de redes e protocolos
- Desenvolvimento de ferramentas de análise
- Boas práticas de programação Python
- Interface de usuário moderna e responsiva
- Testes unitários e integração
- Documentação técnica completa

### Funcionalidades Profissionais
- Scanner de rede multi-threaded
- Sistema de detecção de ameaças
- Análise de vulnerabilidades
- Geração de relatórios
- Dashboard interativo
- Sistema de logging robusto

## 📄 Licença

Este projeto é destinado para fins educacionais e de portfólio. Use com responsabilidade e sempre com autorização adequada.

## 🆘 Solução de Problemas

### Problemas Comuns

**Erro de permissão ao executar ping:**
```bash
# Linux/macOS - execute com sudo se necessário
sudo python netscope/scanner.py
```

**Streamlit não inicia:**
```bash
# Verifique se todas as dependências estão instaladas
pip install -r requirements.txt

# Execute diretamente
streamlit run dashboard/app.py
```

**Portas não detectadas:**
- Verifique se você tem permissões adequadas
- Alguns firewalls podem bloquear varreduras
- Aumente o timeout para redes mais lentas

**Dashboard não carrega:**
- Verifique se a porta 8501 está disponível
- Tente acessar via `http://127.0.0.1:8501`
- Verifique os logs no terminal

### Logs de Debug
Para debug avançado, verifique os arquivos de log em `logs/`:
- Erros gerais: `radar_digital.log`
- Problemas de varredura: `scan_results.log`
- Alertas não esperados: `threats.log`

---

**Desenvolvido com 🛡️ para Cibersegurança e Threat Intelligence**

*Sistema completo e funcional para análise de segurança de redes, demonstrando domínio técnico em Python, segurança cibernética e desenvolvimento de interfaces modernas.*

