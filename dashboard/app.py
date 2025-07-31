"""
Radar Digital - Streamlit Dashboard
Interface web interativa para varredura de rede e análise de segurança.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
from datetime import datetime
import sys
import os

# Adiciona o diretório pai ao path para importar os módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscope.scanner import NetworkScanner
from netscope.analyzer import ThreatAnalyzer
from netscope.logger import Logger


class RadarDigitalApp:
    """
    Aplicação principal do dashboard Radar Digital.
    """
    
    def __init__(self):
        """Inicializa a aplicação."""
        self.scanner = NetworkScanner()
        self.analyzer = ThreatAnalyzer()
        self.logger = Logger()
        
        # Configuração da página
        st.set_page_config(
            page_title="Radar Digital",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Inicializa session state
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = []
        if 'network_analysis' not in st.session_state:
            st.session_state.network_analysis = None
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
    
    def run(self):
        """Executa a aplicação principal."""
        self._render_header()
        self._render_sidebar()
        self._render_main_content()
    
    def _render_header(self):
        """Renderiza o cabeçalho da aplicação."""
        st.markdown("""
        <div style="background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%); padding: 1rem; border-radius: 10px; margin-bottom: 2rem;">
            <h1 style="color: white; text-align: center; margin: 0;">
                🛡️ Radar Digital
            </h1>
            <p style="color: #e0e0e0; text-align: center; margin: 0.5rem 0 0 0;">
                Sistema de Cibersegurança e Threat Intelligence
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    def _render_sidebar(self):
        """Renderiza a barra lateral com controles."""
        with st.sidebar:
            st.header("🔧 Controles")
            
            # Informações da rede local
            st.subheader("📡 Rede Local")
            network_info = self.scanner.get_network_info()
            st.info(f"**IP Local:** {network_info['local_ip']}")
            st.info(f"**Hostname:** {network_info['hostname']}")
            
            # Configurações de varredura
            st.subheader("⚙️ Configurações")
            
            network_input = st.text_input(
                "Rede para Varredura (CIDR)",
                value=network_info['suggested_network'],
                help="Ex: 192.168.1.0/24"
            )
            
            include_udp = st.checkbox(
                "Incluir varredura UDP",
                help="Varredura UDP é mais lenta mas detecta mais serviços"
            )
            
            timeout = st.slider(
                "Timeout (segundos)",
                min_value=0.5,
                max_value=5.0,
                value=1.0,
                step=0.5
            )
            
            max_threads = st.slider(
                "Threads máximas",
                min_value=10,
                max_value=200,
                value=100,
                step=10
            )
            
            # Atualiza configurações do scanner
            self.scanner.timeout = timeout
            self.scanner.max_threads = max_threads
            
            # Botão de varredura
            st.subheader("🚀 Executar Varredura")
            
            if st.button("🔍 Iniciar Scan", type="primary", use_container_width=True):
                self._run_network_scan(network_input, include_udp)
            
            # Botão para limpar resultados
            if st.button("🗑️ Limpar Resultados", use_container_width=True):
                st.session_state.scan_results = []
                st.session_state.network_analysis = None
                st.rerun()
    
    def _render_main_content(self):
        """Renderiza o conteúdo principal."""
        # Tabs principais
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Dashboard", "🔍 Resultados", "⚠️ Alertas", "📈 Análises", "📋 Logs"
        ])
        
        with tab1:
            self._render_dashboard_tab()
        
        with tab2:
            self._render_results_tab()
        
        with tab3:
            self._render_alerts_tab()
        
        with tab4:
            self._render_analysis_tab()
        
        with tab5:
            self._render_logs_tab()
    
    def _render_dashboard_tab(self):
        """Renderiza a aba do dashboard principal."""
        st.header("📊 Dashboard Principal")
        
        if not st.session_state.scan_results:
            st.info("👆 Execute uma varredura usando os controles na barra lateral para ver os resultados aqui.")
            
            # Mostra informações básicas da rede
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Status", "Aguardando", "Pronto para varredura")
            
            with col2:
                st.metric("Hosts Escaneados", "0", "Nenhuma varredura executada")
            
            with col3:
                st.metric("Ameaças Detectadas", "0", "Nenhuma varredura executada")
            
            return
        
        # Métricas principais
        results = st.session_state.scan_results
        analysis = st.session_state.network_analysis
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Hosts Ativos",
                analysis['active_hosts'],
                f"de {analysis['total_hosts']} escaneados"
            )
        
        with col2:
            st.metric(
                "Portas Abertas",
                analysis['total_open_ports'],
                "Total na rede"
            )
        
        with col3:
            critical_hosts = analysis['risk_distribution']['CRITICAL']
            high_hosts = analysis['risk_distribution']['HIGH']
            st.metric(
                "Hosts Críticos",
                critical_hosts + high_hosts,
                "Alto risco detectado" if critical_hosts + high_hosts > 0 else "Rede segura"
            )
        
        with col4:
            total_vulns = len(analysis['top_vulnerabilities'])
            st.metric(
                "Vulnerabilidades",
                total_vulns,
                "Tipos únicos"
            )
        
        # Gráficos
        col1, col2 = st.columns(2)
        
        with col1:
            # Gráfico de distribuição de risco
            risk_data = analysis['risk_distribution']
            risk_df = pd.DataFrame([
                {'Nível': k, 'Hosts': v} for k, v in risk_data.items() if v > 0
            ])
            
            if not risk_df.empty:
                fig = px.pie(
                    risk_df, 
                    values='Hosts', 
                    names='Nível',
                    title="Distribuição de Risco por Host",
                    color_discrete_map={
                        'LOW': '#28a745',
                        'MEDIUM': '#ffc107',
                        'HIGH': '#fd7e14',
                        'CRITICAL': '#dc3545'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Gráfico de top vulnerabilidades
            if analysis['top_vulnerabilities']:
                vuln_df = pd.DataFrame(analysis['top_vulnerabilities'][:5])
                fig = px.bar(
                    vuln_df,
                    x='count',
                    y='vulnerability',
                    orientation='h',
                    title="Top 5 Vulnerabilidades",
                    labels={'count': 'Ocorrências', 'vulnerability': 'Vulnerabilidade'}
                )
                fig.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)
    
    def _render_results_tab(self):
        """Renderiza a aba de resultados detalhados."""
        st.header("🔍 Resultados da Varredura")
        
        if not st.session_state.scan_results:
            st.info("Nenhuma varredura executada ainda.")
            return
        
        results = st.session_state.scan_results
        
        # Filtros
        col1, col2, col3 = st.columns(3)
        
        with col1:
            show_only_active = st.checkbox("Apenas hosts ativos", value=True)
        
        with col2:
            min_ports = st.number_input("Mín. portas abertas", min_value=0, value=0)
        
        with col3:
            risk_filter = st.multiselect(
                "Filtrar por risco",
                options=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                default=['MEDIUM', 'HIGH', 'CRITICAL']
            )
        
        # Filtra resultados
        filtered_results = []
        for host in results:
            if show_only_active and not host['is_alive']:
                continue
            if len(host['open_ports']) < min_ports:
                continue
            
            # Obtém análise do host
            host_analysis = None
            if st.session_state.network_analysis:
                for analysis in st.session_state.network_analysis['host_analyses']:
                    if analysis['ip'] == host['ip']:
                        host_analysis = analysis
                        break
            
            if host_analysis and risk_filter:
                if host_analysis['risk_level'] not in risk_filter:
                    continue
            
            filtered_results.append((host, host_analysis))
        
        # Exibe resultados
        for host, analysis in filtered_results:
            with st.expander(f"🖥️ {host['ip']} ({host.get('hostname', 'N/A')})", expanded=False):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Status:** {'🟢 Ativo' if host['is_alive'] else '🔴 Inativo'}")
                    st.write(f"**Portas Abertas:** {len(host['open_ports'])}")
                
                with col2:
                    if analysis:
                        risk_color = {
                            'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🔴'
                        }
                        st.write(f"**Risco:** {risk_color.get(analysis['risk_level'], '⚪')} {analysis['risk_level']}")
                        st.write(f"**Score:** {analysis['security_score']}/100")
                
                with col3:
                    if analysis:
                        st.write(f"**Alertas:** {len(analysis['alerts'])}")
                        st.write(f"**Vulnerabilidades:** {len(analysis['vulnerabilities'])}")
                
                # Tabela de portas
                if host['open_ports']:
                    ports_df = pd.DataFrame(host['open_ports'])
                    st.dataframe(ports_df, use_container_width=True)
                
                # Alertas do host
                if analysis and analysis['alerts']:
                    st.write("**⚠️ Alertas:**")
                    for alert in analysis['alerts']:
                        severity_icon = {'LOW': '🟡', 'MEDIUM': '🟠', 'HIGH': '🔴', 'CRITICAL': '🚨'}
                        st.write(f"{severity_icon.get(alert['severity'], '⚪')} {alert['description']}")
    
    def _render_alerts_tab(self):
        """Renderiza a aba de alertas de segurança."""
        st.header("⚠️ Alertas de Segurança")
        
        if not st.session_state.network_analysis:
            st.info("Execute uma varredura para ver os alertas de segurança.")
            return
        
        analysis = st.session_state.network_analysis
        
        # Alertas de rede
        if analysis['network_alerts']:
            st.subheader("🌐 Alertas de Rede")
            for alert in analysis['network_alerts']:
                severity_color = {
                    'LOW': 'info', 'MEDIUM': 'warning', 'HIGH': 'error', 'CRITICAL': 'error'
                }
                st.toast(f"[{alert['severity']}] {alert['description']}", icon="⚠️")
                with st.expander(f"{alert['type']} - {alert['severity']}", expanded=False):
                    st.json(alert)
        
        # Alertas por host
        st.subheader("🖥️ Alertas por Host")
        
        for host_analysis in analysis['host_analyses']:
            if host_analysis['alerts']:
                st.write(f"**Host: {host_analysis['ip']}**")
                
                for alert in host_analysis['alerts']:
                    severity_icon = {'LOW': '🟡', 'MEDIUM': '🟠', 'HIGH': '🔴', 'CRITICAL': '🚨'}
                    
                    with st.container():
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.write(f"{severity_icon.get(alert['severity'], '⚪')} {alert['description']}")
                        with col2:
                            st.write(f"**{alert['severity']}**")
                
                st.divider()
    
    def _render_analysis_tab(self):
        """Renderiza a aba de análises detalhadas."""
        st.header("📈 Análises Detalhadas")
        
        if not st.session_state.network_analysis:
            st.info("Execute uma varredura para ver as análises detalhadas.")
            return
        
        analysis = st.session_state.network_analysis
        
        # Relatório de segurança
        st.subheader("📋 Relatório de Segurança")
        
        report = self.analyzer.generate_report(analysis)
        st.text_area("Relatório Completo", report, height=400)
        
        # Botão para download do relatório
        st.download_button(
            label="📥 Download Relatório",
            data=report,
            file_name=f"radar_digital_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
        
        # Análise temporal (se houver histórico)
        if len(st.session_state.scan_history) > 1:
            st.subheader("📊 Análise Temporal")
            
            # Gráfico de evolução de ameaças
            history_data = []
            for scan in st.session_state.scan_history:
                timestamp = scan['timestamp']
                total_threats = sum(scan['analysis']['risk_distribution'].values())
                history_data.append({'timestamp': timestamp, 'threats': total_threats})
            
            if history_data:
                history_df = pd.DataFrame(history_data)
                fig = px.line(
                    history_df,
                    x='timestamp',
                    y='threats',
                    title="Evolução de Ameaças ao Longo do Tempo",
                    labels={'threats': 'Total de Ameaças', 'timestamp': 'Data/Hora'}
                )
                st.plotly_chart(fig, use_container_width=True)
    
    def _render_logs_tab(self):
        """Renderiza a aba de logs do sistema."""
        st.header("📋 Logs do Sistema")
        
        # Seletor de tipo de log
        log_type = st.selectbox(
            "Tipo de Log",
            options=["Principal", "Varreduras", "Ameaças"],
            index=0
        )
        
        log_files = {
            "Principal": "logs/radar_digital.log",
            "Varreduras": "logs/scan_results.log",
            "Ameaças": "logs/threats.log"
        }
        
        log_file = log_files[log_type]
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                
                # Mostra as últimas linhas primeiro
                log_lines = log_content.split('\n')
                recent_lines = log_lines[-100:] if len(log_lines) > 100 else log_lines
                
                st.text_area(
                    f"Últimas entradas - {log_type}",
                    '\n'.join(recent_lines),
                    height=400
                )
                
                # Botão para download do log
                st.download_button(
                    label=f"📥 Download Log {log_type}",
                    data=log_content,
                    file_name=f"{log_file.split('/')[-1]}",
                    mime="text/plain"
                )
            else:
                st.info(f"Arquivo de log {log_type.lower()} ainda não foi criado.")
        
        except Exception as e:
            st.error(f"Erro ao ler arquivo de log: {e}")
    
    def _run_network_scan(self, network: str, include_udp: bool):
        """Executa a varredura de rede."""
        try:
            with st.spinner("🔍 Executando varredura de rede..."):
                # Log do início da varredura
                self.logger.log_info(f"Iniciando varredura da rede: {network}")
                
                # Executa a varredura
                start_time = time.time()
                results = self.scanner.scan_network(network, include_udp)
                scan_time = time.time() - start_time
                
                # Log dos resultados
                self.logger.log_info(f"Varredura concluída em {scan_time:.2f}s. {len(results)} hosts encontrados.")
                
                # Salva resultados
                st.session_state.scan_results = results
                
                # Executa análise de ameaças
                with st.spinner("🔍 Analisando ameaças..."):
                    analysis = self.analyzer.analyze_network(results)
                    st.session_state.network_analysis = analysis
                
                # Salva no histórico
                scan_record = {
                    'timestamp': datetime.now().isoformat(),
                    'network': network,
                    'results': results,
                    'analysis': analysis,
                    'scan_time': scan_time
                }
                st.session_state.scan_history.append(scan_record)
                
                # Log dos alertas críticos
                critical_alerts = [
                    alert for host in analysis['host_analyses']
                    for alert in host['alerts']
                    if alert['severity'] in ['HIGH', 'CRITICAL']
                ]
                
                for alert in critical_alerts:
                    self.logger.log_threat_alert(alert)
                
                st.success(f"✅ Varredura concluída! {len(results)} hosts analisados em {scan_time:.2f}s")
                
                # Mostra resumo rápido
                if analysis['risk_distribution']['CRITICAL'] > 0:
                    st.error(f"🚨 {analysis['risk_distribution']['CRITICAL']} host(s) crítico(s) detectado(s)!")
                elif analysis['risk_distribution']['HIGH'] > 0:
                    st.warning(f"⚠️ {analysis['risk_distribution']['HIGH']} host(s) de alto risco detectado(s)!")
                else:
                    st.info("✅ Nenhuma ameaça crítica detectada.")
        
        except Exception as e:
            error_msg = f"Erro durante a varredura: {str(e)}"
            st.error(error_msg)
            self.logger.log_error(error_msg)


def main():
    """Função principal da aplicação."""
    app = RadarDigitalApp()
    app.run()


if __name__ == "__main__":
    main()

