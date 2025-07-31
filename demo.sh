#!/bin/bash
echo "=== Radar Digital - Demo Script ==="
echo "Testando módulos principais..."
echo ""

echo "1. Testando Scanner..."
python netscope/scanner.py
echo ""

echo "2. Testando Analyzer..."
python netscope/analyzer.py
echo ""

echo "3. Testando Logger..."
python netscope/logger.py
echo ""

echo "4. Executando testes unitários..."
python -m pytest tests/ -v --tb=short
echo ""

echo "=== Demo concluída! ==="
echo "Para executar o dashboard: streamlit run dashboard/app.py"
