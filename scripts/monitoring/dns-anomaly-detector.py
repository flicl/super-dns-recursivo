#!/usr/bin/env python3
#
# dns-anomaly-detector.py - Detector de anomalias DNS baseado em machine learning
#
# Este script analisa os padrões de tráfego DNS utilizando técnicas de machine learning
# para detectar comportamentos anômalos que podem indicar ataques ou abusos
#

import os
import sys
import time
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Configurações
CONFIG = {
    'log_file': '/var/log/dns-anomaly.log',
    'data_dir': '/opt/dns-protection/ml',
    'model_file': '/opt/dns-protection/ml/anomaly_model.pkl',
    'training_days': 7,  # Dias de dados para treinar o modelo
    'anomaly_threshold': -0.5,  # Threshold para considerar anomalia (-1 a 0)
    'max_samples_train': 10000,  # Número máximo de amostras para treinamento
    'metrics_file': '/opt/dns-protection/metrics/prometheus/dns_metrics.prom',
    'feature_columns': [
        'total_queries', 'unique_ips', 'max_rps', 'avg_rps', 
        'nx_percent', 'hour_of_day', 'day_of_week'
    ]
}

# Criação dos diretórios
os.makedirs(CONFIG['data_dir'], exist_ok=True)

# Função para log
def log_message(level, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{level}] {message}"
    print(log_line)
    
    with open(CONFIG['log_file'], 'a') as log_file:
        log_file.write(log_line + "\n")

# Função para extrair métricas do arquivo do Prometheus
def extract_metrics():
    metrics = {}
    
    if not os.path.exists(CONFIG['metrics_file']):
        log_message("ERRO", f"Arquivo de métricas não encontrado: {CONFIG['metrics_file']}")
        return None
    
    try:
        # Lê o arquivo de métricas do Prometheus
        with open(CONFIG['metrics_file'], 'r') as f:
            lines = f.readlines()
        
        # Extrai as métricas
        for line in lines:
            if line.startswith('#'):
                continue
                
            parts = line.strip().split()
            if len(parts) >= 2:
                metric_name = parts[0]
                metric_value = float(parts[1])
                metrics[metric_name] = metric_value
        
        # Adiciona características temporais
        now = datetime.now()
        metrics['hour_of_day'] = now.hour
        metrics['day_of_week'] = now.weekday()
        
        return metrics
    
    except Exception as e:
        log_message("ERRO", f"Erro ao extrair métricas: {str(e)}")
        return None

# Função para salvar métricas para treinamento
def save_metrics_for_training():
    metrics = extract_metrics()
    if not metrics:
        return False
    
    # Cria DataFrame com as métricas
    df = pd.DataFrame([metrics])
    
    # Adiciona timestamp
    df['timestamp'] = datetime.now().timestamp()
    
    # Define o arquivo para salvar
    filename = os.path.join(CONFIG['data_dir'], f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    
    # Salva as métricas
    df.to_csv(filename, index=False)
    log_message("INFO", f"Métricas salvas para treinamento: {filename}")
    
    return True

# Função para carregar dados de treinamento
def load_training_data():
    # Obtém a data limite para incluir arquivos no treinamento
    cutoff_date = datetime.now() - timedelta(days=CONFIG['training_days'])
    
    # Lista todos os arquivos de métricas no diretório
    metrics_files = []
    for root, _, files in os.walk(CONFIG['data_dir']):
        for file in files:
            if file.startswith('metrics_') and file.endswith('.csv'):
                file_path = os.path.join(root, file)
                # Verifica a data do arquivo
                file_date = datetime.fromtimestamp(os.path.getmtime(file_path))
                if file_date >= cutoff_date:
                    metrics_files.append(file_path)
    
    if not metrics_files:
        log_message("AVISO", "Nenhum arquivo de dados de treinamento encontrado")
        return None
    
    # Combina todos os arquivos em um único DataFrame
    dfs = []
    for file in metrics_files:
        try:
            df = pd.read_csv(file)
            dfs.append(df)
        except Exception as e:
            log_message("AVISO", f"Erro ao ler arquivo {file}: {str(e)}")
    
    if not dfs:
        return None
    
    combined_df = pd.concat(dfs, ignore_index=True)
    
    # Limita o número de amostras se necessário
    if len(combined_df) > CONFIG['max_samples_train']:
        combined_df = combined_df.sample(n=CONFIG['max_samples_train'], random_state=42)
    
    log_message("INFO", f"Carregados {len(combined_df)} registros para treinamento")
    
    return combined_df

# Função para treinar o modelo
def train_model():
    # Carrega os dados de treinamento
    data = load_training_data()
    if data is None or len(data) < 100:  # Precisamos de pelo menos 100 amostras
        log_message("AVISO", "Dados insuficientes para treinamento. Colete mais dados primeiro.")
        return False
    
    try:
        # Seleciona apenas as colunas de features
        features = data[CONFIG['feature_columns']].copy()
        
        # Normaliza os dados
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Treina um modelo de detecção de anomalias (Isolation Forest)
        model = IsolationForest(
            contamination=0.05,  # Assume que 5% dos dados são anomalias
            random_state=42,
            n_estimators=100
        )
        
        model.fit(features_scaled)
        
        # Salva o modelo e o scaler
        with open(CONFIG['model_file'], 'wb') as f:
            pickle.dump((model, scaler), f)
        
        log_message("INFO", f"Modelo treinado e salvo em {CONFIG['model_file']}")
        return True
    
    except Exception as e:
        log_message("ERRO", f"Erro ao treinar modelo: {str(e)}")
        return False

# Função para detectar anomalias
def detect_anomalies():
    # Verifica se o modelo existe
    if not os.path.exists(CONFIG['model_file']):
        log_message("AVISO", "Modelo não encontrado. Execute o treinamento primeiro.")
        return False
    
    # Extrai métricas atuais
    metrics = extract_metrics()
    if not metrics:
        return False
    
    try:
        # Carrega o modelo e o scaler
        with open(CONFIG['model_file'], 'rb') as f:
            model, scaler = pickle.load(f)
        
        # Cria DataFrame com as métricas
        df = pd.DataFrame([metrics])
        
        # Seleciona apenas as colunas de features
        features = df[CONFIG['feature_columns']].copy()
        
        # Normaliza os dados
        features_scaled = scaler.transform(features)
        
        # Prediz a anomalia
        anomaly_score = model.decision_function(features_scaled)[0]
        is_anomaly = model.predict(features_scaled)[0] == -1
        
        # Registra resultado
        if is_anomaly:
            log_message("ALERTA", f"Anomalia detectada! Score: {anomaly_score:.4f}")
            
            # Salva a anomalia para análise posterior
            anomaly_file = os.path.join(CONFIG['data_dir'], f"anomaly_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(anomaly_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'metrics': metrics,
                    'anomaly_score': float(anomaly_score)
                }, f, indent=2)
            
            # Adiciona a informação da anomalia ao arquivo de métricas do Prometheus
            if os.path.exists(CONFIG['metrics_file']):
                with open(CONFIG['metrics_file'], 'a') as f:
                    timestamp = int(time.time())
                    f.write(f"\n# HELP dns_anomaly_score Score de anomalia DNS (-1 a 0, quanto menor mais anômalo)\n")
                    f.write(f"# TYPE dns_anomaly_score gauge\n")
                    f.write(f"dns_anomaly_score {anomaly_score:.6f} {timestamp}\n")
                    f.write(f"\n# HELP dns_anomaly_detected Flag indicando se uma anomalia foi detectada (0=normal, 1=anomalia)\n")
                    f.write(f"# TYPE dns_anomaly_detected gauge\n")
                    f.write(f"dns_anomaly_detected 1 {timestamp}\n")
        else:
            log_message("INFO", f"Comportamento normal. Score: {anomaly_score:.4f}")
            
            # Atualiza o arquivo de métricas do Prometheus com o score de normalidade
            if os.path.exists(CONFIG['metrics_file']):
                with open(CONFIG['metrics_file'], 'a') as f:
                    timestamp = int(time.time())
                    f.write(f"\n# HELP dns_anomaly_score Score de anomalia DNS (-1 a 0, quanto menor mais anômalo)\n")
                    f.write(f"# TYPE dns_anomaly_score gauge\n")
                    f.write(f"dns_anomaly_score {anomaly_score:.6f} {timestamp}\n")
                    f.write(f"\n# HELP dns_anomaly_detected Flag indicando se uma anomalia foi detectada (0=normal, 1=anomalia)\n")
                    f.write(f"# TYPE dns_anomaly_detected gauge\n")
                    f.write(f"dns_anomaly_detected 0 {timestamp}\n")
        
        return True
    
    except Exception as e:
        log_message("ERRO", f"Erro ao detectar anomalias: {str(e)}")
        return False

# Função principal
def main():
    # Verifica argumentos
    if len(sys.argv) > 1:
        if sys.argv[1] == '--train':
            train_model()
        elif sys.argv[1] == '--collect':
            save_metrics_for_training()
        elif sys.argv[1] == '--detect':
            detect_anomalies()
        elif sys.argv[1] == '--help':
            print("Uso: dns-anomaly-detector.py [OPÇÃO]")
            print()
            print("Opções:")
            print("  --train   Treina o modelo com os dados coletados")
            print("  --collect Coleta métricas atuais para treinamento futuro")
            print("  --detect  Executa a detecção de anomalias com as métricas atuais")
            print("  --help    Exibe esta mensagem de ajuda")
        else:
            print(f"Opção desconhecida: {sys.argv[1]}")
    else:
        # Comportamento padrão: detecta anomalias
        detect_anomalies()

if __name__ == "__main__":
    main()