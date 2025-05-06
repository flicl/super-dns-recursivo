#!/usr/bin/env python3
#
# dns-api-server.py - API REST para o Super DNS Recursivo
#
# Este script fornece uma API REST para consultar estatísticas do servidor DNS
# e gerenciar o sistema de proteção remotamente
#

import os
import sys
import json
import time
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, request, render_template, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env se existir
env_path = Path('/opt/dns-protection/config/.env')
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Configuração da API
API_CONFIG = {
    'host': os.getenv('API_HOST', '127.0.0.1'),
    'port': int(os.getenv('API_PORT', 5000)),
    'debug': os.getenv('API_DEBUG', 'False').lower() == 'true',
    'log_file': os.getenv('API_LOG_FILE', '/var/log/dns-api.log'),
    'metrics_file': os.getenv('METRICS_FILE', '/opt/dns-protection/metrics/prometheus/dns_metrics.prom'),
    'config_dir': os.getenv('CONFIG_DIR', '/opt/dns-protection/config'),
    'whitelist_file': os.getenv('WHITELIST_FILE', '/opt/dns-protection/config/whitelist.txt'),
    'rate_limited_file': os.getenv('RATE_LIMITED_FILE', '/opt/dns-protection/config/rate_limited.txt'),
    'dns_monitor_script': os.getenv('DNS_MONITOR_SCRIPT', '/opt/dns-protection/dns-monitor.sh'),
    'dns_metrics_script': os.getenv('DNS_METRICS_SCRIPT', '/scripts/monitoring/dns-metrics-exporter.sh'),
    'admin_user': os.getenv('ADMIN_USER', 'admin'),
    'admin_password_hash': os.getenv('ADMIN_PASSWORD_HASH', generate_password_hash('superDNSadmin2023!')),
    'api_key': os.getenv('API_KEY', 'sua-chave-secreta-aqui'),
    'allow_anonymous_stats': os.getenv('ALLOW_ANONYMOUS_STATS', 'True').lower() == 'true'
}

# Configurar o logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(API_CONFIG['log_file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Inicializa a aplicação Flask
app = Flask(__name__, 
            static_folder=os.path.join(os.path.dirname(__file__), 'static'),
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

# Função de autenticação por API Key
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_key = request.headers.get('X-API-Key')
        if API_CONFIG['api_key'] != 'sua-chave-secreta-aqui' and provided_key == API_CONFIG['api_key']:
            return f(*args, **kwargs)
        return jsonify({"error": "Acesso não autorizado: API Key válida necessária"}), 401
    return decorated

# Função de autenticação por usuário/senha
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if auth and auth.username == API_CONFIG['admin_user'] and check_password_hash(API_CONFIG['admin_password_hash'], auth.password):
            return f(*args, **kwargs)
        return jsonify({"error": "Acesso não autorizado: credenciais válidas necessárias"}), 401
    return decorated

# Rotas para ativos estáticos do dashboard
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory(app.static_folder, path)

# Rota principal - Dashboard web
@app.route('/')
def index():
    return render_template('index.html')

# API - Obter estatísticas do DNS
@app.route('/api/stats', methods=['GET'])
def get_stats():
    # Se stats anônimas não estiverem habilitadas, requer autenticação
    if not API_CONFIG['allow_anonymous_stats']:
        auth = request.authorization
        if not auth or auth.username != API_CONFIG['admin_user'] or not check_password_hash(API_CONFIG['admin_password_hash'], auth.password):
            return jsonify({"error": "Acesso não autorizado para estatísticas"}), 401
    
    try:
        stats = parse_metrics_file()
        
        if not stats:
            # Se não conseguir ler o arquivo, tenta executar o script de exportação de métricas
            update_metrics()
            stats = parse_metrics_file()
        
        # Adiciona timestamp
        stats['timestamp'] = int(time.time())
        stats['readable_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas: {str(e)}")
        return jsonify({"error": f"Erro ao obter estatísticas: {str(e)}"}), 500

# API - Obter lista de IPs banidos
@app.route('/api/banned', methods=['GET'])
@require_auth
def get_banned():
    try:
        # Executa o comando fail2ban-client para obter IPs banidos
        result = subprocess.run(['fail2ban-client', 'status', 'dns-abuse'], 
                                capture_output=True, text=True, check=True)
        
        # Extrai a lista de IPs banidos do output
        output = result.stdout
        banned_ips = []
        
        for line in output.splitlines():
            if 'Banned IP list:' in line:
                # Extrai IPs da linha
                ip_part = line.split('Banned IP list:')[1].strip()
                if ip_part:  # Se houver IPs banidos
                    banned_ips = [ip.strip() for ip in ip_part.split(' ')]
                break
        
        return jsonify({
            "banned_ips": banned_ips,
            "count": len(banned_ips),
            "timestamp": int(time.time()),
            "readable_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar fail2ban-client: {e.stderr}")
        return jsonify({"error": f"Erro ao obter IPs banidos: {e.stderr}"}), 500
    except Exception as e:
        logger.error(f"Erro ao obter IPs banidos: {str(e)}")
        return jsonify({"error": f"Erro ao obter IPs banidos: {str(e)}"}), 500

# API - Desbanir um IP
@app.route('/api/unban/<ip>', methods=['POST'])
@require_auth
def unban_ip(ip):
    try:
        # Validação básica do IP
        import ipaddress
        ipaddress.ip_address(ip)  # Vai lançar uma exceção se o IP for inválido
        
        # Executa o comando para desbanir o IP
        result = subprocess.run(['fail2ban-client', 'set', 'dns-abuse', 'unbanip', ip],
                              capture_output=True, text=True, check=True)
        
        logger.info(f"IP {ip} desbanido com sucesso")
        return jsonify({
            "success": True,
            "message": f"IP {ip} desbanido com sucesso",
            "ip": ip,
            "timestamp": int(time.time()),
            "readable_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except ValueError:
        return jsonify({"error": f"IP inválido: {ip}"}), 400
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao desbanir IP {ip}: {e.stderr}")
        return jsonify({"error": f"Erro ao desbanir IP: {e.stderr}"}), 500
    except Exception as e:
        logger.error(f"Erro ao desbanir IP {ip}: {str(e)}")
        return jsonify({"error": f"Erro ao desbanir IP: {str(e)}"}), 500

# API - Obter whitelist
@app.route('/api/whitelist', methods=['GET'])
@require_auth
def get_whitelist():
    try:
        whitelist = []
        whitelist_path = Path(API_CONFIG['whitelist_file'])
        
        if whitelist_path.exists():
            with open(whitelist_path, 'r') as f:
                whitelist = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        return jsonify({
            "whitelist": whitelist,
            "count": len(whitelist),
            "timestamp": int(time.time())}
        )
    except Exception as e:
        logger.error(f"Erro ao obter whitelist: {str(e)}")
        return jsonify({"error": f"Erro ao obter whitelist: {str(e)}"}), 500

# API - Adicionar à whitelist
@app.route('/api/whitelist', methods=['POST'])
@require_auth
def add_to_whitelist():
    data = request.json
    if not data or not data.get('ip'):
        return jsonify({"error": "IP não fornecido"}), 400
    
    ip = data['ip'].strip()
    
    try:
        # Validação do IP/rede
        import ipaddress
        try:
            ipaddress.ip_network(ip)  # Verifica se é uma rede CIDR válida
        except ValueError:
            ipaddress.ip_address(ip)  # Se não for rede, verifica se é um IP válido
        
        whitelist_path = Path(API_CONFIG['whitelist_file'])
        
        # Verifica se o IP já está na whitelist
        current_whitelist = []
        if whitelist_path.exists():
            with open(whitelist_path, 'r') as f:
                current_whitelist = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        if ip in current_whitelist:
            return jsonify({"message": f"IP {ip} já está na whitelist"}), 200
        
        # Adiciona o IP à whitelist
        with open(whitelist_path, 'a') as f:
            f.write(f"\n{ip}")
        
        logger.info(f"IP {ip} adicionado à whitelist")
        return jsonify({
            "success": True,
            "message": f"IP {ip} adicionado à whitelist",
            "ip": ip
        })
    except ValueError:
        return jsonify({"error": f"IP/rede inválido: {ip}"}), 400
    except Exception as e:
        logger.error(f"Erro ao adicionar à whitelist: {str(e)}")
        return jsonify({"error": f"Erro ao adicionar à whitelist: {str(e)}"}), 500

# API - Remover da whitelist
@app.route('/api/whitelist/<ip>', methods=['DELETE'])
@require_auth
def remove_from_whitelist(ip):
    try:
        whitelist_path = Path(API_CONFIG['whitelist_file'])
        
        # Verifica se o arquivo existe
        if not whitelist_path.exists():
            return jsonify({"error": "Arquivo de whitelist não encontrado"}), 404
        
        # Lê a whitelist atual
        with open(whitelist_path, 'r') as f:
            lines = f.readlines()
        
        # Remove o IP
        new_lines = [line for line in lines if line.strip() != ip]
        
        # Se não houve alteração, o IP não estava na whitelist
        if len(lines) == len(new_lines):
            return jsonify({"message": f"IP {ip} não encontrado na whitelist"}), 404
        
        # Salva a nova whitelist
        with open(whitelist_path, 'w') as f:
            f.writelines(new_lines)
        
        logger.info(f"IP {ip} removido da whitelist")
        return jsonify({
            "success": True,
            "message": f"IP {ip} removido da whitelist",
            "ip": ip
        })
    except Exception as e:
        logger.error(f"Erro ao remover da whitelist: {str(e)}")
        return jsonify({"error": f"Erro ao remover da whitelist: {str(e)}"}), 500

# API - Executar análise de tráfego
@app.route('/api/analyze', methods=['POST'])
@require_auth
def analyze_traffic():
    try:
        # Executa o script de análise
        result = subprocess.run([API_CONFIG['dns_monitor_script'], '--analyze', '--json'],
                              capture_output=True, text=True, check=True)
        
        # Tenta fazer parse do output JSON
        try:
            data = json.loads(result.stdout)
            return jsonify(data)
        except json.JSONDecodeError:
            # Se não conseguir fazer parse como JSON, retorna o output como texto
            return jsonify({
                "raw_output": result.stdout,
                "timestamp": int(time.time()),
                "readable_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar análise de tráfego: {e.stderr}")
        return jsonify({"error": f"Erro ao executar análise de tráfego: {e.stderr}"}), 500
    except Exception as e:
        logger.error(f"Erro ao executar análise de tráfego: {str(e)}")
        return jsonify({"error": f"Erro ao executar análise de tráfego: {str(e)}"}), 500

# Função para atualizar as métricas
def update_metrics():
    try:
        # Executa o script de exportação de métricas
        subprocess.run([API_CONFIG['dns_metrics_script']], 
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logger.error(f"Erro ao atualizar métricas: {str(e)}")
        return False

# Função para fazer parse do arquivo de métricas
def parse_metrics_file():
    metrics_path = Path(API_CONFIG['metrics_file'])
    if not metrics_path.exists():
        logger.warning(f"Arquivo de métricas não encontrado: {metrics_path}")
        return None
    
    try:
        metrics = {}
        with open(metrics_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        metric_name = parts[0]
                        metric_value = float(parts[1])
                        metrics[metric_name] = metric_value
                    except (ValueError, IndexError):
                        pass
        
        return metrics
    except Exception as e:
        logger.error(f"Erro ao fazer parse do arquivo de métricas: {str(e)}")
        return None

# Função para verificar prereqs
def check_prerequisites():
    # Verifica se o diretório de configuração existe
    config_dir = Path(API_CONFIG['config_dir'])
    if not config_dir.exists():
        logger.warning(f"Diretório de configuração não encontrado: {config_dir}")
        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Diretório de configuração criado: {config_dir}")
        except Exception as e:
            logger.error(f"Erro ao criar diretório de configuração: {str(e)}")
    
    # Verifica se o arquivo de whitelist existe
    whitelist_path = Path(API_CONFIG['whitelist_file'])
    if not whitelist_path.exists():
        logger.warning(f"Arquivo de whitelist não encontrado, criando: {whitelist_path}")
        try:
            with open(whitelist_path, 'w') as f:
                f.write("# Super DNS Recursivo - Lista de IPs confiáveis\n")
                f.write("# Um IP ou rede por linha (ex: 192.168.1.0/24)\n")
                f.write("127.0.0.1\n")
                f.write("::1\n")
            logger.info(f"Arquivo de whitelist criado: {whitelist_path}")
        except Exception as e:
            logger.error(f"Erro ao criar arquivo de whitelist: {str(e)}")
    
    # Verifica se o arquivo .env existe, cria se não existir
    env_path = Path('/opt/dns-protection/config/.env')
    if not env_path.exists():
        logger.warning(f"Arquivo .env não encontrado, criando: {env_path}")
        try:
            with open(env_path, 'w') as f:
                f.write(f"API_HOST={API_CONFIG['host']}\n")
                f.write(f"API_PORT={API_CONFIG['port']}\n")
                f.write(f"API_DEBUG={str(API_CONFIG['debug']).lower()}\n")
                f.write(f"API_LOG_FILE={API_CONFIG['log_file']}\n")
                f.write(f"METRICS_FILE={API_CONFIG['metrics_file']}\n")
                f.write(f"CONFIG_DIR={API_CONFIG['config_dir']}\n")
                f.write(f"WHITELIST_FILE={API_CONFIG['whitelist_file']}\n")
                f.write(f"RATE_LIMITED_FILE={API_CONFIG['rate_limited_file']}\n")
                f.write(f"DNS_MONITOR_SCRIPT={API_CONFIG['dns_monitor_script']}\n")
                f.write(f"DNS_METRICS_SCRIPT={API_CONFIG['dns_metrics_script']}\n")
                f.write(f"ADMIN_USER={API_CONFIG['admin_user']}\n")
                f.write(f"ADMIN_PASSWORD_HASH={API_CONFIG['admin_password_hash']}\n")
                f.write(f"API_KEY=sua-chave-secreta-aqui-{int(time.time())}\n")
                f.write(f"ALLOW_ANONYMOUS_STATS={str(API_CONFIG['allow_anonymous_stats']).lower()}\n")
            logger.info(f"Arquivo .env criado: {env_path}")
        except Exception as e:
            logger.error(f"Erro ao criar arquivo .env: {str(e)}")

# Ponto de entrada principal
if __name__ == '__main__':
    # Verifica pré-requisitos
    check_prerequisites()
    
    # Inicia o servidor
    logger.info(f"Iniciando API REST do Super DNS Recursivo em {API_CONFIG['host']}:{API_CONFIG['port']}")
    app.run(host=API_CONFIG['host'], port=API_CONFIG['port'], debug=API_CONFIG['debug'])