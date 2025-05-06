#!/usr/bin/env python3
#
# dns-api-tester.py - Script de testes para a API do Super DNS Recursivo
#
# Este script automatiza testes para validar o funcionamento 
# da API REST e do sistema de proteção DNS
#

import os
import sys
import json
import time
import unittest
import requests
import subprocess
import logging
from datetime import datetime

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dns-api-test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configurações dos testes
TEST_CONFIG = {
    'api_base_url': os.getenv('API_BASE_URL', 'http://localhost:5000'),
    'admin_user': os.getenv('TEST_ADMIN_USER', 'admin'),
    'admin_password': os.getenv('TEST_ADMIN_PASSWORD', 'superDNSadmin2023!'),
    'test_ip': os.getenv('TEST_IP', '192.168.100.100'),
    'dns_query_command': 'dig @127.0.0.1 example.com',
    'dns_flood_command': 'for i in $(seq 1 30); do dig @127.0.0.1 random$i.example.com +tries=1 +timeout=1; done',
    'fail2ban_status_command': 'fail2ban-client status dns-abuse',
    'timeout': 10  # segundos
}

class DNSAPITestCase(unittest.TestCase):
    """Testes para validar a API REST do Super DNS Recursivo"""

    @classmethod
    def setUpClass(cls):
        """Executado uma vez antes de todos os testes"""
        logger.info("Iniciando testes da API REST do Super DNS Recursivo")
        
        # Verifica se a API está acessível
        try:
            response = requests.get(f"{TEST_CONFIG['api_base_url']}/api/stats", timeout=TEST_CONFIG['timeout'])
            if response.status_code == 200:
                logger.info("API REST está acessível!")
            else:
                logger.warning(f"API REST respondeu com código {response.status_code}")
        except Exception as e:
            logger.error(f"Erro ao acessar API REST: {str(e)}")
            logger.warning("Alguns testes podem falhar se a API não estiver disponível")

    def setUp(self):
        """Executado antes de cada teste"""
        self.base_url = TEST_CONFIG['api_base_url']
        self.auth = (TEST_CONFIG['admin_user'], TEST_CONFIG['admin_password'])
        self.test_ip = TEST_CONFIG['test_ip']

    def test_01_api_status(self):
        """Testa se a API está online e retornando estatísticas básicas"""
        logger.info("Testando status da API...")
        response = requests.get(f"{self.base_url}/api/stats", timeout=TEST_CONFIG['timeout'])
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('timestamp', data)
        logger.info("API está online e retornando estatísticas")

    def test_02_whitelist_operations(self):
        """Testa operações de whitelist (adicionar e remover IPs)"""
        logger.info("Testando operações de whitelist...")
        
        # Testa adicionar IP à whitelist
        add_response = requests.post(
            f"{self.base_url}/api/whitelist",
            json={"ip": self.test_ip},
            auth=self.auth,
            timeout=TEST_CONFIG['timeout']
        )
        self.assertEqual(add_response.status_code, 200)
        logger.info(f"IP {self.test_ip} adicionado à whitelist")
        
        # Testa obter whitelist
        get_response = requests.get(
            f"{self.base_url}/api/whitelist",
            auth=self.auth,
            timeout=TEST_CONFIG['timeout']
        )
        self.assertEqual(get_response.status_code, 200)
        whitelist_data = get_response.json()
        self.assertIn('whitelist', whitelist_data)
        self.assertIn(self.test_ip, whitelist_data['whitelist'])
        logger.info("Whitelist obtida com sucesso")
        
        # Testa remover IP da whitelist
        remove_response = requests.delete(
            f"{self.base_url}/api/whitelist/{self.test_ip}",
            auth=self.auth,
            timeout=TEST_CONFIG['timeout']
        )
        self.assertEqual(remove_response.status_code, 200)
        logger.info(f"IP {self.test_ip} removido da whitelist")
        
        # Verifica se o IP foi realmente removido
        get_response_after = requests.get(
            f"{self.base_url}/api/whitelist",
            auth=self.auth,
            timeout=TEST_CONFIG['timeout']
        )
        whitelist_data_after = get_response_after.json()
        self.assertNotIn(self.test_ip, whitelist_data_after['whitelist'])
        logger.info("Operações de whitelist testadas com sucesso")

    def test_03_analyze_traffic(self):
        """Testa a análise de tráfego DNS"""
        logger.info("Testando análise de tráfego DNS...")
        
        # Executa o endpoint de análise
        analyze_response = requests.post(
            f"{self.base_url}/api/analyze",
            auth=self.auth,
            timeout=TEST_CONFIG['timeout'] * 2  # Dobra o timeout para análise
        )
        self.assertEqual(analyze_response.status_code, 200)
        analyze_data = analyze_response.json()
        logger.info("Análise de tráfego executada com sucesso")

    def test_04_banned_ips(self):
        """Testa obtenção da lista de IPs banidos"""
        logger.info("Testando listagem de IPs banidos...")
        
        banned_response = requests.get(
            f"{self.base_url}/api/banned",
            auth=self.auth,
            timeout=TEST_CONFIG['timeout']
        )
        self.assertEqual(banned_response.status_code, 200)
        banned_data = banned_response.json()
        self.assertIn('banned_ips', banned_data)
        self.assertIn('count', banned_data)
        logger.info(f"Obtida lista de IPs banidos: {banned_data['count']} IPs")

    def test_05_dns_query_functionality(self):
        """Testa a funcionalidade básica de consulta DNS"""
        logger.info("Testando funcionalidade básica de consulta DNS...")
        
        # Executa uma consulta DNS
        try:
            result = subprocess.run(
                TEST_CONFIG['dns_query_command'].split(),
                capture_output=True,
                text=True,
                check=True
            )
            self.assertIn('ANSWER SECTION', result.stdout)
            logger.info("Consulta DNS executada com sucesso")
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao executar consulta DNS: {e.stderr}")
            self.fail("Erro ao executar consulta DNS")

    def test_06_rate_limiting(self):
        """Testa se o rate limiting está funcionando"""
        logger.info("Testando sistema de rate limiting...")
        
        # Este teste não verifica realmente se o IP foi banido
        # apenas se o sistema processa várias consultas sem erros
        try:
            subprocess.run(
                TEST_CONFIG['dns_flood_command'], 
                shell=True,
                capture_output=True,
                check=False
            )
            logger.info("Flood de consultas DNS executado para testar rate limiting")
            
            # Verifica o status do fail2ban após as consultas
            result = subprocess.run(
                TEST_CONFIG['fail2ban_status_command'].split(),
                capture_output=True,
                text=True,
                check=False
            )
            logger.info(f"Status do fail2ban após consultas: {result.stdout}")
            
        except Exception as e:
            logger.error(f"Erro ao testar rate limiting: {str(e)}")
            self.fail("Erro ao testar rate limiting")

    @classmethod
    def tearDownClass(cls):
        """Executado uma vez após todos os testes"""
        logger.info("Testes da API REST do Super DNS Recursivo concluídos")

class DNSLoadTestCase(unittest.TestCase):
    """Testes de carga para o servidor DNS"""
    
    def test_01_dns_load_test(self):
        """Teste de carga simples para o servidor DNS"""
        logger.info("Executando teste de carga simples (10 consultas)...")
        
        start_time = time.time()
        success_count = 0
        
        for i in range(10):
            try:
                command = f"dig @127.0.0.1 load-test-{i}.example.com +tries=1 +timeout=1"
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    check=False
                )
                if result.returncode == 0:
                    success_count += 1
            except Exception as e:
                logger.error(f"Erro na consulta {i}: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        logger.info(f"Teste de carga concluído: {success_count}/10 consultas bem-sucedidas em {duration:.2f} segundos")
        logger.info(f"Taxa média: {(success_count/duration):.2f} consultas/segundo")

def generate_report():
    """Gera um relatório com os resultados dos testes"""
    logger.info("Gerando relatório de testes...")
    
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tests": {
            "api": {
                "status": "Executado",
                "result": "Verificar logs para detalhes"
            },
            "dns_functionality": {
                "status": "Executado",
                "result": "Verificar logs para detalhes"
            },
            "security": {
                "status": "Executado",
                "result": "Verificar logs para detalhes"
            }
        }
    }
    
    # Tenta obter estatísticas atuais do servidor
    try:
        response = requests.get(
            f"{TEST_CONFIG['api_base_url']}/api/stats",
            timeout=TEST_CONFIG['timeout']
        )
        if response.status_code == 200:
            report["current_stats"] = response.json()
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas para o relatório: {str(e)}")
    
    # Salva o relatório em JSON
    report_path = os.path.join(os.path.dirname(__file__), f"test_report_{int(time.time())}.json")
    try:
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Relatório salvo em {report_path}")
    except Exception as e:
        logger.error(f"Erro ao salvar relatório: {str(e)}")

if __name__ == "__main__":
    # Executa os testes
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
    
    # Gera o relatório
    generate_report()