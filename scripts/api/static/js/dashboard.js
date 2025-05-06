/**
 * dashboard.js - Script para o dashboard web do Super DNS Recursivo
 *
 * Este script gerencia a interface do dashboard, incluindo a coleta e visualização
 * de dados e interações com a API REST
 */

// Configurações globais
const CONFIG = {
    // Intervalo de atualização automática (em ms)
    refreshInterval: 30000,
    // Endpoints da API
    api: {
        stats: '/api/stats',
        banned: '/api/banned',
        whitelist: '/api/whitelist',
        unban: '/api/unban',
        analyze: '/api/analyze'
    },
    // Cores para gráficos
    colors: {
        primary: '#0d6efd',
        success: '#198754',
        danger: '#dc3545',
        warning: '#ffc107',
        info: '#0dcaf0',
        secondary: '#6c757d',
        light: '#f8f9fa',
        dark: '#212529',
        chartColors: [
            '#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0', 
            '#6c757d', '#d63384', '#fd7e14', '#20c997', '#6610f2'
        ]
    }
};

// Variáveis globais para armazenar dados e gráficos
let queriesChart = null;
let queryTypesChart = null;
let statsData = {};
let statsHistory = [];
let refreshTimer = null;
let activePanel = 'dashboard';
let authenticated = false;

// Elementos da interface - Serão definidos após o carregamento do DOM
let elements = {};

// Função principal inicializada quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', () => {
    // Inicializa a navegação por abas
    initNavigation();
    
    // Armazena referências a elementos do DOM frequentemente acessados
    cacheElements();
    
    // Inicializa os gráficos vazios
    initCharts();
    
    // Configura os listeners de eventos
    setupEventListeners();
    
    // Carrega dados iniciais
    refreshAllData();
    
    // Configura atualização automática
    startAutoRefresh();
    
    // Verifica autenticação
    checkAuthentication();
});

// Função para guardar referências aos elementos do DOM
function cacheElements() {
    elements = {
        // Elementos de status e estatísticas
        lastUpdate: document.getElementById('lastUpdate'),
        serverStatus: document.getElementById('serverStatus'),
        queriesPerSecond: document.getElementById('queriesPerSecond'),
        cacheHitRate: document.getElementById('cacheHitRate'),
        avgResponseTime: document.getElementById('avgResponseTime'),
        detailedStatsTable: document.getElementById('detailedStatsTable'),
        
        // Elementos da seção de segurança
        blockedThreats: document.getElementById('blockedThreats'),
        bannedIPs: document.getElementById('bannedIPs'),
        anomalyStatus: document.getElementById('anomalyStatus'),
        abuseAttempts: document.getElementById('abuseAttempts'),
        bannedIPsTable: document.getElementById('bannedIPsTable'),
        whitelistTable: document.getElementById('whitelistTable'),
        
        // Painéis de conteúdo
        panels: {
            dashboard: document.getElementById('dashboard'),
            security: document.getElementById('security'),
            config: document.getElementById('config'),
            logs: document.getElementById('logs')
        },
        
        // Formulários e modais
        addWhitelistModal: new bootstrap.Modal(document.getElementById('addWhitelistModal')),
        addWhitelistForm: document.getElementById('addWhitelistForm'),
        whitelistIP: document.getElementById('whitelistIP'),
        
        // Botões
        refreshBannedBtn: document.getElementById('refreshBannedBtn'),
        refreshWhitelistBtn: document.getElementById('refreshWhitelistBtn'),
        addWhitelistBtn: document.getElementById('addWhitelistBtn'),
        saveWhitelistBtn: document.getElementById('saveWhitelistBtn'),
        runAnalysisBtn: document.getElementById('runAnalysisBtn'),
        updateMetricsBtn: document.getElementById('updateMetricsBtn'),
        
        // Área de resultados de análise
        analysisResult: document.getElementById('analysisResult'),
        analysisOutput: document.getElementById('analysisOutput'),
        
        // Área de alertas
        alertsArea: document.getElementById('alertsArea')
    };
}

// Função para inicializar navegação
function initNavigation() {
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Remove a classe 'active' de todos os links
            document.querySelectorAll('.navbar-nav .nav-link').forEach(navLink => {
                navLink.classList.remove('active');
            });
            
            // Adiciona a classe 'active' ao link clicado
            link.classList.add('active');
            
            // Obtém o ID do painel a ser exibido
            const panelId = link.getAttribute('href').substring(1);
            
            // Oculta todos os painéis
            document.querySelectorAll('.content-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            
            // Exibe o painel selecionado
            const selectedPanel = document.getElementById(panelId);
            if (selectedPanel) {
                selectedPanel.classList.add('active');
                activePanel = panelId;
                
                // Carrega dados específicos do painel, se necessário
                if (panelId === 'security') {
                    loadSecurityData();
                }
            }
        });
    });
}

// Função para inicializar os gráficos
function initCharts() {
    // Gráfico de consultas por minuto
    const queriesCtx = document.getElementById('queriesChart').getContext('2d');
    queriesChart = new Chart(queriesCtx, {
        type: 'line',
        data: {
            labels: Array(10).fill(''),
            datasets: [{
                label: 'Consultas por Minuto',
                data: Array(10).fill(0),
                borderColor: CONFIG.colors.primary,
                backgroundColor: 'rgba(13, 110, 253, 0.2)',
                tension: 0.2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Gráfico de tipos de consultas
    const queryTypesCtx = document.getElementById('queryTypesChart').getContext('2d');
    queryTypesChart = new Chart(queryTypesCtx, {
        type: 'doughnut',
        data: {
            labels: ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'Outros'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0, 0],
                backgroundColor: CONFIG.colors.chartColors
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Função para configurar listeners de eventos
function setupEventListeners() {
    // Botão para atualizar lista de IPs banidos
    if (elements.refreshBannedBtn) {
        elements.refreshBannedBtn.addEventListener('click', loadBannedIPs);
    }
    
    // Botão para atualizar whitelist
    if (elements.refreshWhitelistBtn) {
        elements.refreshWhitelistBtn.addEventListener('click', loadWhitelist);
    }
    
    // Botão para abrir modal de adicionar IP à whitelist
    if (elements.addWhitelistBtn) {
        elements.addWhitelistBtn.addEventListener('click', () => {
            elements.addWhitelistModal.show();
        });
    }
    
    // Botão para salvar IP na whitelist
    if (elements.saveWhitelistBtn) {
        elements.saveWhitelistBtn.addEventListener('click', addIPToWhitelist);
    }
    
    // Botão para executar análise de tráfego
    if (elements.runAnalysisBtn) {
        elements.runAnalysisBtn.addEventListener('click', runTrafficAnalysis);
    }
    
    // Botão para atualizar métricas manualmente
    if (elements.updateMetricsBtn) {
        elements.updateMetricsBtn.addEventListener('click', () => {
            refreshAllData();
            showAlert('Métricas atualizadas com sucesso!', 'success');
        });
    }
}

// Função para verificar autenticação
function checkAuthentication() {
    // Este é um placeholder. Em uma implementação real, você verificaria
    // se o usuário está autenticado fazendo uma chamada à API.
    authenticated = true;
}

// Função para carregar todas as estatísticas
function refreshAllData() {
    loadStats();
    
    // Se o painel de segurança estiver ativo, também carrega os dados de segurança
    if (activePanel === 'security') {
        loadSecurityData();
    }
    
    // Atualiza o timestamp da última atualização
    updateLastRefreshTime();
}

// Função para iniciar a atualização automática
function startAutoRefresh() {
    // Limpa qualquer timer existente
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }
    
    // Configura um novo timer
    refreshTimer = setInterval(() => {
        refreshAllData();
    }, CONFIG.refreshInterval);
}

// Função para carregar estatísticas do servidor DNS
function loadStats() {
    fetch(CONFIG.api.stats)
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao carregar estatísticas: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Armazena os dados mais recentes
            statsData = data;
            
            // Adiciona ao histórico, limitando o tamanho
            statsHistory.push(data);
            if (statsHistory.length > 10) {
                statsHistory.shift();
            }
            
            // Atualiza o dashboard com os novos dados
            updateDashboard(data);
        })
        .catch(error => {
            console.error('Erro ao carregar estatísticas:', error);
            showAlert(`Erro ao carregar estatísticas: ${error.message}`, 'danger');
        });
}

// Função para carregar dados de segurança
function loadSecurityData() {
    // Carrega IPs banidos
    loadBannedIPs();
    
    // Carrega whitelist
    loadWhitelist();
}

// Função para carregar IPs banidos
function loadBannedIPs() {
    fetch(CONFIG.api.banned, {
        headers: {
            'Authorization': 'Basic ' + btoa('admin:password') // Placeholder - use proper auth
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao carregar IPs banidos: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Atualiza card com número de IPs banidos
            if (elements.bannedIPs) {
                elements.bannedIPs.innerHTML = data.count || 0;
            }
            
            // Atualiza tabela de IPs banidos
            updateBannedIPsTable(data.banned_ips || []);
        })
        .catch(error => {
            console.error('Erro ao carregar IPs banidos:', error);
            if (elements.bannedIPs) {
                elements.bannedIPs.innerHTML = '<span class="text-danger">Erro</span>';
            }
            if (elements.bannedIPsTable) {
                elements.bannedIPsTable.innerHTML = `
                    <tr>
                        <td colspan="2" class="text-center text-danger">
                            Erro ao carregar IPs banidos: ${error.message}
                        </td>
                    </tr>
                `;
            }
        });
}

// Função para carregar whitelist
function loadWhitelist() {
    fetch(CONFIG.api.whitelist, {
        headers: {
            'Authorization': 'Basic ' + btoa('admin:password') // Placeholder - use proper auth
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao carregar whitelist: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Atualiza tabela de whitelist
            updateWhitelistTable(data.whitelist || []);
        })
        .catch(error => {
            console.error('Erro ao carregar whitelist:', error);
            if (elements.whitelistTable) {
                elements.whitelistTable.innerHTML = `
                    <tr>
                        <td colspan="2" class="text-center text-danger">
                            Erro ao carregar whitelist: ${error.message}
                        </td>
                    </tr>
                `;
            }
        });
}

// Função para remover um IP da whitelist
function removeFromWhitelist(ip) {
    if (!confirm(`Tem certeza de que deseja remover ${ip} da whitelist?`)) {
        return;
    }
    
    fetch(`${CONFIG.api.whitelist}/${ip}`, {
        method: 'DELETE',
        headers: {
            'Authorization': 'Basic ' + btoa('admin:password') // Placeholder - use proper auth
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao remover IP da whitelist: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            showAlert(`IP ${ip} removido da whitelist com sucesso!`, 'success');
            loadWhitelist();
        })
        .catch(error => {
            console.error('Erro ao remover da whitelist:', error);
            showAlert(`Erro ao remover IP da whitelist: ${error.message}`, 'danger');
        });
}

// Função para adicionar um IP à whitelist
function addIPToWhitelist() {
    const ip = elements.whitelistIP.value.trim();
    
    if (!ip) {
        showAlert('Por favor, insira um IP ou rede válida', 'warning');
        return;
    }
    
    fetch(CONFIG.api.whitelist, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa('admin:password') // Placeholder - use proper auth
        },
        body: JSON.stringify({ ip })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao adicionar IP à whitelist: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            elements.addWhitelistModal.hide();
            elements.whitelistIP.value = '';
            showAlert(`IP ${ip} adicionado à whitelist com sucesso!`, 'success');
            loadWhitelist();
        })
        .catch(error => {
            console.error('Erro ao adicionar à whitelist:', error);
            showAlert(`Erro ao adicionar IP à whitelist: ${error.message}`, 'danger');
        });
}

// Função para desbanir um IP
function unbanIP(ip) {
    if (!confirm(`Tem certeza de que deseja desbanir o IP ${ip}?`)) {
        return;
    }
    
    fetch(`${CONFIG.api.unban}/${ip}`, {
        method: 'POST',
        headers: {
            'Authorization': 'Basic ' + btoa('admin:password') // Placeholder - use proper auth
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao desbanir IP: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            showAlert(`IP ${ip} desbanido com sucesso!`, 'success');
            loadBannedIPs();
        })
        .catch(error => {
            console.error('Erro ao desbanir IP:', error);
            showAlert(`Erro ao desbanir IP: ${error.message}`, 'danger');
        });
}

// Função para executar análise de tráfego
function runTrafficAnalysis() {
    elements.runAnalysisBtn.disabled = true;
    elements.runAnalysisBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analisando...';
    
    fetch(CONFIG.api.analyze, {
        method: 'POST',
        headers: {
            'Authorization': 'Basic ' + btoa('admin:password') // Placeholder - use proper auth
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Erro ao executar análise: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Exibe o resultado da análise
            elements.analysisOutput.textContent = JSON.stringify(data, null, 2);
            elements.analysisResult.style.display = 'block';
            
            // Restaura o botão
            elements.runAnalysisBtn.disabled = false;
            elements.runAnalysisBtn.innerHTML = '<i class="bi bi-bar-chart"></i> Executar Análise de Tráfego';
            
            // Mostra alerta de sucesso
            showAlert('Análise de tráfego concluída com sucesso!', 'success');
        })
        .catch(error => {
            console.error('Erro ao executar análise:', error);
            elements.runAnalysisBtn.disabled = false;
            elements.runAnalysisBtn.innerHTML = '<i class="bi bi-bar-chart"></i> Executar Análise de Tráfego';
            showAlert(`Erro ao executar análise: ${error.message}`, 'danger');
        });
}

// Função para atualizar o dashboard com novos dados
function updateDashboard(data) {
    // Atualiza o status do servidor
    updateServerStatus(data);
    
    // Atualiza estatísticas básicas
    updateBasicStats(data);
    
    // Atualiza tabela de estatísticas detalhadas
    updateDetailedStats(data);
    
    // Atualiza os gráficos
    updateCharts();
}

// Função para atualizar o status do servidor
function updateServerStatus(data) {
    if (!elements.serverStatus) return;
    
    if (data.dns_server_status === 1 || data.unbound_status === 1) {
        elements.serverStatus.innerHTML = `
            <div class="server-status online">
                <i class="bi bi-check-circle"></i>
            </div>
            <div class="mt-2">Online</div>
        `;
    } else if (data.dns_server_warning === 1) {
        elements.serverStatus.innerHTML = `
            <div class="server-status warning">
                <i class="bi bi-exclamation-triangle"></i>
            </div>
            <div class="mt-2">Atenção</div>
        `;
    } else {
        elements.serverStatus.innerHTML = `
            <div class="server-status offline">
                <i class="bi bi-x-circle"></i>
            </div>
            <div class="mt-2">Offline</div>
        `;
    }
}

// Função para atualizar estatísticas básicas
function updateBasicStats(data) {
    // Consultas por segundo
    if (elements.queriesPerSecond) {
        elements.queriesPerSecond.innerHTML = Math.round(data.dns_queries_per_second || 0);
    }
    
    // Taxa de acerto do cache
    if (elements.cacheHitRate) {
        const hitRate = data.dns_cache_hit_rate || 0;
        elements.cacheHitRate.innerHTML = `${hitRate.toFixed(1)}%`;
    }
    
    // Tempo médio de resposta
    if (elements.avgResponseTime) {
        const responseTime = data.dns_avg_response_time || 0;
        elements.avgResponseTime.innerHTML = `${responseTime.toFixed(2)} ms`;
    }
    
    // Estatísticas de segurança
    if (elements.blockedThreats) {
        elements.blockedThreats.innerHTML = Math.round(data.dns_blocked_queries || 0);
    }
    
    if (elements.anomalyStatus) {
        if (data.dns_anomaly_detected === 1) {
            elements.anomalyStatus.innerHTML = `
                <span class="status-icon danger"><i class="bi bi-exclamation-triangle-fill"></i></span>
                <div>Sim</div>
            `;
        } else {
            elements.anomalyStatus.innerHTML = `
                <span class="status-icon success"><i class="bi bi-shield-check"></i></span>
                <div>Não</div>
            `;
        }
    }
    
    if (elements.abuseAttempts) {
        elements.abuseAttempts.innerHTML = Math.round(data.dns_abuse_attempts_24h || 0);
    }
}

// Função para atualizar estatísticas detalhadas
function updateDetailedStats(data) {
    if (!elements.detailedStatsTable) return;
    
    // Filtra e formata os dados para a tabela
    const metrics = [];
    for (const [key, value] of Object.entries(data)) {
        if (key.startsWith('dns_') && key !== 'timestamp' && key !== 'readable_time') {
            // Formata o nome da métrica para exibição
            const displayName = key
                .replace('dns_', '')
                .replace(/_/g, ' ')
                .replace(/\b\w/g, c => c.toUpperCase());
            
            // Formata o valor com base no tipo
            let displayValue = value;
            if (typeof value === 'number') {
                if (key.includes('percent') || key.includes('rate')) {
                    displayValue = `${value.toFixed(2)}%`;
                } else if (key.includes('time')) {
                    displayValue = `${value.toFixed(2)} ms`;
                } else if (Number.isInteger(value)) {
                    displayValue = value.toLocaleString();
                } else {
                    displayValue = value.toFixed(2);
                }
            }
            
            metrics.push({ name: displayName, value: displayValue });
        }
    }
    
    // Gera as linhas da tabela (em pares para duas colunas)
    let html = '';
    for (let i = 0; i < metrics.length; i += 2) {
        html += '<tr>';
        html += `<td>${metrics[i].name}</td>`;
        html += `<td>${metrics[i].value}</td>`;
        
        if (i + 1 < metrics.length) {
            html += `<td>${metrics[i+1].name}</td>`;
            html += `<td>${metrics[i+1].value}</td>`;
        } else {
            html += '<td></td><td></td>';
        }
        
        html += '</tr>';
    }
    
    elements.detailedStatsTable.innerHTML = html;
}

// Função para atualizar os gráficos
function updateCharts() {
    // Atualiza o gráfico de consultas
    if (queriesChart) {
        const queries = statsHistory.map(data => data.dns_queries_per_minute || 0);
        const labels = statsHistory.map((data, index) => {
            const date = new Date(data.timestamp * 1000);
            return `${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')}`;
        });
        
        queriesChart.data.labels = labels;
        queriesChart.data.datasets[0].data = queries;
        queriesChart.update();
    }
    
    // Atualiza o gráfico de tipos de consultas
    if (queryTypesChart && statsData) {
        const queryTypes = [
            statsData.dns_query_types_a || 0,
            statsData.dns_query_types_aaaa || 0,
            statsData.dns_query_types_ns || 0,
            statsData.dns_query_types_mx || 0,
            statsData.dns_query_types_txt || 0,
            statsData.dns_query_types_cname || 0,
            statsData.dns_query_types_other || 0
        ];
        
        queryTypesChart.data.datasets[0].data = queryTypes;
        queryTypesChart.update();
    }
}

// Função para atualizar tabela de IPs banidos
function updateBannedIPsTable(bannedIPs) {
    if (!elements.bannedIPsTable) return;
    
    if (bannedIPs.length === 0) {
        elements.bannedIPsTable.innerHTML = `
            <tr>
                <td colspan="2" class="text-center">
                    Nenhum IP banido no momento
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    for (const ip of bannedIPs) {
        html += `
            <tr>
                <td>${ip}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary action-btn" onclick="unbanIP('${ip}')">
                        <i class="bi bi-unlock"></i> Desbanir
                    </button>
                </td>
            </tr>
        `;
    }
    
    elements.bannedIPsTable.innerHTML = html;
}

// Função para atualizar tabela de whitelist
function updateWhitelistTable(whitelist) {
    if (!elements.whitelistTable) return;
    
    if (whitelist.length === 0) {
        elements.whitelistTable.innerHTML = `
            <tr>
                <td colspan="2" class="text-center">
                    Nenhum IP na whitelist
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    for (const ip of whitelist) {
        html += `
            <tr>
                <td>${ip}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger action-btn" onclick="removeFromWhitelist('${ip}')">
                        <i class="bi bi-trash"></i> Remover
                    </button>
                </td>
            </tr>
        `;
    }
    
    elements.whitelistTable.innerHTML = html;
}

// Função para mostrar alerta
function showAlert(message, type = 'info') {
    const alertsArea = elements.alertsArea;
    if (!alertsArea) return;
    
    const alertId = `alert-${Date.now()}`;
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Fechar"></button>
        </div>
    `;
    
    alertsArea.innerHTML += alertHtml;
    
    // Remove o alerta após alguns segundos
    setTimeout(() => {
        const alert = document.getElementById(alertId);
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

// Função para atualizar o timestamp da última atualização
function updateLastRefreshTime() {
    if (elements.lastUpdate) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString();
        elements.lastUpdate.innerHTML = `<i class="bi bi-clock"></i> Última atualização: ${timeStr}`;
    }
}

// Adicionamos as funções unbanIP e removeFromWhitelist ao escopo global
// para que possam ser chamadas dos elementos HTML
window.unbanIP = unbanIP;
window.removeFromWhitelist = removeFromWhitelist;