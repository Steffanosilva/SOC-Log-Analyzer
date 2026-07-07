document.addEventListener("DOMContentLoaded", () => {
    // Referências de Navegação
    const landingPage = document.getElementById('landing-page');
    const appInterface = document.getElementById('app-interface');
    const btnStart = document.getElementById('btn-start');
    const btnBack = document.getElementById('btn-back');
    const btnNewAnalysis = document.getElementById('btn-new-analysis');

    // Referências da Aplicação
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const metricsSection = document.getElementById('metrics');
    const chartsSection = document.getElementById('charts-section');
    const tableSection = document.getElementById('table-section');
    const threatTableBody = document.getElementById('threat-table-body');
    const topIpsList = document.getElementById('top-ips');

    // Variáveis de Estado
    let attackChartInstance = null;
    let ipChartInstance = null;
    let currentThreatData = []; // Armazena os dados atuais para exportação

    // RegEx Nginx Combined Log Format
    const logPattern = /^(\S+) \S+ \S+ \[([^\]]+)\] "(.*?)" (\d{3}) (\S+) "(.*?)" "(.*?)"/;

    const signatures = {
        sqli: /(?:union\s+select|select\s+.*\s+from|update\s+.*\s+set|insert\s+into|drop\s+table|1=1|--\s*$|'or'|' OR ')/i,
        xss: /(?:<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie)/i,
        lfi: /(?:\.\.\/|\.\.\\|\/etc\/passwd|win\.ini|system32)/i
    };

    // --- LÓGICA DE NAVEGAÇÃO E ESTADO ---
    
    btnStart.addEventListener('click', () => {
        landingPage.classList.add('d-none');
        appInterface.classList.remove('d-none');
        appInterface.classList.add('d-flex');
    });

    function resetWorkspace() {
        metricsSection.classList.add('d-none');
        metricsSection.classList.remove('d-flex');
        chartsSection.classList.add('d-none');
        chartsSection.classList.remove('d-flex');
        tableSection.classList.add('d-none');
        tableSection.classList.remove('d-block');
        btnNewAnalysis.classList.add('d-none');
        
        dropZone.classList.remove('d-none');
        fileInput.value = ''; 
        currentThreatData = []; // Limpa o estado da memória

        if (attackChartInstance) attackChartInstance.destroy();
        if (ipChartInstance) ipChartInstance.destroy();
    }

    btnBack.addEventListener('click', () => {
        appInterface.classList.add('d-none');
        appInterface.classList.remove('d-flex');
        landingPage.classList.remove('d-none');
        resetWorkspace(); 
    });

    btnNewAnalysis.addEventListener('click', () => resetWorkspace());

    // --- LÓGICA DE ARQUIVOS (DRAG & DROP) ---

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-active');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-active'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-active');
        if (e.dataTransfer.files.length) {
            processFile(e.dataTransfer.files[0]);
        }
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            processFile(e.target.files[0]);
        }
    });

    function processFile(file) {
        if (!file.name.endsWith('.log') && !file.name.endsWith('.txt')) {
            alert('Acesso Negado: Formato de arquivo não suportado. Utilize .log ou .txt');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            analyzeLogs(e.target.result);
        };
        reader.readAsText(file);
    }

    // --- MOTOR DE ANÁLISE ---

    function analyzeLogs(logData) {
        const lines = logData.split('\n').filter(line => line.trim() !== '');
        
        let totalReqs = lines.length;
        let threats = [];
        let attackStats = { SQLi: 0, XSS: 0, PathTraversal: 0, BruteForce: 0 };
        let ipStats = {};

        lines.forEach((line) => {
            const match = line.match(logPattern);
            if (!match) return;

            const [_, ip, timestamp, request, status, bytes, referer, userAgent] = match;
            const fullPayload = `${request} ${referer} ${userAgent}`;

            if (!ipStats[ip]) ipStats[ip] = { total: 0, errors: 0, attacks: 0 };
            ipStats[ip].total += 1;
            
            if (status === '401' || status === '404') {
                ipStats[ip].errors += 1;
            }

            let threatType = null;
            let badgeClass = '';

            if (signatures.sqli.test(fullPayload)) { threatType = 'SQLi'; badgeClass = 'badge-sqli'; attackStats.SQLi++; }
            else if (signatures.xss.test(fullPayload)) { threatType = 'XSS'; badgeClass = 'badge-xss'; attackStats.XSS++; }
            else if (signatures.lfi.test(fullPayload)) { threatType = 'PathTraversal'; badgeClass = 'badge-lfi'; attackStats.PathTraversal++; }

            if (threatType) {
                ipStats[ip].attacks += 1;
                threats.push({ timestamp, ip, type: threatType, request, badgeClass, raw: line });
            }
        });

        const BRUTE_FORCE_THRESHOLD = 4;
        for (const [ip, stats] of Object.entries(ipStats)) {
            if (stats.errors >= BRUTE_FORCE_THRESHOLD && stats.attacks === 0) {
                attackStats.BruteForce += stats.errors;
                threats.push({
                    timestamp: "Vários",
                    ip: ip,
                    type: "Brute Force",
                    request: `Anomalia de volume: ${stats.errors}x 401/404 capturados`,
                    badgeClass: "badge-brute",
                    raw: `[ALERTA COMPORTAMENTAL] Padrão anômalo de acessos negados gerado pelo host ${ip}`
                });
            }
        }

        // Atualiza a variável global com os dados processados
        currentThreatData = threats;
        updateDashboard(totalReqs, threats, attackStats, ipStats);
    }

    function updateDashboard(totalReqs, threats, attackStats, ipStats) {
        metricsSection.classList.remove('d-none');
        chartsSection.classList.remove('d-none');
        tableSection.classList.remove('d-none');
        
        metricsSection.classList.add('d-flex');
        chartsSection.classList.add('d-flex');
        tableSection.classList.add('d-block');

        dropZone.classList.add('d-none');
        btnNewAnalysis.classList.remove('d-none');

        document.getElementById('total-reqs').textContent = totalReqs.toLocaleString();
        document.getElementById('total-attacks').textContent = threats.length.toLocaleString();

        const topIps = Object.entries(ipStats)
            .sort((a, b) => (b[1].attacks + b[1].errors) - (a[1].attacks + a[1].errors))
            .slice(0, 5);

        topIpsList.innerHTML = topIps.map(([ip, stats]) => 
            `<li class="d-flex justify-content-between align-items-center border-bottom border-secondary pb-2">
                <span class="${stats.attacks > 0 || stats.errors > 3 ? 'text-danger' : 'text-cyan-glow'}">${ip}</span>
                <span class="badge bg-dark border border-secondary text-light">${stats.attacks + stats.errors} EVENTOS</span>
            </li>`
        ).join('');

        threatTableBody.innerHTML = threats.map(t => 
            `<tr>
                <td class="py-3 text-secondary">${t.timestamp.split(' ')[0]}</td>
                <td class="py-3 text-danger fw-bold">${t.ip}</td>
                <td class="py-3"><span class="badge ${t.badgeClass}">${t.type}</span></td>
                <td class="py-3 text-truncate text-secondary" style="max-width: 400px;" title='${t.raw.replace(/'/g, "&#39;")}'>
                    ${escapeHTML(t.request)}
                </td>
            </tr>`
        ).join('');

        renderCharts(attackStats, ipStats);
    }

    function renderCharts(attackStats, ipStats) {
        if (attackChartInstance) attackChartInstance.destroy();
        if (ipChartInstance) ipChartInstance.destroy();

        const ctxAttack = document.getElementById('attackChart').getContext('2d');
        attackChartInstance = new Chart(ctxAttack, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'Path Traversal', 'Brute Force/Scanner'],
                datasets: [{
                    data: [attackStats.SQLi, attackStats.XSS, attackStats.PathTraversal, attackStats.BruteForce],
                    backgroundColor: ['#dc3545', '#ffc107', '#6f42c1', '#0dcaf0'],
                    borderColor: '#020617',
                    borderWidth: 2
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#06b6d4' } } } }
        });

        const sortedIps = Object.entries(ipStats)
            .sort((a, b) => (b[1].attacks + b[1].errors) - (a[1].attacks + a[1].errors))
            .slice(0, 7);

        const ctxIp = document.getElementById('ipChart').getContext('2d');
        ipChartInstance = new Chart(ctxIp, {
            type: 'bar',
            data: {
                labels: sortedIps.map(item => item[0]),
                datasets: [{
                    label: 'Eventos de Segurança',
                    data: sortedIps.map(item => item[1].attacks + item[1].errors),
                    backgroundColor: '#06b6d4',
                    borderRadius: 2
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: { y: { beginAtZero: true, grid: { color: 'rgba(6, 182, 212, 0.1)' }, ticks: { color: 'rgba(6, 182, 212, 0.5)' } }, x: { grid: { display: false }, ticks: { color: 'rgba(6, 182, 212, 0.5)' } } },
                plugins: { legend: { display: false } }
            }
        });
    }

    function escapeHTML(str) {
        const p = document.createElement("p");
        p.appendChild(document.createTextNode(str));
        return p.innerHTML;
    }

    // --- LÓGICA DE EXPORTAÇÃO DE RELATÓRIOS ---

    // Função utilitária para forçar download
    function triggerDownload(content, filename, type) {
        const blob = new Blob([content], { type: type });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    // Exportar CSV (Excel)
    document.getElementById('btn-export-csv').addEventListener('click', (e) => {
        e.preventDefault();
        if (!currentThreatData.length) return alert('Nenhum dado malicioso detectado para exportar.');
        
        // Adicionando BOM para o Excel ler acentuação corretamente
        let csvContent = '\uFEFF'; 
        csvContent += "Timestamp,Origem (IP),Tipo de Ataque,Payload Bruto\n";
        
        currentThreatData.forEach(t => {
            // Escapar aspas duplas no payload para não quebrar as colunas do CSV
            let safePayload = t.raw.replace(/"/g, '""');
            csvContent += `"${t.timestamp}","${t.ip}","${t.type}","${safePayload}"\n`;
        });
        triggerDownload(csvContent, 'soc_triage_export.csv', 'text/csv;charset=utf-8;');
    });

    // Exportar XML
    document.getElementById('btn-export-xml').addEventListener('click', (e) => {
        e.preventDefault();
        if (!currentThreatData.length) return alert('Nenhum dado malicioso detectado para exportar.');
        
        let xmlContent = '<?xml version="1.0" encoding="UTF-8"?>\n<ThreatLogs>\n';
        currentThreatData.forEach(t => {
            xmlContent += `  <Event>\n`;
            xmlContent += `    <Timestamp>${t.timestamp}</Timestamp>\n`;
            xmlContent += `    <IP>${t.ip}</IP>\n`;
            xmlContent += `    <Type>${t.type}</Type>\n`;
            // Envelopar payload em CDATA para que scripts XSS não quebrem o parser XML
            xmlContent += `    <Payload><![CDATA[${t.raw}]]></Payload>\n`;
            xmlContent += `  </Event>\n`;
        });
        xmlContent += '</ThreatLogs>';
        triggerDownload(xmlContent, 'soc_triage_export.xml', 'application/xml');
    });

    // Exportar PDF
    document.getElementById('btn-export-pdf').addEventListener('click', (e) => {
        e.preventDefault();
        if (!currentThreatData.length) return alert('Nenhum dado malicioso detectado para exportar.');
        
        // Inicializa jsPDF da window (carregado via CDN)
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF('landscape'); // Formato deitado para caber os logs
        
        // Cabeçalho do PDF
        doc.setFontSize(16);
        doc.setTextColor(220, 53, 69); // Vermelho Alerta
        doc.text('SYS.TRIAGE - RELATORIO DE INTERCEPTACAO TATICA', 14, 15);
        doc.setFontSize(10);
        doc.setTextColor(100);
        doc.text(`Data de Geracao: ${new Date().toLocaleString()}`, 14, 22);

        // Montando as linhas da tabela
        const tableBody = currentThreatData.map(t => {
            // Truncar o payload no PDF para não quebrar a página infinitamente
            let shortPayload = t.raw.length > 90 ? t.raw.substring(0, 87) + '...' : t.raw;
            return [t.timestamp.split(' ')[0], t.ip, t.type, shortPayload];
        });

        // Configuração da Tabela usando o plugin AutoTable
        doc.autoTable({
            startY: 28,
            head: [['Timestamp', 'Origem IP', 'Classificacao', 'Payload (Truncado)']],
            body: tableBody,
            theme: 'grid',
            headStyles: { fillColor: [15, 23, 42], textColor: [6, 182, 212], font: 'courier' },
            bodyStyles: { font: 'courier', fontSize: 8 },
            alternateRowStyles: { fillColor: [245, 245, 245] }
        });

        doc.save('soc_triage_report.pdf');
    });

});