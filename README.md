# 🛡️ SYS.TRIAGE - Client-Side SOC Log Analyzer

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Security](https://img.shields.io/badge/Security-Zero--Trust-success.svg)
![VanillaJS](https://img.shields.io/badge/JavaScript-Vanilla_ES6+-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 📌 O Problema (Contexto SOC)
Centros de Operações de Segurança (SOC) lidam com volumes massivos de tráfego. Durante um incidente (como um ataque de força bruta ou varredura de vulnerabilidades), ferramentas pesadas em nuvem ou SIEMs podem apresentar delay de indexação. Além disso, logs de acesso bruto de servidores (Apache/Nginx) frequentemente contêm **Informações Sensíveis (PII)** ou tokens de sessão. Fazer o upload desses logs para ferramentas de análise de terceiros na internet configura uma quebra grave de políticas de privacidade.

## 🚀 A Solução
**SYS.TRIAGE** é uma plataforma de resposta a incidentes que roda **100% no client-side (Navegador)**. 
Desenvolvida para fornecer uma visão imediata de anomalias em arquivos `access.log` brutos, a ferramenta garante total privacidade (Zero-Trust Data), processando tudo na memória local da máquina do analista sem disparar uma única requisição de rede para back-ends externos.

## 🧠 Arquitetura e Funcionalidades Core

* **Motor Regex Nativo (Alta Performance):** Parseamento linha a linha do padrão *Nginx Combined Format* em tempo real.
* **Detecção por Assinatura e Comportamento:**
  * Identificação de XSS (Cross-Site Scripting), SQL Injection e Path Traversal via assinaturas de payload.
  * Detecção de Scanners e Força Bruta através de heurística de volume (excesso de erros HTTP 401/404 pelo mesmo IP).
* **Processamento Assíncrono:** Utilização nativa da `FileReader API` para suportar leitura rápida sem travar a thread principal da UI.
* **Módulo de Exportação Forense:** Geração dinâmica de relatórios (CSV, XML e PDF) formatados para auditoria de compliance (ISO 27001, SOC 2).
* **Interface Tática:** Design focado em usabilidade, com suporte a *Drag & Drop* e visualização limpa de métricas críticas.

## 🛠️ Stack Tecnológica
* **Front-End Core:** HTML5, CSS3, Vanilla JavaScript (ES6+).
* **Estilização e Layout:** Bootstrap 5 (Dark Theme), CSS Customizado (Glassmorphism).
* **Data Visualization:** Chart.js
* **Engine de Exportação:** jsPDF, jsPDF-AutoTable (PDF) e Blob API nativa (CSV/XML).

## 🚦 Como Testar (Ambiente Local)

Como a aplicação é estritamente Client-Side, não há necessidade de containers Docker, servidores Node.js ou build steps complexos.

1. Clone o repositório:
   ```bash
   git clone [https://github.com/SEU_USUARIO/soc-triage-client.git](https://github.com/SEU_USUARIO/soc-triage-client.git)

2. Entre no link abaixo diretamente no seu navegador moderno de preferência (Chrome, Firefox, Brave, Edge ou Safari)

	[]

3. Utilize o arquivo **mock_attack.log** ou **financial_server_access.log** incluso na raiz do projeto, que contém simulações de tráfego legítimo mesclado com injeções maliciosas e tráfego de scanners. Arraste-o para a zona de upload.


## 🤝 Contribuição

Sugestões de novas assinaturas Regex para outros CVEs ou melhorias no motor de parseamento são bem-vindas. Sinta-se à vontade para abrir uma Issue ou enviar um Pull Request.


