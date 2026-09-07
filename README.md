# Windows Threat Detector

Ferramenta de **Blue Team** desenvolvida em Python para análise de eventos de segurança do Windows, correlação de falhas de autenticação e identificação de comportamentos potencialmente maliciosos.

O projeto utiliza o **Windows Security Event Log** como fonte de dados, realiza a normalização dos eventos, aplica regras de correlação e associa as detecções a técnicas do framework **MITRE ATT&CK**.

> Projeto desenvolvido para fins educacionais, laboratoriais e defensivos de Segurança da Informação.

---

## Objetivo

O objetivo do Windows Threat Detector é construir uma ferramenta modular de detecção para ambientes Windows capaz de:

- coletar eventos reais do Windows;
- normalizar logs em estruturas internas;
- identificar eventos relevantes para segurança;
- correlacionar múltiplos eventos;
- reduzir falsos positivos;
- gerar alertas estruturados;
- mapear comportamentos ao MITRE ATT&CK;
- permitir configuração externa das regras;
- validar a lógica de detecção através de testes automatizados.

O projeto também tem como objetivo servir como laboratório prático de:

- Blue Team;
- SOC;
- Detection Engineering;
- Windows Event Logs;
- Threat Detection;
- MITRE ATT&CK;
- Python aplicado à Segurança da Informação.

---

## Funcionalidades atuais

Atualmente o projeto possui:

- leitura do Windows Security Event Log;
- coleta de eventos através de `pywin32`;
- normalização dos eventos em objetos `SecurityEvent`;
- análise do Windows Event ID `4625`;
- extração de informações de autenticação;
- identificação de usuário e domínio;
- identificação do endereço IP de origem;
- identificação do processo relacionado ao evento;
- identificação do tipo de logon;
- análise de status e substatus de autenticação;
- correlação temporal de eventos;
- agrupamento de falhas por usuário e IP;
- detecção de possíveis ataques de força bruta;
- configuração das regras através de YAML;
- geração estruturada de objetos `Alert`;
- mapeamento para MITRE ATT&CK;
- testes automatizados utilizando `pytest`.

---

## Estado atual do projeto

A primeira versão funcional do Windows Threat Detector já possui um fluxo completo de:

```text
Coleta
  ↓
Normalização
  ↓
Interpretação
  ↓
Correlação
  ↓
Detecção
  ↓
Alerta
  ↓
MITRE ATT&CK
```

### Componentes implementados

```text
Windows Event Log                 ✅
Canal Security                    ✅
Coleta com pywin32                ✅
SecurityEvent                     ✅
Event ID 4625                     ✅
Parser de autenticação            ✅
Extração de usuário               ✅
Extração de IP                    ✅
Extração de processo              ✅
Correlação temporal               ✅
Agrupamento usuário + IP          ✅
Detecção de brute force           ✅
Alert model                       ✅
MITRE ATT&CK T1110                ✅
Configuração YAML                 ✅
Testes automatizados              ✅
```

---

## Arquitetura

O fluxo atual da aplicação é:

```text
Windows Security Event Log
            |
            v
         pywin32
            |
            v
 WindowsEventCollector
            |
            v
      SecurityEvent
            |
            v
   Event ID 4625 Parser
            |
            v
 AuthenticationDetector
            |
            v
 Correlação por usuário + IP
            |
            v
      Janela temporal
            |
       +----+----+
       |         |
       v         v
    Normal    Suspeito
                 |
                 v
               Alert
                 |
                 v
        MITRE ATT&CK T1110
```

A arquitetura foi dividida em componentes para evitar que toda a lógica da aplicação fique concentrada em um único arquivo.

---

## Estrutura do projeto

```text
windows-threat-detector/
│
├── config/
│   └── detector.yaml
│
├── src/
│   └── threat_detector/
│       │
│       ├── __init__.py
│       ├── __main__.py
│       ├── main.py
│       ├── settings.py
│       │
│       ├── collector/
│       │   ├── __init__.py
│       │   └── windows_eventlog.py
│       │
│       ├── detection/
│       │   ├── __init__.py
│       │   └── authentication.py
│       │
│       ├── mitre/
│       │   ├── __init__.py
│       │   └── mappings.py
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── alert.py
│       │   └── event.py
│       │
│       └── output/
│           ├── __init__.py
│           └── console.py
│
├── tests/
│   └── test_authentication.py
│
├── reports/
│
├── .gitignore
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## Componentes

### WindowsEventCollector

Arquivo:

```text
src/threat_detector/collector/windows_eventlog.py
```

Responsável por acessar o Windows Event Log através da biblioteca `pywin32`.

Fluxo:

```text
Windows
   ↓
Security Event Log
   ↓
pywin32
   ↓
WindowsEventCollector
```

O coletor realiza a leitura dos eventos e os transforma em objetos internos utilizados pelo restante da aplicação.

---

### SecurityEvent

Arquivo:

```text
src/threat_detector/models/event.py
```

Representa um evento de segurança normalizado.

Em vez de todas as partes do programa trabalharem diretamente com a estrutura original dos logs do Windows, os dados são convertidos para um formato consistente.

Exemplos de informações armazenadas:

```text
Event ID
Timestamp
Computer
Channel
Username
Domain
Source IP
Source Port
Logon Type
Process
Status
Substatus
```

---

### AuthenticationDetector

Arquivo:

```text
src/threat_detector/detection/authentication.py
```

Responsável por analisar eventos relacionados à autenticação.

A primeira detecção implementada é a identificação de possíveis ataques de força bruta através do Event ID `4625`.

O detector agrupa os eventos considerando:

```text
Usuário
   +
IP de origem
   +
Janela temporal
```

A simples existência de múltiplos eventos `4625` não é suficiente para gerar um alerta.

Isso ajuda a reduzir falsos positivos.

---

### Alert

Arquivo:

```text
src/threat_detector/models/alert.py
```

Representa um comportamento considerado relevante pelo mecanismo de detecção.

Existe uma separação proposital entre:

```text
SecurityEvent
```

e:

```text
Alert
```

Um `SecurityEvent` representa algo que ocorreu no sistema.

Um `Alert` representa uma conclusão produzida pelo mecanismo de detecção após analisar um ou vários eventos.

---

## Detecção implementada

### Possível ataque de força bruta

A primeira regra implementada analisa:

```text
Windows Event ID 4625
```

Esse evento representa uma falha de logon.

A detecção considera:

```text
Event ID 4625
      +
mesmo usuário
      +
mesmo endereço IP
      +
quantidade mínima de falhas
      +
janela temporal configurada
      |
      v
Possível ataque de força bruta
```

A regra atual do ambiente de laboratório utiliza:

```text
5 falhas
dentro de
300 segundos
```

para o mesmo usuário e endereço IP.

A existência de múltiplos eventos `4625` isoladamente não é suficiente para caracterizar um possível ataque de força bruta.

---

## Configuração

As regras não ficam fixas diretamente no código Python.

A configuração é armazenada em:

```text
config/detector.yaml
```

Configuração atual:

```yaml
authentication:
  brute_force:
    enabled: true
    event_id: 4625
    threshold: 5
    window_seconds: 300
    severity: HIGH

    mitre:
      id: T1110
      technique: Brute Force
```

Isso permite alterar a sensibilidade da detecção sem modificar o código-fonte.

Por exemplo:

```yaml
threshold: 10
```

pode ser utilizado para exigir dez falhas antes da geração do alerta.

---

## MITRE ATT&CK

A detecção atual é mapeada para:

```text
T1110 - Brute Force
```

Fluxo:

```text
Falhas de autenticação
        ↓
Event ID 4625
        ↓
Correlação temporal
        ↓
Possível Brute Force
        ↓
MITRE ATT&CK
        ↓
T1110
```

O mapeamento das técnicas fica centralizado em:

```text
src/threat_detector/mitre/mappings.py
```

A intenção é ampliar gradualmente essa estrutura à medida que novas detecções forem implementadas.

---

## Windows Event ID 4625

O Event ID `4625` registra uma tentativa malsucedida de logon.

Durante os testes do projeto, foram extraídas informações como:

```text
Usuário
Domínio
Status
Substatus
Logon Type
Logon Process
Authentication Package
Process ID
Process Name
Source IP
Source Port
```

Exemplo anonimizado de evento analisado durante o laboratório:

```text
Event ID       : 4625
Usuário        : lab-user
Domínio        : LAB
Logon Type     : 2
Logon Process  : seclogo
Autenticação   : Negotiate
Status         : 0xc000006d
Substatus      : 0xc000006a
Processo       : C:\Windows\System32\svchost.exe
IP de origem   : ::1
```

Nesse cenário:

```text
0xc000006d
```

indica uma falha de autenticação.

O substatus:

```text
0xc000006a
```

indica uma situação de senha incorreta.

O endereço:

```text
::1
```

representa o endereço IPv6 de loopback, equivalente ao:

```text
127.0.0.1
```

em IPv4.

---

## Outros eventos observados

Durante os testes do Windows Security Event Log também foram encontrados eventos como:

```text
4624 - Logon realizado com sucesso
4672 - Privilégios especiais atribuídos a uma nova sessão
4625 - Falha de logon
```

Esses eventos foram utilizados durante o desenvolvimento para validar a coleta e interpretação dos logs do Windows.

---

## Validação em ambiente real

Uma tentativa controlada de autenticação inválida foi realizada no ambiente de laboratório.

O fluxo observado foi:

```text
Tentativa de autenticação inválida
              ↓
Windows registra Event ID 4625
              ↓
Security Event Log
              ↓
WindowsEventCollector
              ↓
SecurityEvent
              ↓
Windows Threat Detector
```

O programa identificou corretamente o evento criado pelo sistema operacional.

---

## Exemplo de execução

Exemplo de execução no ambiente de laboratório:

```text
Windows Threat Detector v0.1
[*] Inicializando detector...
[*] Regra carregada: 5 falhas em 300 segundos.
[*] Coletando falhas de autenticação (Event ID 4625)...
[+] 7 falhas de autenticação encontradas.
[*] Executando análise de correlação...
[OK] Nenhum padrão de força bruta detectado.
```

Nesse exemplo existem sete eventos de falha de autenticação registrados no Windows.

Entretanto, eles não atendem simultaneamente aos critérios necessários para caracterizar o padrão definido pela regra:

```text
mesmo usuário
+
mesmo IP
+
5 ou mais falhas
+
dentro de 300 segundos
```

Portanto, nenhum alerta é gerado.

Esse comportamento é intencional e demonstra que o sistema não considera simplesmente a quantidade total de eventos como evidência suficiente de um ataque.

---

## Exemplo de alerta

Quando a quantidade configurada de eventos correlacionados é atingida, o detector pode gerar uma saída semelhante a:

```text
======================================================================
WINDOWS THREAT DETECTOR - ALERTA
======================================================================
Severidade     : HIGH
Título         : Possível ataque de força bruta
Descrição      : 5 falhas de autenticação foram detectadas dentro
                 da janela configurada.

Evidências
----------------------------------------------------------------------
Event ID       : 4625
Usuário        : lab-user
IP de origem   : 192.0.2.10
Tentativas     : 5
Primeiro evento: 2026-09-07 10:00:00
Último evento  : 2026-09-07 10:02:00

MITRE ATT&CK
----------------------------------------------------------------------
Técnica        : T1110
Nome           : Brute Force
======================================================================
```

O endereço `192.0.2.10` utilizado no exemplo é apenas um endereço de documentação e não representa o ambiente real utilizado durante o desenvolvimento.

---

## Testes automatizados

A lógica de detecção possui testes automatizados através do `pytest`.

Arquivo:

```text
tests/test_authentication.py
```

Atualmente são validados quatro cenários.

### 1. Poucas falhas

```text
3 falhas
mesmo usuário
mesmo IP
dentro da janela
        ↓
nenhum alerta
```

Esse teste ajuda a verificar a prevenção de falsos positivos.

### 2. Brute force

Um dos testes instancia o detector com um `threshold` específico de `10` tentativas para validar a lógica independentemente da configuração YAML utilizada pelo ambiente real.

```text
10 falhas
mesmo usuário
mesmo IP
dentro de 300 segundos
        ↓
alerta HIGH
        ↓
MITRE T1110
```

A configuração do ambiente de laboratório pode utilizar um threshold diferente, como `5`.

Os testes automatizados são independentes da configuração de execução da aplicação.

### 3. Eventos fora da janela temporal

Mesmo existindo várias falhas:

```text
10:00
10:01
10:02
10:03
...
```

se a quantidade necessária não estiver concentrada dentro da janela configurada, nenhum alerta deve ser criado.

### 4. IPs diferentes

Eventos provenientes de IPs diferentes não são agrupados como se fossem uma única origem.

Exemplo:

```text
192.0.2.10 → 5 falhas
192.0.2.20 → 5 falhas
```

não é interpretado automaticamente como:

```text
10 falhas → ataque
```

Cada origem é analisada separadamente.

---

## Resultado atual dos testes

Execução:

```powershell
pytest -v
```

Resultado:

```text
tests/test_authentication.py::test_three_failures_do_not_generate_alert PASSED
tests/test_authentication.py::test_ten_failures_generate_brute_force_alert PASSED
tests/test_authentication.py::test_failures_outside_time_window_do_not_generate_alert PASSED
tests/test_authentication.py::test_different_source_ips_are_not_combined PASSED

4 passed
```

Os testes permitem validar a lógica de detecção sem a necessidade de gerar repetidamente falhas reais de autenticação no sistema operacional.

---

## Requisitos

O projeto foi desenvolvido e testado com:

```text
Windows
Python 3.11+
pywin32
PyYAML
pytest
```

A leitura do Windows Security Event Log pode exigir privilégios administrativos.

---

## Instalação

Clone o repositório:

```powershell
git clone https://github.com/DaniloArantesVieira/windows-threat-detector.git
```

Entre na pasta:

```powershell
cd windows-threat-detector
```

Crie um ambiente virtual:

```powershell
python -m venv .venv
```

Ative o ambiente:

```powershell
.\.venv\Scripts\Activate.ps1
```

Instale as dependências:

```powershell
pip install -r requirements.txt
```

---

## Dependências

O arquivo:

```text
requirements.txt
```

contém as dependências necessárias para executar o detector:

```text
pywin32
PyYAML
```

Para desenvolvimento e testes:

```text
requirements-dev.txt
```

com:

```text
-r requirements.txt
pytest
```

Instalação completa para desenvolvimento:

```powershell
pip install -r requirements-dev.txt
```

---

## Executando

O Windows Security Event Log pode exigir privilégios elevados.

Abra o **PowerShell como Administrador**.

Entre na pasta do projeto:

```powershell
cd windows-threat-detector
```

Ative o ambiente virtual:

```powershell
.\.venv\Scripts\Activate.ps1
```

Entre na pasta `src`:

```powershell
cd src
```

Execute:

```powershell
python -m threat_detector
```

---

## Problemas de permissão

Caso seja exibido um erro semelhante a:

```text
O cliente não tem o privilégio necessário.
```

ou:

```text
Sem permissão para acessar o Windows Security Event Log.
```

execute o terminal como Administrador.

O canal `Security` possui restrições adicionais de acesso impostas pelo Windows.

---

## Executando os testes

A partir da raiz do projeto:

```powershell
cd windows-threat-detector
```

Execute:

```powershell
pytest -v
```

Resultado esperado atualmente:

```text
4 passed
```

---

## Segurança e redução de falsos positivos

O projeto foi desenvolvido evitando uma associação simplista como:

```text
Event ID 4625 = ataque
```

Uma falha de autenticação isolada pode ocorrer por diversos motivos legítimos.

Por isso, a lógica atual utiliza correlação:

```text
Event ID
+
Usuário
+
Origem
+
Quantidade
+
Tempo
```

somente então avaliando se o comportamento pode representar uma ameaça.

Essa abordagem aproxima o projeto de uma lógica utilizada em soluções defensivas de monitoramento e detecção.

---

## Status da versão

### v0.1 — Authentication Detection

```text
[✓] Estrutura modular Python
[✓] Windows Security Event Log
[✓] pywin32
[✓] Event ID 4625
[✓] SecurityEvent
[✓] Parser de falhas de autenticação
[✓] Extração de usuário
[✓] Extração de endereço IP
[✓] Extração de processo
[✓] Correlação temporal
[✓] Agrupamento por usuário + IP
[✓] Detecção de força bruta
[✓] Alert model
[✓] MITRE ATT&CK T1110
[✓] Configuração YAML
[✓] Testes automatizados
[✓] 4 testes passando
```

---

## Roadmap

### v0.2 — Defense Evasion

- [ ] Event ID `1102`
- [ ] Detecção de limpeza do Windows Security Event Log
- [ ] MITRE ATT&CK `T1070.001`
- [ ] Geração de alerta específico
- [ ] Testes automatizados

### v0.3 — Account Monitoring

- [ ] Event ID `4720`
- [ ] Detecção de criação de usuários
- [ ] Event ID `4732`
- [ ] Monitoramento de alterações em grupos locais privilegiados
- [ ] Mapeamento MITRE ATT&CK
- [ ] Testes automatizados

### v0.4 — Process Monitoring

- [ ] Event ID `4688`
- [ ] Monitoramento de criação de processos
- [ ] Identificação de processos potencialmente suspeitos
- [ ] Análise de linha de comando

### v0.5 — PowerShell Detection

- [ ] PowerShell Script Block Logging
- [ ] Event ID `4104`
- [ ] Detecção de comandos suspeitos
- [ ] Risk scoring
- [ ] MITRE ATT&CK `T1059.001`

### v0.6 — Sysmon

- [ ] Suporte ao Sysmon
- [ ] Process Creation
- [ ] Network Connections
- [ ] File Creation
- [ ] Registry Events
- [ ] DNS Events

### Futuro

- [ ] Regras Sigma
- [ ] Regras YARA
- [ ] Exportação de alertas em JSON
- [ ] Relatórios de investigação
- [ ] IOC enrichment
- [ ] Threat Intelligence
- [ ] Integração com Wazuh
- [ ] Integração com SIEM
- [ ] API REST
- [ ] Dashboard
- [ ] Histórico de alertas
- [ ] Estatísticas de detecção

---

## Próximas detecções planejadas

O objetivo é evoluir gradualmente o projeto para detectar comportamentos como:

```text
Falhas repetidas de autenticação
Criação de usuários
Alterações de privilégios
Criação de serviços
Execução suspeita de PowerShell
Criação de processos
Limpeza de logs
Atividade de persistência
Conexões suspeitas
```

Cada nova detecção deverá possuir:

```text
Evento
  ↓
Normalização
  ↓
Regra de detecção
  ↓
MITRE ATT&CK
  ↓
Alert
  ↓
Teste automatizado
```

---

## Finalidade do projeto

O Windows Threat Detector não tem como objetivo substituir soluções comerciais de EDR, XDR ou SIEM.

O projeto foi criado como laboratório de estudo e portfólio para demonstrar conhecimentos práticos relacionados a:

```text
Blue Team
SOC
Detection Engineering
Windows Security
Windows Event Logs
Log Analysis
Event Correlation
Threat Detection
MITRE ATT&CK
Python
Testes automatizados
```

---

## Aviso de uso

Este projeto deve ser utilizado exclusivamente para:

- fins educacionais;
- estudos de Segurança da Informação;
- laboratórios próprios;
- ambientes autorizados;
- testes defensivos;
- monitoramento de sistemas sob responsabilidade do usuário.

Não utilize a ferramenta em ambientes nos quais você não possui autorização.

---

## Autor

**Danilo Arantes**

Projeto desenvolvido como parte de estudos e aprofundamento prático em **Cybersecurity, Blue Team e Detection Engineering**.