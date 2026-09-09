# Windows Threat Detector

[![CI](https://github.com/DaniloArantesVieira/windows-threat-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/DaniloArantesVieira/windows-threat-detector/actions/workflows/ci.yml)

Ferramenta de **Blue Team** desenvolvida em Python para análise do Windows Security Event Log, correlação de eventos de autenticação e identificação de comportamentos potencialmente maliciosos.

O projeto coleta e normaliza eventos de segurança do Windows, aplica regras de detecção e correlação e associa os alertas gerados a técnicas do framework **MITRE ATT&CK**.

> Projeto desenvolvido para fins educacionais, laboratoriais e defensivos de Segurança da Informação.

---

## Visão geral

O Windows Threat Detector foi criado como uma ferramenta modular de detecção para ambientes Windows e como laboratório prático de segurança defensiva.

O projeto tem como principais objetivos:

- coletar eventos reais do Windows;
- normalizar logs em estruturas internas;
- identificar eventos relevantes para segurança;
- correlacionar múltiplos eventos;
- reduzir falsos positivos;
- gerar alertas estruturados;
- mapear comportamentos ao MITRE ATT&CK;
- permitir configuração externa das regras;
- validar a lógica de detecção através de testes automatizados.

A primeira detecção implementada analisa falhas de autenticação registradas pelo **Windows Event ID 4625** e procura identificar padrões compatíveis com ataques de força bruta.

O detector não considera uma falha de autenticação isolada como um ataque. Os eventos são correlacionados utilizando informações como:

- usuário;
- endereço IP de origem;
- quantidade de falhas;
- janela temporal.

Além do desenvolvimento da ferramenta, o projeto serve como laboratório prático de:

- Blue Team;
- SOC;
- Detection Engineering;
- Windows Event Logs;
- Threat Detection;
- Event Correlation;
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
- testes automatizados utilizando `pytest`;
- integração contínua através do GitHub Actions.

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

A arquitetura foi dividida em componentes independentes para evitar que toda a lógica da aplicação fique concentrada em um único arquivo.

Os componentes são separados por responsabilidades de:

- coleta;
- normalização;
- detecção;
- modelagem;
- mapeamento MITRE ATT&CK;
- apresentação dos alertas.

---

## Estrutura do projeto

```text
windows-threat-detector/
│
├── .github/
│   └── workflows/
│       └── ci.yml
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
├── LICENSE
├── README.md
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

---

## Principais componentes

### WindowsEventCollector

Arquivo:

```text
src/threat_detector/collector/windows_eventlog.py
```

Responsável por acessar o Windows Event Log através da biblioteca `pywin32`.

O coletor realiza a leitura dos eventos e os transforma em objetos internos utilizados pelo restante da aplicação.

Fluxo:

```text
Windows
   |
   v
Security Event Log
   |
   v
pywin32
   |
   v
WindowsEventCollector
```

---

### SecurityEvent

Arquivo:

```text
src/threat_detector/models/event.py
```

Representa um evento de segurança normalizado.

Em vez de todas as partes do programa trabalharem diretamente com a estrutura original dos logs do Windows, os dados são convertidos para um formato consistente.

Entre as informações representadas estão:

- Event ID;
- timestamp;
- computador;
- canal;
- usuário;
- domínio;
- endereço IP de origem;
- porta de origem;
- Logon Type;
- processo;
- status;
- substatus.

---

### AuthenticationDetector

Arquivo:

```text
src/threat_detector/detection/authentication.py
```

Responsável por analisar eventos relacionados à autenticação e aplicar regras de correlação.

A primeira regra implementada identifica possíveis ataques de força bruta através da combinação de:

```text
Usuário
   +
IP de origem
   +
Quantidade de falhas
   +
Janela temporal
```

A simples existência de múltiplos eventos `4625` não é suficiente para gerar um alerta.

Essa estratégia ajuda a reduzir falsos positivos.

---

### Alert

Arquivo:

```text
src/threat_detector/models/alert.py
```

Representa uma conclusão produzida pelo mecanismo de detecção.

Existe uma separação proposital entre:

```text
SecurityEvent
```

e:

```text
Alert
```

Um `SecurityEvent` representa algo observado no sistema.

Um `Alert` representa uma conclusão produzida após a análise e correlação de um ou vários eventos.

Essa distinção permite que múltiplos eventos sejam avaliados antes que o sistema classifique determinado comportamento como potencialmente suspeito.

---

## Detecção implementada

### Brute force — Event ID 4625

A primeira regra implementada analisa o **Windows Event ID `4625`**, que registra uma tentativa malsucedida de logon.

A detecção correlaciona:

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

No ambiente de laboratório, a configuração padrão utiliza:

```text
5 falhas em 300 segundos
```

para o mesmo usuário e endereço IP.

Múltiplos eventos `4625` isolados não são considerados evidência suficiente para gerar um alerta.

A correlação busca reduzir falsos positivos e identificar padrões de comportamento.

### Informações analisadas

Durante a normalização e interpretação dos eventos, o detector pode trabalhar com informações como:

- usuário;
- domínio;
- timestamp;
- status;
- substatus;
- Logon Type;
- Logon Process;
- Authentication Package;
- Process ID;
- Process Name;
- endereço IP de origem;
- porta de origem.

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

Nesse exemplo:

- `0xc000006d` representa uma falha de autenticação;
- `0xc000006a` indica uma situação de senha incorreta;
- `::1` representa o endereço IPv6 de loopback, equivalente a `127.0.0.1` em IPv4.

### MITRE ATT&CK

A detecção atual é mapeada para:

```text
T1110 — Brute Force
```

O fluxo de classificação é:

```text
Falhas de autenticação
        |
        v
Event ID 4625
        |
        v
Correlação temporal
        |
        v
Possível Brute Force
        |
        v
MITRE ATT&CK T1110
```

Os mapeamentos das técnicas ficam centralizados em:

```text
src/threat_detector/mitre/mappings.py
```

Essa estrutura deverá ser ampliada à medida que novas detecções forem implementadas.

---

## Configuração

As regras de detecção são configuradas externamente através de:

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

faz com que sejam necessárias dez falhas correlacionadas antes da geração do alerta.

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
              |
              v
Windows registra Event ID 4625
              |
              v
Security Event Log
              |
              v
WindowsEventCollector
              |
              v
SecurityEvent
              |
              v
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

Severidade      : HIGH
Título          : Possível ataque de força bruta
Descrição       : 5 falhas de autenticação foram detectadas dentro
                  da janela configurada.

Evidências
----------------------------------------------------------------------
Event ID        : 4625
Usuário         : lab-user
IP de origem    : 192.0.2.10
Tentativas      : 5
Primeiro evento : 2026-09-07 10:00:00
Último evento   : 2026-09-07 10:02:00

MITRE ATT&CK
----------------------------------------------------------------------
Técnica         : T1110
Nome            : Brute Force
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

Atualmente são validados quatro cenários principais.

### 1. Poucas falhas

```text
3 falhas
mesmo usuário
mesmo IP
dentro da janela
        |
        v
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
        |
        v
alerta HIGH
        |
        v
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
192.0.2.10 -> 5 falhas
192.0.2.20 -> 5 falhas
```

não é interpretado automaticamente como:

```text
10 falhas -> ataque
```

Cada origem é analisada separadamente.

### Resultado atual

Execute:

```powershell
pytest -v
```

Resultado esperado:

```text
tests/test_authentication.py::test_three_failures_do_not_generate_alert PASSED
tests/test_authentication.py::test_ten_failures_generate_brute_force_alert PASSED
tests/test_authentication.py::test_failures_outside_time_window_do_not_generate_alert PASSED
tests/test_authentication.py::test_different_source_ips_are_not_combined PASSED

4 passed
```

Os testes permitem validar a lógica de detecção sem a necessidade de gerar repetidamente falhas reais de autenticação no sistema operacional.

Além da execução local, a suíte é executada automaticamente através do **GitHub Actions**. O CI também valida o código com o **Ruff**.

Para executar o lint localmente:

```powershell
python -m ruff check .
```

---

## Requisitos

O projeto foi desenvolvido e testado com:

```text
Windows
Python 3.11+
pywin32
PyYAML
pytest
ruff
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

Para desenvolvimento e testes:

```powershell
pip install -r requirements-dev.txt
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

As dependências utilizadas para desenvolvimento e testes ficam em:

```text
requirements-dev.txt
```

incluindo:

```text
-r requirements.txt
pytest
ruff
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
   |
   v
Avaliação do comportamento
```

somente então avaliando se o comportamento pode representar uma ameaça.

Essa abordagem aproxima o projeto de uma lógica utilizada em soluções defensivas de monitoramento e detecção.

---

## Status da versão

### v0.1 — Authentication Detection

- [x] Estrutura modular Python
- [x] Windows Security Event Log
- [x] `pywin32`
- [x] Event ID `4625`
- [x] `SecurityEvent`
- [x] Parser de falhas de autenticação
- [x] Extração de usuário
- [x] Extração de endereço IP
- [x] Extração de processo
- [x] Correlação temporal
- [x] Agrupamento por usuário + IP
- [x] Detecção de força bruta
- [x] modelo `Alert`
- [x] MITRE ATT&CK `T1110`
- [x] configuração YAML
- [x] testes automatizados
- [x] 4 testes passando
- [x] GitHub Actions CI

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

## Finalidade do projeto

O Windows Threat Detector não tem como objetivo substituir soluções comerciais de EDR, XDR ou SIEM.

O projeto foi criado como laboratório de estudo e portfólio para demonstrar conhecimentos práticos relacionados a:

- Blue Team;
- SOC;
- Detection Engineering;
- Windows Security;
- Windows Event Logs;
- Log Analysis;
- Event Correlation;
- Threat Detection;
- MITRE ATT&CK;
- Python;
- testes automatizados.

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

## Licença

Este projeto é distribuído sob os termos da [MIT License](LICENSE).

---

## Autor

**Danilo Arantes**

Projeto desenvolvido como parte de estudos e aprofundamento prático em **Cybersecurity, Blue Team e Detection Engineering**.