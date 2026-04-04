# AWS-CloudTrail-Investigando-um-Hack-em-um-Site

Este laboratório simula um cenário real onde o site do Café é hackeado logo após a ativação de uma trilha do **AWS CloudTrail**. O objetivo é investigar a origem do ataque, identificar o responsável e aplicar medidas corretivas e de segurança.

### 🎯 O que você vai aprender

- Criar e configurar uma trilha no AWS CloudTrail
- Analisar logs do CloudTrail usando:
  - Utilitário Linux `grep`
  - AWS CLI
  - Amazon Athena (consultas SQL)
- Identificar ações suspeitas em grupos de segurança EC2
- Remover acesso de usuários maliciosos (SO e IAM)
- Corrigir configurações de segurança (SSH) e restaurar o site

### ⏱️ Duração estimada

75 minutos

---

## 🧩 Arquitetura utilizada

- 1 instância EC2 (Café Web Server)
- 1 grupo de segurança (WebSecurityGroup)
- AWS CloudTrail + bucket S3 para logs
- Amazon Athena para consultas SQL
- IAM para gerenciamento de usuários

---

## 📁 Estrutura do Repositório

```bash
📂 aws-cloudtrail-investigation-lab/
├── README.md                 # Este arquivo
├── queries/                  # Consultas SQL utilizadas no Athena
│   └── hacker_identification.sql
├── scripts/                  # Comandos úteis para análise
│   └── grep_analysis.sh
└── results/                  # Evidências encontradas (exemplo)
    └── hacker_info.txt

🧪 Passo a Passo do Laboratório

✅ Pré-requisitos

    Conta AWS com permissões para criar recursos (CloudTrail, S3, EC2, Athena, IAM)

    Acesso SSH à instância EC2 (via PuTTY no Windows ou terminal no macOS/Linux)

🔹 Tarefa 1 – Configuração inicial e observação do site

    Acesse o console EC2 e localize a instância Café Web Server.

    No grupo de segurança associado, adicione uma regra de entrada para SSH (porta 22) restrita ao seu IP (Meu IP).

    Acesse o site via navegador:
    http://<IP_PUBLICO_DA_INSTANCIA>/cafe/
    O site aparece normal.

🔹 Tarefa 2 – Criar trilha no CloudTrail e detectar o hack

    No serviço CloudTrail, crie uma trilha chamada monitor.

    Crie um bucket S3 novo com nome monitoring#### (#### = 4 dígitos aleatórios).

    Após alguns minutos, atualize o site → ele foi hackeado (imagem alterada).

    No grupo de segurança, uma nova regra SSH 0.0.0.0/0 aparece (brecha criada pelo hacker).

🔹 Tarefa 3 – Análise com grep e AWS CLI
Conectar via SSH à instância EC2
bash

ssh -i labsuser.pem ec2-user@<IP_PUBLICO>

Baixar e extrair logs do CloudTrail
bash

mkdir ctraillogs && cd ctraillogs
aws s3 ls
aws s3 cp s3://monitoring####/ . --recursive
gunzip *.gz

Usar grep para inspecionar logs
bash

# Ver sourceIPAddress
for i in $(ls); do echo $i && cat $i | python -m json.tool | grep sourceIPAddress; done

# Ver eventName
for i in $(ls); do echo $i && cat $i | python -m json.tool | grep eventName; done

Usar AWS CLI para lookup events
bash

aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin

# Buscar ações em grupos de segurança
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::SecurityGroup --output text

# Filtrar pelo ID do grupo de segurança
region=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | cut -d '"' -f4)
sgId=$(aws ec2 describe-instances --filters "Name=tag:Name,Values='Cafe Web Server'" --query 'Reservations[*].Instances[*].SecurityGroups[*].[GroupId]' --region $region --output text)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::SecurityGroup --region $region --output text | grep $sgId

🔹 Tarefa 4 – Análise com Amazon Athena

    No console do CloudTrail, vá em Event history → Create Athena table.

    Escolha o bucket S3 monitoring#### e crie a tabela.

    No Athena Query Editor, configure o local de resultados:
    s3://monitoring####/results/

    Execute consultas SQL para identificar o hacker.

Exemplo de consulta inicial
sql

SELECT useridentity.userName, eventtime, eventsource, eventname, requestparameters
FROM cloudtrail_logs_monitoring####
LIMIT 30;

Consulta para identificar o hacker
sql

SELECT DISTINCT useridentity.userName, eventName, eventSource
FROM cloudtrail_logs_monitoring####
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -1, now())
ORDER BY eventSource;

✅ O que você deve encontrar

    Nome do usuário IAM: chaos

    Ação: AuthorizeSecurityGroupIngress (abriu porta 22 para 0.0.0.0/0)

    Origem: acesso programático (AWS CLI)

    Horário exato e IP de origem

🔹 Tarefa 5 – Correções e remediação
5.1 Remover usuário malicioso do SO
bash

sudo aureport --auth          # ver logins recentes
who                           # ver usuários logados
sudo userdel -r chaos-user    # remover usuário (falha se logado)
sudo kill -9 <PID>            # matar processo do chaos-user
sudo userdel -r chaos-user    # agora funciona

5.2 Ajustar configuração SSH
bash

sudo vi /etc/ssh/sshd_config
# Comentar: PasswordAuthentication yes
# Descomentar: PasswordAuthentication no
sudo service sshd restart

5.3 Remover regra SSH aberta no grupo de segurança

    Console EC2 → Security Groups → editar regras de entrada

    Remover a regra 0.0.0.0/0 para porta 22

5.4 Restaurar o site
bash

cd /var/www/html/cafe/images/
sudo mv Coffee-and-Pastries.backup Coffee-and-Pastries.jpg

5.5 Excluir usuário chaos do IAM

    Console IAM → Users → selecionar chaos → Delete

📊 Evidências coletadas (exemplo)
Campo	Valor encontrado
Nome do usuário IAM	chaos
Ação executada	AuthorizeSecurityGroupIngress
IP de origem	203.0.113.45 (exemplo)
Método	Programático (AWS CLI)
Porta aberta	22 (SSH) para 0.0.0.0/0

📄 Arquivo: queries/hacker_identification.sql
sql

-- =====================================================
-- CONSULTAS PARA IDENTIFICAR O HACKER NO LABORATÓRIO 187
-- AWS CloudTrail + Amazon Athena
-- =====================================================

-- 1. VISUALIZAR ESTRUTURA DA TABELA E DADOS BÁSICOS
-- Ver os primeiros 5 registros para entender o formato dos dados
SELECT *
FROM cloudtrail_logs_monitoring####
LIMIT 5;

-- 2. CONSULTA FOCADA EM AÇÕES DO EC2
-- Filtrar apenas eventos relacionados ao serviço EC2
SELECT 
    useridentity.userName, 
    eventtime, 
    eventsource, 
    eventname, 
    requestparameters
FROM cloudtrail_logs_monitoring####
WHERE eventsource = 'ec2.amazonaws.com'
LIMIT 50;

-- 3. BUSCAR AÇÕES RELACIONADAS A SEGURANÇA
-- Procurar eventos que contenham "Security" no nome
SELECT 
    useridentity.userName, 
    eventtime, 
    eventname, 
    sourceipaddress,
    requestparameters
FROM cloudtrail_logs_monitoring####
WHERE eventsource = 'ec2.amazonaws.com'
  AND eventname LIKE '%Security%'
ORDER BY eventtime DESC;

-- 4. IDENTIFICAR AÇÃO SUSPEITA DE ABERTURA DE PORTA SSH
-- Buscar especificamente a ação AuthorizeSecurityGroupIngress
SELECT 
    useridentity.userName,
    useridentity.type,
    useridentity.accessKeyId,
    eventtime,
    eventname,
    sourceipaddress,
    requestparameters,
    responseelements
FROM cloudtrail_logs_monitoring####
WHERE eventname = 'AuthorizeSecurityGroupIngress';

-- 5. LISTAR TODOS OS USUÁRIOS ATIVOS NAS ÚLTIMAS 24 HORAS
-- Consulta recomendada no laboratório para identificar atividades recentes
SELECT DISTINCT 
    useridentity.userName, 
    eventName, 
    eventSource,
    COUNT(*) as total_actions
FROM cloudtrail_logs_monitoring####
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -1, now())
GROUP BY useridentity.userName, eventName, eventSource
ORDER BY eventSource, useridentity.userName;

-- 6. ANÁLISE DETALHADA DO HACKER (USUÁRIO "chaos")
-- Todas as ações executadas pelo usuário chaos
SELECT 
    eventtime,
    eventname,
    eventsource,
    sourceipaddress,
    useragent,
    requestparameters
FROM cloudtrail_logs_monitoring####
WHERE useridentity.userName = 'chaos'
ORDER BY eventtime;

-- 7. VERIFICAR ACESSOS PROGRAMÁTICOS VS CONSOLE
-- Identificar como o hacker executou as ações
SELECT 
    useridentity.userName,
    eventname,
    useridentity.type,
    useragent,
    sourceipaddress,
    COUNT(*) as count
FROM cloudtrail_logs_monitoring####
WHERE useridentity.userName = 'chaos'
GROUP BY useridentity.userName, eventname, useridentity.type, useragent, sourceipaddress;

-- 8. LINHA DO TEMPO DO ATAQUE
-- Sequência completa de eventos do ataque
SELECT 
    eventtime,
    eventname,
    sourceipaddress,
    useragent
FROM cloudtrail_logs_monitoring####
WHERE useridentity.userName = 'chaos'
   OR eventname = 'AuthorizeSecurityGroupIngress'
ORDER BY eventtime;

-- 9. IDENTIFICAR MUDANÇAS NO GRUPO DE SEGURANÇA ESPECÍFICO
-- Substitua 'sg-xxxxxxxxxx' pelo ID real do grupo de segurança
SELECT 
    useridentity.userName,
    eventtime,
    eventname,
    requestparameters
FROM cloudtrail_logs_monitoring####
WHERE requestparameters LIKE '%sg-xxxxxxxxxx%'
  AND (eventname = 'AuthorizeSecurityGroupIngress' 
       OR eventname = 'RevokeSecurityGroupIngress'
       OR eventname = 'CreateSecurityGroup'
       OR eventname = 'DeleteSecurityGroup')
ORDER BY eventtime;

-- 10. RELATÓRIO FINAL DO HACKER
-- Informações consolidadas para relatório de incidente
SELECT 
    useridentity.userName AS "Nome do Usuário",
    eventtime AS "Data/Hora",
    sourceipaddress AS "IP de Origem",
    eventname AS "Ação",
    CASE 
        WHEN useragent LIKE '%console%' THEN 'Console AWS'
        WHEN useragent LIKE '%aws-cli%' THEN 'AWS CLI'
        WHEN useragent LIKE '%botocore%' THEN 'AWS SDK (Python)'
        ELSE 'Outro'
    END AS "Método de Acesso",
    requestparameters AS "Parâmetros da Requisição"
FROM cloudtrail_logs_monitoring####
WHERE useridentity.userName = 'chaos'
   OR eventname = 'AuthorizeSecurityGroupIngress'
ORDER BY eventtime;

📄 Arquivo: scripts/grep_analysis.sh
bash

#!/bin/bash
# =====================================================
# SCRIPT PARA ANÁLISE DE LOGS DO CLOUDTRAIL COM GREP
# LABORATÓRIO 187 - AWS CloudTrail Investigation
# =====================================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   ANÁLISE DE LOGS DO CLOUDTRAIL        ${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Verificar se está no diretório correto
if [ ! -d "ctraillogs" ]; then
    echo -e "${RED}[ERRO] Diretório 'ctraillogs' não encontrado.${NC}"
    echo -e "${YELLOW}Execute primeiro: mkdir ctraillogs && cd ctraillogs${NC}"
    exit 1
fi

cd ctraillogs

# Verificar se existem arquivos de log
if [ -z "$(ls -A 2>/dev/null)" ]; then
    echo -e "${RED}[ERRO] Nenhum arquivo de log encontrado.${NC}"
    echo -e "${YELLOW}Execute: aws s3 cp s3://monitoring####/ . --recursive${NC}"
    exit 1
fi

echo -e "${GREEN}[1] Extraindo arquivos .gz...${NC}"
gunzip -f *.gz 2>/dev/null
echo -e "${GREEN}OK${NC}\n"

echo -e "${GREEN}[2] Listando arquivos disponíveis:${NC}"
ls -la *.json 2>/dev/null | head -10
echo ""

# Função para contar total de eventos
total_events=$(cat *.json 2>/dev/null | python -m json.tool 2>/dev/null | grep -c "eventVersion" || echo "0")
echo -e "${GREEN}[3] Total de eventos encontrados: ${YELLOW}$total_events${NC}\n"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}        ANÁLISE DE EVENTOS             ${NC}"
echo -e "${BLUE}========================================${NC}\n"

# 1. Ver todos os sourceIPAddress
echo -e "${YELLOW}[4] Analisando sourceIPAddress em todos os logs:${NC}"
for i in $(ls *.json 2>/dev/null); do
    echo -e "${GREEN}Arquivo: $i${NC}"
    cat $i | python -m json.tool 2>/dev/null | grep sourceIPAddress | head -5
    echo ""
done

# 2. Ver todos os eventName
echo -e "${YELLOW}[5] Listando todos os eventName encontrados:${NC}"
for i in $(ls *.json 2>/dev/null); do
    echo -e "${GREEN}Arquivo: $i${NC}"
    cat $i | python -m json.tool 2>/dev/null | grep eventName | sort | uniq
    echo ""
done

# 3. Buscar eventos relacionados a SecurityGroup
echo -e "${YELLOW}[6] Buscando eventos relacionados a Security Group:${NC}"
for i in $(ls *.json 2>/dev/null); do
    cat $i | python -m json.tool 2>/dev/null | grep -A5 -B5 "SecurityGroup" | grep -E "eventName|userName|sourceIPAddress|eventTime" | head -20
    echo ""
done

# 4. Buscar ações de autorização (AuthorizeSecurityGroupIngress)
echo -e "${YELLOW}[7] Buscando ação AuthorizeSecurityGroupIngress (abertura de porta):${NC}"
for i in $(ls *.json 2>/dev/null); do
    result=$(cat $i | python -m json.tool 2>/dev/null | grep -A20 "AuthorizeSecurityGroupIngress")
    if [ ! -z "$result" ]; then
        echo -e "${RED}>>> ENCONTRADO EM: $i${NC}"
        echo "$result" | grep -E "eventName|userName|sourceIPAddress|eventTime|requestParameters" | head -10
        echo ""
    fi
done

# 5. Extrair informações do usuário chaos
echo -e "${YELLOW}[8] Buscando atividades do usuário 'chaos':${NC}"
for i in $(ls *.json 2>/dev/null); do
    result=$(cat $i | python -m json.tool 2>/dev/null | grep -A30 '"userName": "chaos"')
    if [ ! -z "$result" ]; then
        echo -e "${RED}>>> ATIVIDADE DO CHAOS ENCONTRADA EM: $i${NC}"
        echo "$result" | grep -E "eventName|userName|sourceIPAddress|eventTime|userAgent" | head -10
        echo ""
    fi
done

# 6. Relatório final consolidado
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}        RELATÓRIO CONSOLIDADO          ${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${GREEN}▶ ARQUIVOS ANALISADOS:${NC}"
ls -la *.json 2>/dev/null | wc -l
echo ""

echo -e "${GREEN}▶ EVENTOS POR TIPO:${NC}"
for i in $(ls *.json 2>/dev/null); do
    cat $i | python -m json.tool 2>/dev/null | grep '"eventName"' | cut -d '"' -f4 | sort | uniq -c | sort -rn
done | head -20

echo -e "\n${GREEN}▶ USUÁRIOS IDENTIFICADOS:${NC}"
for i in $(ls *.json 2>/dev/null); do
    cat $i | python -m json.tool 2>/dev/null | grep '"userName"' | cut -d '"' -f4 | sort | uniq
done | sort | uniq

echo -e "\n${GREEN}▶ IPs DE ORIGEM:${NC}"
for i in $(ls *.json 2>/dev/null); do
    cat $i | python -m json.tool 2>/dev/null | grep '"sourceIPAddress"' | cut -d '"' -f4 | sort | uniq
done | sort | uniq | head -10

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}        FIM DA ANÁLISE                ${NC}"
echo -e "${BLUE}========================================${NC}\n"

📄 Arquivo: results/hacker_info.txt
txt

========================================
RELATÓRIO DE INCIDENTE DE SEGURANÇA
Laboratório 187 - AWS CloudTrail Investigation
Data do incidente: [INSERIR DATA DO LAB]
========================================

1. IDENTIFICAÇÃO DO HACKER
--------------------------
Nome do usuário IAM: chaos
Tipo de usuário: IAM User
Método de acesso: Programático (AWS CLI / SDK)

2. AÇÃO MALICIOSA EXECUTADA
---------------------------
Event Name: AuthorizeSecurityGroupIngress
Descrição: Adicionou regra de entrada no grupo de segurança
Recurso afetado: WebSecurityGroup (grupo de segurança do Café Web Server)
Configuração adicionada: 
  - Protocolo: TCP
  - Porta: 22 (SSH)
  - Origem: 0.0.0.0/0 (qualquer lugar da internet)

3. DETALHES DO ATAQUE
--------------------
Horário exato: [INSERIR HORÁRIO DO EVENTO NO LOG]
IP de origem: [INSERIR IP ENCONTRADO NO LOG]
User Agent: [INSERIR USER AGENT]
Access Key ID utilizada: [INSERIR ACCESS KEY ID]

4. EVIDÊNCIAS NO LOG
--------------------
Query SQL utilizada no Athena:
--------------------------------------------------------------
SELECT useridentity.userName, eventtime, eventname, 
       sourceipaddress, requestparameters
FROM cloudtrail_logs_monitoring####
WHERE eventname = 'AuthorizeSecurityGroupIngress'
--------------------------------------------------------------

Resultado encontrado:
--------------------------------------------------------------
| userName | eventTime | eventName | sourceIPAddress |
| chaos    | [TIME]    | AuthorizeSecurityGroupIngress | [IP_HACKER] |
--------------------------------------------------------------

5. AÇÕES CORRETIVAS APLICADAS
-----------------------------
✅ Removido usuário 'chaos' do IAM
✅ Removido usuário 'chaos' do sistema operacional (Linux)
✅ Removida regra SSH 0.0.0.0/0 do grupo de segurança
✅ Desabilitada autenticação por senha no SSH
✅ Restaurada imagem original do site (Coffee-and-Pastries.jpg)
✅ Bloqueado processo ativo do hacker (kill -9)

6. RECOMENDAÇÕES DE SEGURANÇA
-----------------------------
- Habilitar MFA para todos os usuários IAM
- Usar AWS Config para monitorar mudanças em grupos de segurança
- Configurar alertas no CloudWatch para eventos específicos
- Revisar periodicamente as permissões IAM (least privilege)
- Desabilitar chaves de acesso não utilizadas
- Habilitar AWS GuardDuty para detecção de ameaças

========================================
Documentado por: amelia viana 
Data: 04/2026
========================================

📄 Instruções para usar os arquivos
1. Estrutura final do repositório
bash

📂 aws-cloudtrail-investigation-lab/
├── README.md
├── queries/
│   └── hacker_identification.sql
├── scripts/
│   └── grep_analysis.sh
└── results/
    └── hacker_info.txt

2. Como executar o script de análise com grep
bash

# Dar permissão de execução
chmod +x scripts/grep_analysis.sh

# Executar (dentro da instância EC2, no diretório onde estão os logs)
./scripts/grep_analysis.sh

3. Como usar as queries do Athena

    Copie o conteúdo de queries/hacker_identification.sql

    Substitua #### pelo número do seu bucket (ex: monitoring1234)

    Cole no console do Athena e execute uma por vez

    Substitua sg-xxxxxxxxxx pelo ID real do seu grupo de segurança

4. Preenchendo o relatório

    Abra results/hacker_info.txt

    Substitua [INSERIR ...] pelos valores reais encontrados durante o laboratório

    Adicione seu nome e data


🧠 Conceitos aplicados

    CloudTrail: auditoria de ações na AWS

    Amazon Athena: consultas SQL em logs no S3

    AWS CLI: busca programática por eventos

    Grupos de segurança: controle de tráfego de rede

    Hardening de SSH: desabilitar autenticação por senha

    Resposta a incidentes: remoção de usuário e reversão de alterações

📚 Referências úteis

    Documentação do AWS CloudTrail

    Consultando logs do CloudTrail com Athena

    Boas práticas para grupos de segurança EC2

🧑‍💻 Autor
Laboratório original da AWS Academy.
Este README foi preparado para fins de documentação e portfólio no GitHub.

📝 Licença
Este conteúdo é apenas para fins educacionais. AWS e CloudTrail são marcas registradas da Amazon Web Services, Inc.
text
