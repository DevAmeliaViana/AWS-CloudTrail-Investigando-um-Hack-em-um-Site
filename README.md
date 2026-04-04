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

### 🎯 Objetivos

- Criar e configurar uma trilha no AWS CloudTrail
- Analisar logs do CloudTrail usando `grep`, AWS CLI e Amazon Athena
- Identificar ações suspeitas em grupos de segurança EC2
- Remover acesso de usuários maliciosos (SO e IAM)
- Corrigir configurações de segurança (SSH) e restaurar o site

### ⏱️ Duração estimada

75 minutos

---

## ✅ Pré-requisitos

- Conta AWS com permissões para criar recursos (CloudTrail, S3, EC2, Athena, IAM)
- Acesso SSH à instância EC2 (via PuTTY no Windows ou terminal no macOS/Linux)

---

## 🧪 Passo a Passo do Laboratório

### 🔹 Tarefa 1 – Configuração inicial e observação do site

1. Acesse o console EC2 e localize a instância **Café Web Server**.
2. No grupo de segurança associado, adicione uma regra de entrada para **SSH (porta 22)** restrita ao seu IP (`Meu IP`).
3. Acesse o site via navegador:  
   `http://<IP_PUBLICO_DA_INSTANCIA>/cafe/`  
   O site aparece normal.

### 🔹 Tarefa 2 – Criar trilha no CloudTrail e detectar o hack

1. No serviço **CloudTrail**, crie uma trilha chamada `monitor`.
2. Crie um bucket S3 novo com nome `monitoring####` (#### = 4 dígitos aleatórios).
3. Após alguns minutos, atualize o site → ele foi hackeado (imagem alterada).
4. No grupo de segurança, uma nova regra SSH `0.0.0.0/0` aparece (brecha criada pelo hacker).

### 🔹 Tarefa 3 – Análise com `grep` e AWS CLI

#### Conectar via SSH à instância EC2

```bash
ssh -i labsuser.pem ec2-user@<IP_PUBLICO>
```

#### Baixar e extrair logs do CloudTrail

```bash
mkdir ctraillogs && cd ctraillogs
aws s3 ls
aws s3 cp s3://monitoring####/ . --recursive
gunzip *.gz
```

#### Usar `grep` para inspecionar logs

```bash
# Ver sourceIPAddress
for i in $(ls); do echo $i && cat $i | python -m json.tool | grep sourceIPAddress; done

# Ver eventName
for i in $(ls); do echo $i && cat $i | python -m json.tool | grep eventName; done
```

#### Usar AWS CLI para lookup events

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin

# Buscar ações em grupos de segurança
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::SecurityGroup --output text

# Filtrar pelo ID do grupo de segurança
region=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | cut -d '"' -f4)
sgId=$(aws ec2 describe-instances --filters "Name=tag:Name,Values='Cafe Web Server'" --query 'Reservations[*].Instances[*].SecurityGroups[*].[GroupId]' --region $region --output text)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::EC2::SecurityGroup --region $region --output text | grep $sgId
```

### 🔹 Tarefa 4 – Análise com Amazon Athena

1. No console do CloudTrail, vá em **Event history** → **Create Athena table**.
2. Escolha o bucket S3 `monitoring####` e crie a tabela.
3. No Athena Query Editor, configure o local de resultados:  
   `s3://monitoring####/results/`
4. Execute as consultas SQL para identificar o hacker.

#### Consulta inicial

```sql
SELECT useridentity.userName, eventtime, eventsource, eventname, requestparameters
FROM cloudtrail_logs_monitoring####
LIMIT 30;
```

#### Consulta para identificar o hacker

```sql
SELECT DISTINCT useridentity.userName, eventName, eventSource
FROM cloudtrail_logs_monitoring####
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -1, now())
ORDER BY eventSource;
```

### ✅ O que você deve encontrar

| Campo | Valor |
|-------|-------|
| Nome do usuário IAM | `chaos` |
| Ação | `AuthorizeSecurityGroupIngress` |
| Origem | Acesso programático (AWS CLI) |
| Porta aberta | 22 (SSH) para `0.0.0.0/0` |

### 🔹 Tarefa 5 – Correções e remediação

#### 5.1 Remover usuário malicioso do SO

```bash
sudo aureport --auth          # ver logins recentes
who                           # ver usuários logados
sudo userdel -r chaos-user    # remover usuário (falha se logado)
sudo kill -9 <PID>            # matar processo do chaos-user
sudo userdel -r chaos-user    # agora funciona
```

#### 5.2 Ajustar configuração SSH

```bash
sudo vi /etc/ssh/sshd_config
# Comentar: PasswordAuthentication yes
# Descomentar: PasswordAuthentication no
sudo service sshd restart
```

#### 5.3 Remover regra SSH aberta no grupo de segurança

- Console EC2 → Security Groups → editar regras de entrada
- Remover a regra `0.0.0.0/0` para porta 22

#### 5.4 Restaurar o site

```bash
cd /var/www/html/cafe/images/
sudo mv Coffee-and-Pastries.backup Coffee-and-Pastries.jpg
```

#### 5.5 Excluir usuário `chaos` do IAM

- Console IAM → Users → selecionar `chaos` → Delete

---

## 📊 Evidências coletadas (exemplo)

| Campo | Valor encontrado |
|-------|------------------|
| Nome do usuário IAM | chaos |
| Ação executada | AuthorizeSecurityGroupIngress |
| IP de origem | 203.0.113.45 (exemplo) |
| Método | Programático (AWS CLI) |
| Porta aberta | 22 (SSH) para 0.0.0.0/0 |

---

## 📁 Estrutura do Repositório

```bash
📂 aws-cloudtrail-investigation-lab/
├── README.md
├── queries/
│   └── hacker_identification.sql
├── scripts/
│   └── grep_analysis.sh
└── results/
    └── hacker_info.txt
```

---

## 📄 Arquivos Complementares

### `queries/hacker_identification.sql`

```sql
-- =====================================================
-- CONSULTAS PARA IDENTIFICAR O HACKER NO LABORATÓRIO 187
-- =====================================================

-- 1. VISUALIZAR ESTRUTURA DA TABELA
SELECT * FROM cloudtrail_logs_monitoring#### LIMIT 5;

-- 2. AÇÕES DO EC2
SELECT useridentity.userName, eventtime, eventname, requestparameters
FROM cloudtrail_logs_monitoring####
WHERE eventsource = 'ec2.amazonaws.com'
LIMIT 50;

-- 3. AÇÕES DE SEGURANÇA
SELECT useridentity.userName, eventtime, eventname, sourceipaddress
FROM cloudtrail_logs_monitoring####
WHERE eventname LIKE '%Security%'
ORDER BY eventtime DESC;

-- 4. IDENTIFICAR O HACK (AÇÃO SUSPEITA)
SELECT useridentity.userName, eventtime, sourceipaddress, requestparameters
FROM cloudtrail_logs_monitoring####
WHERE eventname = 'AuthorizeSecurityGroupIngress';

-- 5. USUÁRIOS ATIVOS NAS ÚLTIMAS 24H
SELECT DISTINCT useridentity.userName, eventName
FROM cloudtrail_logs_monitoring####
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -1, now());

-- 6. ANÁLISE DETALHADA DO USUÁRIO 'chaos'
SELECT eventtime, eventname, sourceipaddress, useragent
FROM cloudtrail_logs_monitoring####
WHERE useridentity.userName = 'chaos'
ORDER BY eventtime;
```

### `scripts/grep_analysis.sh`

```bash
#!/bin/bash
# Script para análise de logs do CloudTrail com grep

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== ANÁLISE DE LOGS DO CLOUDTRAIL ===${NC}\n"

cd ctraillogs 2>/dev/null || { echo -e "${RED}ERRO: Diretório ctraillogs não encontrado${NC}"; exit 1; }

echo -e "${GREEN}[1] Extraindo arquivos...${NC}"
gunzip -f *.gz 2>/dev/null

echo -e "${GREEN}[2] Buscando AuthorizeSecurityGroupIngress...${NC}"
for i in $(ls *.json 2>/dev/null); do
    result=$(cat $i | python -m json.tool 2>/dev/null | grep -A20 "AuthorizeSecurityGroupIngress")
    if [ ! -z "$result" ]; then
        echo -e "${RED}>>> ENCONTRADO EM: $i${NC}"
        echo "$result" | grep -E "userName|sourceIPAddress|eventTime"
    fi
done

echo -e "${GREEN}[3] Buscando atividades do usuário chaos...${NC}"
for i in $(ls *.json 2>/dev/null); do
    cat $i | python -m json.tool 2>/dev/null | grep -A30 '"userName": "chaos"'
done

echo -e "\n${BLUE}=== FIM DA ANÁLISE ===${NC}"
```

### `results/hacker_info.txt`

```text
========================================
RELATÓRIO DE INCIDENTE DE SEGURANÇA
Laboratório 187 - AWS CloudTrail Investigation
Data do incidente: [INSERIR DATA]
========================================

1. IDENTIFICAÇÃO DO HACKER
--------------------------
Nome do usuário IAM: chaos
Método de acesso: Programático (AWS CLI)

2. AÇÃO MALICIOSA
----------------
Event Name: AuthorizeSecurityGroupIngress
Porta: 22 (SSH)
Origem: 0.0.0.0/0

3. DETALHES DO ATAQUE
--------------------
Horário exato: [INSERIR HORÁRIO]
IP de origem: [INSERIR IP]
User Agent: [INSERIR USER AGENT]

4. AÇÕES CORRETIVAS
------------------
✅ Usuário chaos removido do IAM
✅ Usuário chaos removido do SO
✅ Regra SSH 0.0.0.0/0 removida
✅ Autenticação por senha desabilitada no SSH
✅ Site restaurado

========================================
Documentado por: amelia viana
Data: 04/2026
========================================
```

---

## 🧠 Conceitos aplicados

- **CloudTrail**: auditoria de ações na AWS
- **Amazon Athena**: consultas SQL em logs no S3
- **AWS CLI**: busca programática por eventos
- **Grupos de segurança**: controle de tráfego de rede
- **Hardening de SSH**: desabilitar autenticação por senha
- **Resposta a incidentes**: remoção de usuário e reversão de alterações

---

## 📚 Referências úteis

- [Documentação do AWS CloudTrail](https://docs.aws.amazon.com/cloudtrail/)
- [Consultando logs do CloudTrail com Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Boas práticas para grupos de segurança EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html)

---

## 🧑‍💻 Autora

**Amelia Viana**  
Laboratório original da AWS Academy.  
Este README foi preparado para fins de documentação e portfólio no GitHub.

---

## 📝 Licença

Este conteúdo é apenas para fins educacionais. AWS e CloudTrail são marcas registradas da Amazon Web Services, Inc.
