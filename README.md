# AWS-CloudTrail-Investigando-um-Hack-em-um-Site

Este repositório documenta minha conclusão do **Laboratório AWS 187** - um cenário realístico de resposta a incidentes onde um site de cafeteria foi hackeado. O objetivo foi investigar, identificar o invasor e remediar todas as vulnerabilidades exploradas.

## 🎯 Objetivos Alcançados

- ✅ Configurar trilha do AWS CloudTrail para auditoria
- ✅ Analisar logs JSON brutos com ferramentas Linux
- ✅ Identificar o hacker via IP de origem e eventos da AWS
- ✅ Remover usuários maliciosos do sistema (IAM e SO)
- ✅ Corrigir configurações inseguras de SSH
- ✅ Restaurar aplicação web comprometida
- ✅ Utilizar Amazon Athena para consultas SQL em logs

---

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

## ✅ Pré-requisitos

- Conta AWS com permissões para criar recursos (CloudTrail, S3, EC2, Athena, IAM)
- Acesso SSH à instância EC2 (via PuTTY no Windows ou terminal no macOS/Linux)

---
## 📝 PASSO A PASSO COMPLETO DO LABORATÓRIO

### Tarefa 1: Modificando um grupo de segurança e observando o site

**1.1 Acessar o Console AWS e navegar para EC2**
```bash
Services → Compute → EC2
```

**1.2 Localizar a instância Café Web Server**
- Escolha **Instances**
- Localize e selecione **Café Web Server (WebSecurityGroup)**

**1.3 Verificar regras de segurança existentes**
- Clique na guia **Security**
- Observe o grupo de segurança **sg-xxxxxxxxxx**
- Na guia **Inbound rules**, note que apenas HTTP (porta 80) está liberado

**1.4 Adicionar regra SSH para seu IP**
```bash
# Clique em Edit inbound rules
# Add rule com as configurações:
Type: SSH
Port Range: 22
Source: My IP  # (seu IP específico com /32)
# Save rules
```

**1.5 Verificar o site normal**
```bash
# Copie o Public IPv4 address da instância
# No navegador, acesse:
http://<WebServerIP>/cafe/
# O site deve aparecer normal (fotos de cafeteria)
```

---

### Tarefa 2: Criando um log do CloudTrail e observando o site hackeado

**2.1 Criar trilha do CloudTrail**
```bash
Services → Management & Governance → CloudTrail
# No menu esquerdo: Trails
# Clique em Create trail
```

**Configurações da trilha:**
| Campo | Valor |
|-------|-------|
| Trail name | `monitor` |
| Storage location | Create a new S3 bucket |
| Trail log bucket | `monitoring####` (4 dígitos aleatórios) |
| AWS KMS alias | `iniciais-KMS` (ex: kc-KMS) |

```bash
# Clique em Next (2x) e Create trail
```

**2.2 Observar o site hackeado**
```bash
# Volte ao navegador com o site do Café
# Pressione Shift + F5 (refresh forçado)
# Aguarde 1-2 minutos
# O site agora mostra imagem hackeada!
```

**2.3 Verificar a brecha de segurança**
```bash
# No Console EC2, vá em Security Groups
# Selecione o grupo de segurança da instância
# Inbound rules - observe a nova regra:
Type: SSH, Source: 0.0.0.0/0  # ALERTA! Porta aberta para o mundo!
```

---

### Tarefa 3: Analisando os logs do CloudTrail usando grep

**3.1 Conectar à instância via SSH**

*Para macOS/Linux:*
```bash
cd ~/Downloads
chmod 400 labsuser.pem
ssh -i labsuser.pem ec2-user@<public-ip>
```

*Para Windows (PuTTY):*
- Use o arquivo labsuser.ppk
- Host: <public-ip>
- Port: 22

**3.2 Baixar e extrair os logs**
```bash
# Criar diretório para logs
mkdir ctraillogs
cd ctraillogs

# Listar buckets S3
aws s3 ls
# Saída esperada:
# 2026-04-05 15:09:31 cafeimagefiles74733
# 2026-04-05 15:14:38 monitoring-4920

# Baixar logs do CloudTrail
aws s3 cp s3://monitoring-4920/ . --recursive

# Navegar até os logs
cd /home/ec2-user/ctraillogs/AWSLogs/429022785342/CloudTrail/

# Descompactar todos os arquivos .gz
find . -name "*.gz" -type f -exec gunzip {} \;

# Verificar arquivos JSON extraídos
find . -name "*.json" -type f
```

**3.3 Analisar a estrutura dos logs**
```bash
# Ver um arquivo de log (sem formatação)
cat ./us-west-2/2026/04/05/*.json | head -50

# Ver com formatação JSON legível
cat ./us-west-2/2026/04/05/*.json | python -m json.tool | head -100
```

**3.4 Identificar IPs de origem**
```bash
# Loop para extrair todos os sourceIPAddress
for i in $(find . -name "*.json" -type f); do 
    echo "=== $i ===" 
    cat $i | python -m json.tool | grep sourceIPAddress 
done
```

**Saída esperada (mostrando IP suspeito):**
```json
"sourceIPAddress": "191.241.157.79",  ← IP do hacker!
"sourceIPAddress": "54.218.74.146",   ← IP do servidor web
```

**3.5 Encontrar eventos de Security Group**
```bash
# Buscar atividades relacionadas a security groups
for i in $(find . -name "*.json" -type f); do 
    if cat $i | grep -q "SecurityGroup"; then
        echo "=== ATIVIDADE EM: $i ==="
        cat $i | python -m json.tool | grep -E "(eventName|sourceIPAddress|userName)" | head -20
    fi
done
```

**3.6 Extrair o evento de hack específico**
```bash
# Visualizar o AuthorizeSecurityGroupIngress completo
cat ./us-west-2/2026/04/05/*B5VHzom21nKE4z9u.json | python -m json.tool | grep -A 30 "AuthorizeSecurityGroupIngress"
```

**Resultado encontrado:**
```json
{
    "eventName": "AuthorizeSecurityGroupIngress",
    "eventTime": "2026-04-05T15:15:47Z",
    "sourceIPAddress": "191.241.157.79",
    "requestParameters": {
        "ipPermissions": {
            "items": [{
                "fromPort": 22,
                "ipProtocol": "tcp",
                "ipRanges": {
                    "items": [{"cidrIp": "0.0.0.0/0"}]
                },
                "toPort": 22
            }]
        }
    }
}
```

---

### Tarefa 4: Analisando os logs do CloudTrail usando o Amazon Athena

**4.1 Criar tabela no Athena**
```bash
Services → CloudTrail → Event history
# Clique em "Create Athena table"
# Storage location: selecione s3://monitoring-4920/
# Clique em "Create table"
```

**4.2 Configurar local dos resultados**
```bash
Services → Analytics → Athena
# Settings → Manage
# Location of query result: s3://monitoring-4920/results/
# Save
```

**4.3 Consultas SQL para investigação**

```sql
-- Consulta 1: Verificar estrutura da tabela
SELECT * 
FROM cloudtrail_logs_monitoring_4920 
LIMIT 5;

-- Consulta 2: Listar todos os usuários ativos
SELECT DISTINCT useridentity.username 
FROM cloudtrail_logs_monitoring_4920;

-- Consulta 3: Buscar eventos de security group
SELECT useridentity.username, eventtime, eventname, sourceipaddress
FROM cloudtrail_logs_monitoring_4920
WHERE eventname LIKE '%SecurityGroup%'
ORDER BY eventtime DESC;

-- Consulta 4: Localizar o hack (CRÍTICA)
SELECT useridentity.username, eventtime, sourceipaddress, requestparameters
FROM cloudtrail_logs_monitoring_4920
WHERE eventname = 'AuthorizeSecurityGroupIngress';

-- Consulta 5: Ver atividades do IP suspeito
SELECT eventname, eventtime, useridentity.username
FROM cloudtrail_logs_monitoring_4920
WHERE sourceipaddress = '191.241.157.79'
ORDER BY eventtime;

-- Consulta 6: Resumo do último dia
SELECT DISTINCT useridentity.userName, eventName, eventSource 
FROM cloudtrail_logs_monitoring_4920 
WHERE from_iso8601_timestamp(eventtime) > date_add('day', -1, now()) 
ORDER BY eventSource;
```

**4.4 Resultados do desafio**
```sql
-- Identificar o hacker
SELECT useridentity.username, eventtime, sourceipaddress, useragent
FROM cloudtrail_logs_monitoring_4920
WHERE eventname = 'AuthorizeSecurityGroupIngress';
```

| Informação | Valor |
|------------|-------|
| Nome do usuário | `voclabs` |
| Hora do ataque | `2026-04-05T15:15:47Z` |
| IP de origem | `191.241.157.79` |
| Método | Programático (AWS CLI) |

---

### Tarefa 5: Analisando o hack mais a fundo e melhorando a segurança

**5.1 Verificar usuários do sistema operacional**
```bash
# Ver quem está logado
who

# Ver histórico de autenticação
sudo aureport --auth

# Listar todos os usuários com shell
cat /etc/passwd | grep -v nologin

# Verificar se chaos-user existe
id chaos-user
```

**Saída esperada:**
```
uid=1001(chaos-user) gid=1001(chaos-user) grupos=1001(chaos-user)
CHAOS USER EXISTE
```

**5.2 Remover o usuário chaos-user**
```bash
# Tentar remover (pode falhar se estiver logado)
sudo userdel -r chaos-user

# Se falhar, encontrar o processo e matar
ps aux | grep chaos-user
sudo kill -9 <PID>

# Tentar remover novamente
sudo userdel -r chaos-user

# Verificar remoção
id chaos-user
# Saída: id: ‘chaos-user’: no such user
```

**5.3 Corrigir configuração do SSH**

```bash
# Verificar configuração atual
sudo grep PasswordAuthentication /etc/ssh/sshd_config
# Saída: PasswordAuthentication yes  ← PROBLEMA!

# Fazer backup
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Editar configuração
sudo vi /etc/ssh/sshd_config
```

**Dentro do VI:**
```bash
:set number              # Mostrar números das linhas
# Navegar até linha 61 (PasswordAuthentication yes)
# Pressionar 'a' para editar
# Adicionar '#' no início da linha → #PasswordAuthentication yes
# Navegar até linha 63 (#PasswordAuthentication no)
# Remover o '#' → PasswordAuthentication no
# Pressionar Esc
:wq                      # Salvar e sair
```

```bash
# Reiniciar serviço SSH
sudo service sshd restart

# Verificar alteração
sudo grep PasswordAuthentication /etc/ssh/sshd_config
# Saída esperada: PasswordAuthentication no
```

**5.4 Restaurar a imagem do site**

```bash
# Navegar para diretório das imagens
cd /var/www/html/cafe/images/

# Listar arquivos
ls -la Coffee-and-Pastries*

# Saída esperada:
# -rwxrwxrwx 1 chaos-user root 486325 Coffee-and-Pastries.backup
# -rw-r--r-- 1 chaos-user root 260603 Coffee-and-Pastries.jpg (hackeada)

# Restaurar backup
sudo mv Coffee-and-Pastries.backup Coffee-and-Pastries.jpg

# Corrigir permissões
sudo chown apache:apache Coffee-and-Pastries.jpg
sudo chmod 644 Coffee-and-Pastries.jpg

# Verificar restauração
ls -la Coffee-and-Pastries.jpg
file Coffee-and-Pastries.jpg
```

**5.5 Corrigir Security Group no Console AWS**

```bash
# No Console AWS:
Services → EC2 → Security Groups
# Selecione o grupo de segurança da instância
# Inbound rules → Edit inbound rules
```

**Regras finais (CORRETAS):**
| Type | Port | Source |
|------|------|--------|
| HTTP | 80 | 0.0.0.0/0 |
| SSH | 22 | SEU_IP/32 (NÃO 0.0.0.0/0!) |

```bash
# DELETE a regra maliciosa:
Type: SSH, Source: 0.0.0.0/0  # ← REMOVER!

# Save rules
```

**5.6 Remover usuário IAM hacker**
```bash
# No Console AWS:
Services → IAM → Users
# Localize o usuário 'chaos' ou 'voclabs'
# Selecione → Delete
# Confirme o nome → Delete
```

**5.7 Verificar site restaurado**

```bash
# Testar localmente
curl -I http://localhost/cafe/
# HTTP/1.1 200 OK

# No navegador, acesse:
http://54.218.74.146/cafe/
# Pressione Ctrl+Shift+R (refresh forçado)
# A imagem deve estar NORMAL (cafeteria, não imagem hackeada)
```

**5.8 Validar segurança do SSH**

```bash
# Tentar conectar de outro terminal (deve falhar)
ssh -i labsuser.pem ec2-user@54.218.74.146
# Saída: ssh: connect to host 54.218.74.146 port 22: Connection refused

# Isso é BOM! Significa que o SSH está seguro!
```

---

## 📊 EVIDÊNCIAS DO INVASOR

| Informação | Valor |
|------------|-------|
| **IP de origem** | `191.241.157.79` |
| **Usuário IAM** | `voclabs` |
| **Usuário Linux** | `chaos-user` (UID 1001) |
| **Ação maliciosa** | `AuthorizeSecurityGroupIngress` |
| **Horário do ataque** | `2026-04-05T15:15:47Z` |
| **Regra adicionada** | SSH (tcp/22) para `0.0.0.0/0` |
| **Método de acesso** | Programático (AWS CLI) |
| **Arquivo do log** | `*B5VHzom21nKE4z9u.json` |

---

## 🛠️ COMANDOS ÚTEIS PARA RESPOSTA A INCIDENTES

### Análise de Logs
```bash
# Buscar eventos específicos em múltiplos arquivos
grep -r "AuthorizeSecurityGroupIngress" .

# Extrair todos os IPs de origem
find . -name "*.json" -exec grep -h "sourceIPAddress" {} \; | sort | uniq

# Formatar JSON para leitura
cat log.json | python -m json.tool | less

# Buscar por usuário específico
grep -r '"userName": "chaos"' .

# Contar ocorrências por evento
grep -r '"eventName"' . | cut -d'"' -f4 | sort | uniq -c | sort -rn

# Extrair timestamps de eventos suspeitos
grep -r '"eventTime"' . | grep "15:15"
```

### Segurança do Sistema
```bash
# Verificar todos os usuários com shell
cat /etc/passwd | grep -E "/(bash|sh)$" | cut -d: -f1

# Verificar configuração SSH
sudo sshd -T | grep -E "passwordauthentication|permitrootlogin"

# Verificar portas abertas
sudo netstat -tlnp | grep :22

# Verificar processos suspeitos
ps aux | grep -v "^root\|ec2-user" | grep -v "\["
```

### AWS CLI para Investigação
```bash
# Buscar eventos no CloudTrail via CLI
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress

# Descrever security groups
aws ec2 describe-security-groups --group-ids <sg-id>

# Verificar instâncias
aws ec2 describe-instances --filters "Name=tag:Name,Values='Cafe Web Server'"
```

---

## 📁 ESTRUTURA DOS LOGS ANALISADOS

```
AWSLogs/
└── 429022785342/
    └── CloudTrail/
        ├── us-east-1/
        │   └── 2026/04/05/
        │       ├── 429022785342_CloudTrail_us-east-1_20260405T1520Z_OeMXIlUAtN4VWPTN.json
        │       └── 429022785342_CloudTrail_us-east-1_20260405T1520Z_7wsxNlLD8X5dCRRS.json
        └── us-west-2/
            └── 2026/04/05/
                ├── 429022785342_CloudTrail_us-west-2_20260405T1515Z_KBJr9glEK7U0mulB.json
                └── 429022785342_CloudTrail_us-west-2_20260405T1520Z_B5VHzom21nKE4z9u.json  ← Evento do hacker!
```

---

## 📈 IMPACTO DAS MEDIDAS DE SEGURANÇA

| Métrica | Antes | Depois |
|---------|-------|--------|
| **Superfície de ataque SSH** | 🌍 Global (0.0.0.0/0) | 🏠 Apenas IP autorizado |
| **Autenticação SSH** | 🔑 Senha + Chave | 🔐 Apenas chave |
| **Usuários com acesso** | 3 (root, ec2-user, chaos-user) | 2 (root, ec2-user) |
| **Integridade do site** | ❌ Comprometida | ✅ Restaurada |
| **Arquivo de imagem** | 260KB (hackeado) | 486KB (original) |

---

## 🎓 PRINCIPAIS APRENDIZADOS

1. **CloudTrail é fundamental** - Sem logs, não há como investigar incidentes
2. **Logs estruturados salvam vidas** - JSON + Athena = investigação eficiente
3. **Nunca abra SSH para 0.0.0.0/0** - Use grupos de segurança restritivos
4. **PasswordAuthentication no** - Sempre use chaves SSH
5. **Auditoria contínua** - Monitore eventos como `AuthorizeSecurityGroupIngress`
6. **Princípio do menor privilégio** - Limite permissões IAM rigorosamente
7. **Documentação do incidente** - Registre cada passo da investigação
8. **Backups são essenciais** - O arquivo `.backup` salvou o site!

---

## 🛠️ TECNOLOGIAS UTILIZADAS

| Serviço/Ferramenta | Finalidade |
|-------------------|------------|
| **AWS CloudTrail** | Auditoria de ações da conta |
| **Amazon Athena** | Consultas SQL em logs |
| **Amazon EC2** | Servidor web comprometido |
| **AWS IAM** | Gerenciamento de usuários |
| **Amazon S3** | Armazenamento de logs |
| **Linux CLI** | Análise de logs (grep, sed, awk) |
| **Python** | Formatação JSON (`json.tool`) |
| **SSH** | Acesso remoto seguro |
| **VI Editor** | Edição de configurações |

---

## ✅ LISTA DE VERIFICAÇÃO FINAL

| Tarefa | Status | Comando de Verificação |
|--------|--------|----------------------|
| Tarefa 1 | ✅ | Regra SSH adicionada com My IP |
| Tarefa 2 | ✅ | CloudTrail "monitor" criado |
| Tarefa 3 | ✅ | Logs baixados e analisados |
| Tarefa 4 | ✅ | Hacker identificado via Athena |
| Tarefa 5.1 | ✅ | `id chaos-user` → no such user |
| Tarefa 5.2 | ✅ | `grep PasswordAuthentication` → no |
| Tarefa 5.3 | ✅ | `curl -I` → HTTP 200 |
| Tarefa 5.4 | ✅ | Security group sem 0.0.0.0/0 para SSH |

---

## 🏁 CONCLUSÃO

O laboratório demonstrou a importância de:
- **Proatividade** na configuração de auditoria (CloudTrail)
- **Capacidade de investigação** com ferramentas apropriadas
- **Resposta rápida** a incidentes de segurança
- **Documentação** de todo o processo forense

A combinação de AWS CloudTrail + Amazon Athena + análise manual em Linux CLI provou ser extremamente eficaz para identificar e responder a um ataque realístico.

---

## 📚 REFERÊNCIAS

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [Amazon Athena Documentation](https://docs.aws.amazon.com/athena/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [EC2 Security Groups Guide](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)

---

## 📝 NOTAS FINAIS

**Status:** ✅ Laboratório Concluído com Sucesso  
**Data:** 2026-04-05  
**Duração:** ~75 minutos  
**Nível:** Intermediário  
**Ambiente:** Amazon Linux 2

---

*"Security is not a product, it's a process." - Bruce Schneier*

🔐 **Mantenha-se seguro na nuvem!**

---

## 📂 ARQUIVOS CRIADOS DURANTE O LAB

```bash
/home/ec2-user/ctraillogs/                          # Logs do CloudTrail
/home/ec2-user/respostas_desafio.txt                # Respostas do desafio
/etc/ssh/sshd_config.backup.20260405                # Backup SSH
/var/log/security_investigation.log                 # Relatório de segurança
/var/log/lab187-conclusao.txt                       # Conclusão do lab
```

---

**🔗 Este repositório serve como documentação para fins educacionais e de treinamento em segurança AWS.**
```

## 🧑‍💻 Autora

**Amelia Viana**  
Laboratório original da AWS Academy.  
Este README foi preparado para fins de documentação e portfólio no GitHub.

---

## 📝 Licença

Este conteúdo é apenas para fins educacionais. AWS e CloudTrail são marcas registradas da Amazon Web Services, Inc.
