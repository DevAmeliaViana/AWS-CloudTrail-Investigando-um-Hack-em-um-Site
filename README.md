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
