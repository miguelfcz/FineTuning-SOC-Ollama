import json
import os
import random

SYSTEM_PROMPT = (
    "Você é um Analista de Segurança Nível 3 (SOC L3 Incident Responder). "
    "Sua função é analisar logs brutos de telemetria e auditoria, identificar ameaças e responder estritamente no seguinte padrão:\n"
    "[SEVERIDADE]: <CRÍTICA | ALTA | MÉDIA | BAIXA | FALSO POSITIVO>\n"
    "[TÁTICA MITRE ATT&CK]: <Código e Nome da Técnica MITRE>\n"
    "[ANÁLISE TÉCNICA]: <Diagnóstico técnico objetivo do vetor de ataque ou atividade>\n"
    "[AÇÃO DE CONTENÇÃO]: <Comando técnico imediato de mitigação, firewall ou isolamento>"
)

# Base de incidentes curados com fidelidade técnica real
INCIDENT_TEMPLATES = [
    # 1. SQL Injection (Web Application)
    {
        "category": "sqli",
        "log": '192.168.1.105 - - [02/Nov/2026:10:14:22 -0300] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password_hash%20FROM%20users-- HTTP/1.1" 200 4521 "Mozilla/5.0" 203.0.113.45',
        "severity": "CRÍTICA",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "analysis": "Tentativa bem-sucedida de SQL Injection clássica baseada em UNION. O atacante injetou payload no parâmetro 'id' visando exfiltrar hashes de senhas e nomes de usuário da tabela 'users'. O código HTTP 200 e o payload de 4521 bytes indicam resposta positiva da aplicação.",
        "containment": "iptables -I INPUT -s 203.0.113.45 -j DROP && waf-ctl --rule-add block_sqli --param id"
    },
    {
        "category": "sqli",
        "log": '2026-11-02 14:20:11 W3SVC1 GET /api/v1/search query=\' OR 1=1; DROP TABLE audit_trail;-- 500 0 0 203.0.113.89 Mozilla/5.0',
        "severity": "CRÍTICA",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "analysis": "Tentativa destrutiva de SQL Injection com empilhamento de consultas (stacked queries) tentando deletar a tabela de auditoria 'audit_trail'. O servidor retornou status 500 (Internal Server Error), indicando que a query quebrou a sintaxe do backend.",
        "containment": "iptables -A INPUT -s 203.0.113.89 -j DROP"
    },
    {
        "category": "sqli",
        "log": '172.16.0.45 - - [02/Nov/2026:08:15:30] "POST /login.php HTTP/1.1" 302 512 "user=admin\'--&pass=dummy" 198.51.100.22',
        "severity": "CRÍTICA",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "analysis": "Bypass de autenticação bem-sucedido via SQL Injection no formulário de login. O comentário SQL ('--) anulou a validação de credencial, gerando redirecionamento 302 para o painel administrativo.",
        "containment": "iptables -I INPUT -s 198.51.100.22 -j DROP && pkill -u admin_session"
    },

    # 2. SSH Brute Force
    {
        "category": "ssh_bruteforce",
        "log": 'Nov  2 03:12:01 srv-prod sshd[28411]: Failed password for invalid user root from 185.220.101.5 port 44122 ssh2 (repetido 450 vezes em 2 minutos)',
        "severity": "ALTA",
        "mitre": "T1110.001 - Brute Force: Password Guessing",
        "analysis": "Ataque volumétrico de força bruta direcionado ao serviço SSH. Foram registradas centenas de tentativas sequenciais com dicionário de credenciais a partir de nó de saída Tor/proxy hostil contra a conta root.",
        "containment": "iptables -I INPUT -s 185.220.101.5 -p tcp --dport 22 -j DROP && fail2ban-client set sshd banip 185.220.101.5"
    },
    {
        "category": "ssh_bruteforce",
        "log": 'Nov  2 04:45:12 bastion-linux sshd[31002]: Failed password for ubuntu from 45.33.32.156 port 51230 ssh2\nNov  2 04:45:14 bastion-linux sshd[31005]: Accepted password for ubuntu from 45.33.32.156 port 51234 ssh2',
        "severity": "CRÍTICA",
        "mitre": "T1110.001 - Brute Force: Password Guessing",
        "analysis": "Força bruta SSH bem-sucedida. Após múltiplas falhas, o IP externo obteve êxito no login da conta de serviço 'ubuntu', comprometendo o host de borda.",
        "containment": "pkill -KILL -u ubuntu && iptables -I INPUT -s 45.33.32.156 -j DROP && usermod -L ubuntu"
    },
    {
        "category": "ssh_bruteforce",
        "log": 'Nov  2 02:18:44 gateway-dmz sshd[12450]: Disconnecting authenticating user admin 194.26.29.112 port 58900: Too many authentication failures [preauth]',
        "severity": "ALTA",
        "mitre": "T1110.001 - Brute Force: Password Guessing",
        "analysis": "Tentativas contínuas de autenticação automatizada em lote no daemon SSH, atingindo o limite de MaxAuthTries antes de handshake seguro.",
        "containment": "iptables -A INPUT -s 194.26.29.112 -j DROP"
    },

    # 3. Ransomware / Shadow Copies Deletion
    {
        "category": "ransomware",
        "log": 'EventID: 4688, ProcessName: C:\\Windows\\System32\\cmd.exe, CommandLine: "vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no", User: NT AUTHORITY\\SYSTEM',
        "severity": "CRÍTICA",
        "mitre": "T1490 - Inhibit System Recovery",
        "analysis": "Comportamento típico de pré-criptografia de ransomware. O processo executou o expurgo silencioso de cópias de sombra (Volume Shadow Copies) e desabilitou a recuperação de inicialização do Windows para impedir restauração do sistema.",
        "containment": "taskkill /F /IM cmd.exe & netsh advfirewall set allprofiles state off & Set-NetAdapter -Name * -Status Disabled"
    },
    {
        "category": "ransomware",
        "log": 'EventID: 4688, ProcessName: powershell.exe, CommandLine: "powershell -enc JAB3AG0AaQAgAD0AIABHAGUAdAAtAFcAbQBpAE8AYgBqAGUAYwB0ACAAVwBpAG4AMwAyAF8AUwBoAGEAZABvAHcAQwBvAHAAeQA7ACAAJAB3AG0AaQAuAEQAZQBsAGUAdABlACgAKQA=", ParentProcess: invoice_october.exe',
        "severity": "CRÍTICA",
        "mitre": "T1490 - Inhibit System Recovery",
        "analysis": "Invocação de PowerShell com comando codificado em Base64 gerado por binário não identificado (invoice_october.exe). O payload decodificado executa a deleção de todas as instâncias de Win32_ShadowCopy.",
        "containment": "Stop-Process -Name invoice_october -Force; Stop-Process -Name powershell -Force; Disconnect-NetAdapter -Name \"*\" -Confirm:$false"
    },
    {
        "category": "ransomware",
        "log": 'AuditD alert: type=SYSCALL arch=c000003e syscall=257 success=yes comm="locker" exe="/tmp/.crypto/locker" items=120000 files_renamed_with_extension=".locked"',
        "severity": "CRÍTICA",
        "mitre": "T1486 - Data Encrypted for Impact",
        "analysis": "Ransomware em execução ativa no ambiente Linux. O binário localizado em diretório temporário oculto (/tmp/.crypto) está renomeando massivamente arquivos para a extensão '.locked'.",
        "containment": "killall -9 locker && fuser -k /tmp/.crypto/locker && ip link set dev eth0 down"
    },

    # 4. DNS Exfiltration / Tunneling
    {
        "category": "dns_exfiltration",
        "log": 'named[1092]: client @0x7f884c0 10.0.4.150#54210: query: 7a666338316239303361.exfil.attacker-c2.xyz IN TXT + (10.0.0.2) (taxa de 280 queries/minuto com subdomínios pseudo-aleatórios)',
        "severity": "ALTA",
        "mitre": "T1071.004 - Application Layer Protocol: DNS",
        "analysis": "Exfiltração de dados por DNS Tunneling. O host infectado está codificando informações sigilosas em chunks hexadecimais em labels de subdomínios, realizando centenas de requisições TXT a um domínio C2 dinâmico.",
        "containment": "iptables -I FORWARD -s 10.0.4.150 -j DROP && pihole -b attacker-c2.xyz || unbound-control flush_zone attacker-c2.xyz"
    },
    {
        "category": "dns_exfiltration",
        "log": 'Suricata Alert [1:2024101:1] PROTOCOL-DNS high entropy TXT query detected from internal host 192.168.10.88 to external DNS 198.51.100.99 payload_len=180',
        "severity": "ALTA",
        "mitre": "T1048.003 - Exfiltration Over Alternative Protocol",
        "analysis": "Canal encoberto via consultas DNS com entropia estatística anormalmente alta e tamanho incomum de pacote, indicativo de tunelamento Iodide/DNSCat.",
        "containment": "iptables -I INPUT -s 192.168.10.88 -p udp --dport 53 -j DROP"
    },

    # 5. Linux Privilege Escalation
    {
        "category": "priv_esc",
        "log": 'auditd: type=EXECVE msg=audit(1698931200.123:451): argc=4 a0="/usr/bin/find" a1="." a2="-exec" a3="/bin/sh" : uid=1001 (www-data) euid=0 (root)',
        "severity": "ALTA",
        "mitre": "T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid",
        "analysis": "Escalada de privilégio local via binário com bit SUID mal configurado. O usuário www-data abusou do binário /usr/bin/find para spawnar um shell interativo com euid=0 (permissão root).",
        "containment": "pkill -u www-data -f '/bin/sh' && chmod u-s /usr/bin/find && passwd -l www-data"
    },
    {
        "category": "priv_esc",
        "log": 'sudo: webadmin : TTY=pts/0 ; PWD=/home/webadmin ; USER=root ; COMMAND=/bin/bash ; NOPASSWD=ALL',
        "severity": "MÉDIA",
        "mitre": "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "analysis": "Elevação de privilégio para root sem necessidade de senha a partir da conta webadmin via regra sudoers excessivamente permissiva.",
        "containment": "sed -i '/webadmin ALL=(ALL) NOPASSWD: ALL/d' /etc/sudoers && pkill -KILL -t pts/0"
    },
    {
        "category": "priv_esc",
        "log": 'Linux kernel: [412.890123] cve-2022-0847 (Dirty Pipe) exploit pattern detected: process "pipe_exp" modified read-only page cache for /etc/passwd',
        "severity": "CRÍTICA",
        "mitre": "T1068 - Exploitation for Privilege Escalation",
        "analysis": "Exploração local de vulnerabilidade de kernel Dirty Pipe (CVE-2022-0847). Processo não privilegiado sobrescreveu diretamente a page cache de arquivos protegidos (/etc/passwd) para injetar usuário root clandestino.",
        "containment": "kill -9 $(pidof pipe_exp) && reboot"
    },

    # 6. Falsos Positivos (Tráfego legítimo, DevOps, Backups)
    {
        "category": "false_positive",
        "log": '10.0.100.50 - - [02/Nov/2026:01:00:15 -0300] "POST /api/v2/backup/upload HTTP/1.1" 200 8589934592 "VeeamBackupClient/12.1" 10.0.200.10',
        "severity": "FALSO POSITIVO",
        "mitre": "N/A - Atividade Administrativa Legítima",
        "analysis": "Transferência volumosa de 8GB de dados correspondente à rotina corporativa de backup noturno agendado pelo serviço Veeam entre instâncias autorizadas da sub-rede de infraestrutura.",
        "containment": "Nenhuma ação de contenção necessária. Tráfego em conformidade com a política de baseline da organização."
    },
    {
        "category": "false_positive",
        "log": '10.20.1.15 - - [02/Nov/2026:09:00:00 -0300] "GET /test-sqli-probe?id=1\'%20OR%201=1 HTTP/1.1" 403 120 "OWASP-ZAP/2.14.0 (DevSecOps-Automated-Pipeline)" 10.20.1.15',
        "severity": "FALSO POSITIVO",
        "mitre": "N/A - Scanner Interno Homologado",
        "analysis": "Requisições de teste simulando injeção SQL originadas pelo nó de CI/CD da equipe de DevSecOps interna durante pipeline de testes dinâmicos de segurança (DAST) em staging. Bloqueado corretamente pelo WAF com HTTP 403.",
        "containment": "Nenhuma ação de contenção. Manter regra de auditoria e monitorar término da pipeline CI/CD."
    },
    {
        "category": "false_positive",
        "log": 'Nov  2 00:00:01 srv-backup CRON[4512]: (root) CMD (/usr/local/bin/rsync -avz /var/www/ backup@storage.internal:/backup/www/)',
        "severity": "FALSO POSITIVO",
        "mitre": "N/A - Rotina Operacional",
        "analysis": "Execução periódica de sincronização de arquivos via rsync disparada pelo cron institucional sob privilégios do root para o servidor de armazenamento interno.",
        "containment": "Nenhuma ação necessária. Tarefa automatizada válida e documentada."
    },

    # 7. Web Shell & Remote Code Execution (RCE)
    {
        "category": "webshell",
        "log": '192.168.1.50 - - [02/Nov/2026:16:42:01] "POST /wp-content/uploads/2026/11/up.php?cmd=cat%20/etc/shadow HTTP/1.1" 200 1420 "curl/7.68.0" 195.154.122.3',
        "severity": "CRÍTICA",
        "mitre": "T1505.003 - Server Software Component: Web Shell",
        "analysis": "Web Shell PHP ativa no diretório público de uploads executando comandos arbitrários do sistema operacional via parâmetro HTTP GET/POST para leitura do arquivo /etc/shadow.",
        "containment": "rm -f /var/www/html/wp-content/uploads/2026/11/up.php && iptables -I INPUT -s 195.154.122.3 -j DROP"
    },

    # 8. Lateral Movement / Mimikatz
    {
        "category": "lateral_movement",
        "log": 'EventID: 4624, LogonType: 9, TargetUserName: svc_domain_admin, WorkstationName: DESKTOP-HR04, ProcessName: C:\\Windows\\System32\\lsass.exe, AuthenticationPackage: Negotiate',
        "severity": "ALTA",
        "mitre": "T1550.002 - Use Alternate Authentication Material: Pass the Hash",
        "analysis": "Logon tipo 9 (NewCredentials) disparado a partir de uma estação de trabalho comum do departamento de RH usando credenciais da conta de administrador de domínio, sugerindo ataque Pass-the-Hash via Mimikatz/Rubeus.",
        "containment": "net user svc_domain_admin /active:no && route add 192.168.5.44 MASK 255.255.255.255 127.0.0.1"
    }
]

# Função para enriquecer e multiplicar com variações realistas
def generate_dataset(total_train=60, total_test=15):
    all_samples = []
    
    # Gerar amostras a partir dos templates com variações de IPs, portas, datas e parâmetros
    ip_subnets = ["203.0.113", "198.51.100", "185.220.101", "45.33.32", "194.26.29", "91.240.118", "103.152.220"]
    internal_ips = ["10.0.1", "10.0.2", "172.16.10", "192.168.1", "192.168.15"]
    
    for _ in range(total_train + total_test):
        tpl = random.choice(INCIDENT_TEMPLATES)
        ext_ip = f"{random.choice(ip_subnets)}.{random.randint(2, 250)}"
        int_ip = f"{random.choice(internal_ips)}.{random.randint(10, 240)}"
        port = random.randint(30000, 64000)
        
        raw_log = tpl["log"]
        raw_log = raw_log.replace("203.0.113.45", ext_ip).replace("185.220.101.5", ext_ip).replace("45.33.32.156", ext_ip)
        raw_log = raw_log.replace("192.168.1.105", int_ip).replace("10.0.4.150", int_ip)
        
        containment = tpl["containment"].replace("203.0.113.45", ext_ip).replace("185.220.101.5", ext_ip)
        containment = containment.replace("10.0.4.150", int_ip)
        
        assistant_content = (
            f"[SEVERIDADE]: {tpl['severity']}\n"
            f"[TÁTICA MITRE ATT&CK]: {tpl['mitre']}\n"
            f"[ANÁLISE TÉCNICA]: {tpl['analysis']}\n"
            f"[AÇÃO DE CONTENÇÃO]: {containment}"
        )
        
        sample = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analise o seguinte log e forneça a resposta estrita de SOC:\n{raw_log}"},
                {"role": "assistant", "content": assistant_content}
            ],
            # Também incluímos o formato plano 'text' para compatibilidade total com SFTTrainer
            "text": f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\nAnalise o seguinte log e forneça a resposta estrita de SOC:\n{raw_log}<|im_end|>\n<|im_start|>assistant\n{assistant_content}<|im_end|>"
        }
        all_samples.append(sample)
    
    # Embaralhar para evitar viés de ordem
    random.seed(42)
    random.shuffle(all_samples)
    
    train_samples = all_samples[:total_train]
    test_samples = all_samples[total_train:total_train + total_test]
    
    return train_samples, test_samples

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    train_file = os.path.join(base_dir, "soc_train.jsonl")
    test_file = os.path.join(base_dir, "soc_test.jsonl")
    
    train_data, test_data = generate_dataset(total_train=70, total_test=15)
    
    with open(train_file, "w", encoding="utf-8") as f:
        for item in train_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            
    with open(test_file, "w", encoding="utf-8") as f:
        for item in test_data:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            
    print(f"Dataset gerado com sucesso!")
    print(f"Treino: {len(train_data)} exemplos -> {train_file}")
    print(f"Teste:  {len(test_data)} exemplos -> {test_file}")

if __name__ == "__main__":
    main()
