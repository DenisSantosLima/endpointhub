/* ============================================================
   Security Advisor — Knowledge Base de Implementações
   Cada chave é o nome EXATO da recomendação (case-sensitive)
   conforme aparece no CSV do Defender portal.
   
   Estrutura de cada entrada:
   {
     summary: string          — o que é e por que importa
     risk: string             — risco se não implementado
     links: [{label, url}]    — documentação oficial
     methods: [               — caminhos de implementação
       {
         id: string           — identificador único
         label: string        — nome do método (ex: "Via Intune")
         icon: string         — emoji ou ícone
         platform: string     — 'windows' | 'macos' | 'all'
         steps: [             — passo a passo
           { title, body, code?, lang?, note? }
         ]
       }
     ]
   }
   ============================================================ */

export const KB = {

  "Set account lockout threshold to 5 or lower in macOS": {
    summary: "Configura o número máximo de tentativas de login incorretas antes de bloquear a conta no macOS. Com o threshold em 5 ou menos, um ataque de força bruta fica inviável — após 5 tentativas erradas, a conta trava e exige intervenção do admin ou desbloqueio automático por tempo.",
    risk: "Sem limite de tentativas, um atacante pode tentar senhas indefinidamente (brute force). Em ambientes com contas locais ou LAPS, isso é uma superfície de ataque real.",
    links: [
      { label: "CIS macOS Benchmark — Account Lockout", url: "https://www.cisecurity.org/benchmark/apple_os" },
      { label: "Intune — Settings Catalog macOS", url: "https://learn.microsoft.com/en-us/mem/intune/configuration/settings-catalog" },
    ],
    methods: [
      {
        id: "intune-settings-catalog",
        label: "Via Intune (Settings Catalog)",
        icon: "⚙️",
        platform: "macos",
        steps: [
          {
            title: "Acessar o Settings Catalog",
            body: "No Intune Admin Center, vá em **Devices → Configuration → Create → New policy**. Selecione:\n- Platform: **macOS**\n- Profile type: **Settings catalog**\n\nClique em **Create**.",
          },
          {
            title: "Adicionar o setting de Account Lockout",
            body: "Na tela de configuração, clique em **+ Add settings** e busque por:\n```\npassword\n```\nLocalize a categoria **Passcode** e marque o setting:\n- **Maximum Number Of Failed Attempts**",
            note: "Se o setting não aparecer, tente buscar por 'lockout' ou 'failed attempts'.",
          },
          {
            title: "Configurar o valor",
            body: "Com o setting adicionado, configure:\n- **Maximum Number Of Failed Attempts**: `5`\n\nIsso garante que após 5 tentativas incorretas a conta será bloqueada.",
          },
          {
            title: "Atribuir o perfil",
            body: "Vá até a aba **Assignments** e atribua o perfil ao grupo de dispositivos macOS gerenciados (ex: `All-macOS-Devices` ou o grupo correspondente no seu tenant).\n\nClique em **Review + create** e depois **Create**.",
          },
          {
            title: "Verificar aplicação",
            body: "Aguarde a sincronização (geralmente 15 minutos). Para forçar, abra o **Company Portal** no Mac e clique em **Sync**.\n\nPara validar no terminal do Mac:\n```bash\npwpolicy -n /Local/Default -getglobalpolicy\n```\nO output deve conter `maxFailedLoginAttempts=5`.",
            code: "pwpolicy -n /Local/Default -getglobalpolicy",
            lang: "bash",
          },
        ],
      },
      {
        id: "shell-script-intune",
        label: "Via Shell Script (Intune)",
        icon: "🖥️",
        platform: "macos",
        steps: [
          {
            title: "Criar o script de remediação",
            body: "Crie um arquivo com o conteúdo abaixo. O script configura o limite de tentativas via `pwpolicy` e define o tempo de desbloqueio automático.\n\nSalve como `Set-MacOS-AccountLockout.sh`:",
            code: `#!/bin/bash

# --- CONFIGURAÇÕES ---
LIMITE_TENTATIVAS=5
TEMPO_ESPERA_MINUTOS=15

# Aplica a política de limite de falhas
sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy "maxFailedLoginAttempts=$LIMITE_TENTATIVAS"

# Aplica a política de tempo para resetar o contador (Desbloqueio Automático)
sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy "policyAttributeMinutesUntilFailedAuthenticationReset=$TEMPO_ESPERA_MINUTOS"

# Confirmação da aplicação
echo "Configurações aplicadas com sucesso:"
echo "Limite de tentativas: $LIMITE_TENTATIVAS"
echo "Tempo de desbloqueio automático: $TEMPO_ESPERA_MINUTOS minutos"`,
            lang: "bash",
          },
          {
            title: "Fazer upload do script no Intune",
            body: "No Intune Admin Center, vá em **Devices → Scripts and remediations → Platform scripts → Add → macOS**.\n\nPreencha:\n- **Name**: `Set macOS Account Lockout Threshold`\n- **Description**: `Configura limite de 5 tentativas de login via pwpolicy`\n- **Script file**: faça upload do arquivo `Set-MacOS-AccountLockout.sh`",
            note: "macOS não suporta Proactive Remediations — use Platform scripts (shell scripts) para deploy de configurações.",
          },
          {
            title: "Configurar as opções do script",
            body: "Na aba de configurações do script, marque:\n- **Run script as signed-in user**: **No** (rodar como root/SYSTEM)\n- **Hide script notifications on devices**: **Yes**\n- **Script frequency**: **Every 1 week** (para garantir que a política persiste)\n- **Max number of times to retry if script fails**: `3`",
          },
          {
            title: "Atribuir e monitorar",
            body: "Atribua o script ao grupo de dispositivos macOS. Após a sincronização, monitore o status em:\n\n**Devices → Scripts and remediations → Platform scripts → [nome do script] → Device status**\n\nDevices com **Success** indicam que a política foi aplicada.",
          },
          {
            title: "Validar no dispositivo",
            body: "Para confirmar a aplicação, execute no terminal do Mac:",
            code: `# Verificar política atual
pwpolicy -n /Local/Default -getglobalpolicy

# Output esperado (entre outros):
# maxFailedLoginAttempts=5
# policyAttributeMinutesUntilFailedAuthenticationReset=15`,
            lang: "bash",
          },
        ],
      },
    ],
  },

  "Set minimum password length to 14 or more characters in macOS": {
    summary: "Define o comprimento mínimo de senha para contas locais no macOS. Senhas com 14+ caracteres aumentam exponencialmente a resistência a ataques de força bruta e dicionário.",
    risk: "Senhas curtas podem ser quebradas em segundos com ferramentas modernas. Um Mac com senha de 6 caracteres pode ser comprometido offline em minutos.",
    links: [
      { label: "CIS macOS Benchmark — Password Policy", url: "https://www.cisecurity.org/benchmark/apple_os" },
      { label: "Intune Settings Catalog — macOS Passcode", url: "https://learn.microsoft.com/en-us/mem/intune/configuration/settings-catalog" },
    ],
    methods: [
      {
        id: "intune-settings-catalog",
        label: "Via Intune (Settings Catalog)",
        icon: "⚙️",
        platform: "macos",
        steps: [
          {
            title: "Criar perfil de configuração",
            body: "No Intune Admin Center: **Devices → Configuration → Create → New policy**\n- Platform: **macOS**\n- Profile type: **Settings catalog**",
          },
          {
            title: "Adicionar o setting de senha mínima",
            body: "Clique em **+ Add settings**, busque por `password` ou `passcode` e localize:\n- Categoria **Passcode**\n- Setting: **Minimum Passcode Length**",
          },
          {
            title: "Configurar o valor",
            body: "Configure:\n- **Minimum Passcode Length**: `14`\n\nOpcionalmente, ative também:\n- **Require Alphanumeric Passcode**: **Yes**",
          },
          {
            title: "Atribuir e verificar",
            body: "Atribua ao grupo de Macs e aguarde a sincronização. Para verificar:\n```bash\npwpolicy -n /Local/Default -getglobalpolicy\n```\nOutput esperado: `minChars=14`",
            code: "pwpolicy -n /Local/Default -getglobalpolicy",
            lang: "bash",
          },
        ],
      },
      {
        id: "shell-script-intune",
        label: "Via Shell Script (Intune)",
        icon: "🖥️",
        platform: "macos",
        steps: [
          {
            title: "Script de configuração",
            body: "Crie e deploy o script abaixo via Intune Platform Scripts:",
            code: `#!/bin/bash

TAMANHO_MINIMO=14

sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy "minChars=$TAMANHO_MINIMO"

echo "Política aplicada: comprimento mínimo de senha = $TAMANHO_MINIMO caracteres"
pwpolicy -n /Local/Default -getglobalpolicy | grep minChars`,
            lang: "bash",
          },
          {
            title: "Deploy via Intune",
            body: "**Devices → Scripts and remediations → Platform scripts → Add → macOS**\n\n- Run as: **root (No)**\n- Frequency: **Every 1 week**\n- Atribua ao grupo de dispositivos macOS",
          },
        ],
      },
    ],
  },

  "Disable NTLM authentication for Windows workstations": {
    summary: "Desabilita o protocolo NTLM nos workstations Windows. NTLM é um protocolo legado vulnerável a ataques Pass-the-Hash e NTLM Relay — substituí-lo por Kerberos ou negociação moderna elimina esses vetores de ataque.",
    risk: "NTLM ativo permite ataques Pass-the-Hash (captura e reutilização de hashes de senha), NTLM Relay (intermediação de autenticações) e é facilmente explorado em redes internas. Com 1.570 devices expostos, a superfície de ataque é significativa.",
    links: [
      { label: "Microsoft — NTLM Overview", url: "https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview" },
      { label: "Intune — Endpoint Security Baselines", url: "https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines" },
    ],
    methods: [
      {
        id: "intune-settings-catalog",
        label: "Via Intune (Settings Catalog)",
        icon: "⚙️",
        platform: "windows",
        steps: [
          {
            title: "Criar perfil de configuração",
            body: "No Intune Admin Center: **Devices → Configuration → Create → New policy**\n- Platform: **Windows 10 and later**\n- Profile type: **Settings catalog**",
          },
          {
            title: "Configurar restrições NTLM",
            body: "Clique em **+ Add settings** e busque por `NTLM`. Adicione e configure:\n\n**LAN Manager Authentication Level** (em Security Options):\n- Valor: `Send NTLMv2 response only. Refuse LM & NTLM`\n\n**Restrict NTLM: Outgoing NTLM traffic to remote servers**:\n- Valor: `Deny All`\n\n**Restrict NTLM: NTLM authentication in this domain** (apenas DCs):\n- Valor: `Deny All`",
            note: "⚠️ Implante em fases. Primeiro em modo Audit para capturar dependências de NTLM antes de bloquear. Habilite o event 8004 nos DCs para auditoria.",
          },
          {
            title: "Fase 1 — Auditoria (recomendado antes de bloquear)",
            body: "Configure primeiro em modo auditoria para mapear o que usa NTLM:\n\n**Restrict NTLM: Audit Incoming NTLM Traffic**: `Enable auditing for all accounts`\n**Restrict NTLM: Audit NTLM authentication in this domain**: `Enable all`\n\nMonitore o Event Viewer: **Applications and Services Logs → Microsoft → Windows → NTLM → Operational**",
            note: "Aguarde 2-4 semanas em auditoria antes de partir para o bloqueio. Impressoras, aplicações legadas e drives mapeados por IP são os maiores usuários de NTLM.",
          },
          {
            title: "Fase 2 — Bloqueio gradual",
            body: "Após confirmar que não há dependências críticas, mude para **Deny**. Aplique primeiro em um grupo piloto (ex: 10% da frota) e expanda progressivamente.\n\nAtribua o perfil ao grupo de workstations Windows e monitore incidentes de suporte.",
          },
        ],
      },
      {
        id: "proactive-remediation",
        label: "Via Proactive Remediation",
        icon: "🔧",
        platform: "windows",
        steps: [
          {
            title: "Script de detecção",
            body: "Crie o script de detecção que verifica o nível de autenticação LAN Manager:",
            code: `# Detect-NTLMLevel.ps1
$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
$value = Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

# 5 = NTLMv2 only, refuse LM & NTLM
if ($null -eq $value -or $value.LmCompatibilityLevel -lt 5) {
    Write-Output "NTLM não está configurado corretamente. Valor atual: $($value.LmCompatibilityLevel)"
    exit 1  # Remediação necessária
} else {
    Write-Output "NTLM configurado corretamente (LmCompatibilityLevel = $($value.LmCompatibilityLevel))"
    exit 0  # Conforme
}`,
            lang: "powershell",
          },
          {
            title: "Script de remediação",
            body: "Crie o script de remediação que aplica a configuração:",
            code: `# Remediate-NTLMLevel.ps1
$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"

# 5 = Send NTLMv2 response only. Refuse LM & NTLM
Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force

Write-Output "LmCompatibilityLevel configurado para 5 (NTLMv2 only)"`,
            lang: "powershell",
          },
          {
            title: "Deploy no Intune",
            body: "**Devices → Scripts and remediations → Remediations → Create**\n\n- Detection script: upload do `Detect-NTLMLevel.ps1`\n- Remediation script: upload do `Remediate-NTLMLevel.ps1`\n- Run as: **System (64-bit)**\n- Schedule: **Every 1 day**\n\nAtribua ao grupo de workstations Windows.",
          },
        ],
      },
    ],
  },

};

/* Retorna o conteúdo KB para uma recomendação, ou null se não houver */
export function getKB(name) {
  return KB[name] || null;
}

/* Lista de nomes que têm KB (para mostrar indicador visual na tabela) */
export const KB_NAMES = new Set(Object.keys(KB));
