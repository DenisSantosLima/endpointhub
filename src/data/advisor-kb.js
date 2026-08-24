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

  "Disable the local storage of passwords and credentials": {
    summary: "Impede que o Windows armazene senhas e credenciais de rede localmente no Credential Manager. Quando habilitado, o sistema não salva hashes de senha nem tokens de autenticação em disco — reduzindo drasticamente o que ferramentas de extração como Mimikatz conseguem coletar em caso de comprometimento.",
    risk: "Com o armazenamento local habilitado, um atacante com acesso ao sistema consegue extrair credenciais cacheadas via LSASS dump ou acesso direto ao Credential Manager. A tag 'Human operated ransomware' no Defender indica que grupos de ransomware exploram ativamente essa superfície para movimento lateral. Com 1.330 devices expostos e 4 críticos, o impacto de um comprometimento pode ser amplo.",
    links: [
      { label: "CSP — NetworkProvider/HardenedUNCPaths", url: "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-credentialsui" },
      { label: "Microsoft — Credential Guard overview", url: "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard" },
      { label: "CIS Benchmark — Disable Password Storage", url: "https://www.cisecurity.org/benchmark/microsoft_windows_desktop" },
    ],
    methods: [
      {
        id: "intune-csp",
        label: "Via Intune (CSP / Settings Catalog)",
        icon: "⚙️",
        platform: "windows",
        steps: [
          {
            title: "Criar perfil de configuração",
            body: "No Intune Admin Center, acesse **Devices → Configuration → Create → New policy**.\n\nSelecione:\n- **Platform:** Windows 10 and later\n- **Profile type:** Settings catalog\n\nClique em **Create** e dê um nome descritivo, ex: `SEC-WIN-Disable-Credential-Storage`.",
          },
          {
            title: "Localizar o setting no Settings Catalog",
            body: "Clique em **+ Add settings** e na barra de busca digite:\n```\nDo not allow passwords to be saved\n```\nLocalize a categoria **Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Connection Client** e marque:\n- **Do not allow passwords to be saved**\n\nEm seguida, busque também por:\n```\nNetwork access: Do not allow storage of passwords\n```\nNa categoria **Local Policies / Security Options**, marque:\n- **Network access: Do not allow storage of passwords and credentials for network authentication**",
            note: "Os dois settings se complementam: o primeiro bloqueia salvamento de senhas no RDP Client, o segundo bloqueia o Credential Manager para autenticações de rede.",
          },
          {
            title: "Configurar os valores",
            body: "Com os dois settings adicionados, configure:\n\n**Do not allow passwords to be saved:**\n- Valor: **Enabled**\n\n**Network access: Do not allow storage of passwords and credentials for network authentication:**\n- Valor: **Enabled**",
          },
          {
            title: "Configurar via OMA-URI (alternativa CSP direto)",
            body: "Se preferir usar OMA-URI em vez do Settings Catalog, crie um perfil **Custom** (Templates → Custom) e adicione as entradas:\n\n**OMA-URI 1 — RDP Password Storage:**\n```\n./Device/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal\n```\n- Data type: **Integer**\n- Value: **1**\n\n**OMA-URI 2 — Network Credential Storage:**\n```\n./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowPasswordSaving\n```\n- Data type: **String**\n- Value: `<enabled/>`",
            note: "A opção Settings Catalog (passo anterior) é preferível ao OMA-URI por ser mais legível e auditável. Use OMA-URI apenas se o setting não aparecer no catalog.",
          },
          {
            title: "Atribuir e verificar",
            body: "Na aba **Assignments**, atribua ao grupo de workstations Windows. Recomende começar com um grupo piloto antes de expandir para toda a frota.\n\nApós a sincronização (~15 minutos), valide em um device com:\n```powershell\n# Verificar via registry\nGet-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" -Name \"DisableDomainCreds\" -ErrorAction SilentlyContinue\n\n# Valor esperado: DisableDomainCreds = 1\n```",
            code: [
              "# Verificar política aplicada",
              "Get-ItemProperty -Path \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\" -Name \"DisableDomainCreds\" -ErrorAction SilentlyContinue",
              "",
              "# Esperado: DisableDomainCreds = 1 (habilitado)",
              "# Se retornar vazio ou 0, a política ainda não foi aplicada"
            ].join("\n"),
            lang: "powershell",
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
            body: "Crie o arquivo `Detect-DisableCredentialStorage.ps1`. O script verifica se a chave de registry está configurada corretamente:",
            code: [
              "# Detect-DisableCredentialStorage.ps1",
              "# Verifica se o armazenamento local de credenciais está desabilitado",
              "# Exit 0 = Conforme | Exit 1 = Requer remediação",
              "",
              "$lsaPath    = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\"",
              "$rdpPath    = \"HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal Services\"",
              "",
              "$lsaValue = Get-ItemProperty -Path $lsaPath -Name \"DisableDomainCreds\" -ErrorAction SilentlyContinue",
              "$rdpValue = Get-ItemProperty -Path $rdpPath -Name \"DisablePasswordSaving\" -ErrorAction SilentlyContinue",
              "",
              "$lsaOk = $lsaValue -and $lsaValue.DisableDomainCreds -eq 1",
              "$rdpOk = $rdpValue -and $rdpValue.DisablePasswordSaving -eq 1",
              "",
              "if ($lsaOk -and $rdpOk) {",
              "    Write-Output \"CONFORME: armazenamento de credenciais desabilitado.\"",
              "    exit 0",
              "} else {",
              "    Write-Output \"NAO CONFORME: LSA=$($lsaValue.DisableDomainCreds) | RDP=$($rdpValue.DisablePasswordSaving)\"",
              "    exit 1",
              "}"
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Script de remediação",
            body: "Crie o arquivo `Remediate-DisableCredentialStorage.ps1`. O script aplica as chaves de registry necessárias:",
            code: [
              "# Remediate-DisableCredentialStorage.ps1",
              "# Desabilita o armazenamento local de senhas e credenciais",
              "# Requer execução como SYSTEM (64-bit)",
              "",
              "$ErrorActionPreference = \"Stop\"",
              "",
              "try {",
              "    # 1. Desabilitar armazenamento de credenciais de domínio (LSA)",
              "    $lsaPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\"",
              "    Set-ItemProperty -Path $lsaPath -Name \"DisableDomainCreds\" -Value 1 -Type DWord -Force",
              "    Write-Output \"OK: DisableDomainCreds configurado para 1\"",
              "",
              "    # 2. Desabilitar salvamento de senha no RDP Client",
              "    $rdpPath = \"HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal Services\"",
              "    if (-not (Test-Path $rdpPath)) {",
              "        New-Item -Path $rdpPath -Force | Out-Null",
              "    }",
              "    Set-ItemProperty -Path $rdpPath -Name \"DisablePasswordSaving\" -Value 1 -Type DWord -Force",
              "    Write-Output \"OK: DisablePasswordSaving configurado para 1\"",
              "",
              "    Write-Output \"Remediacao concluida com sucesso.\"",
              "    exit 0",
              "",
              "} catch {",
              "    Write-Output \"ERRO na remediacao: $_\"",
              "    exit 1",
              "}"
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Criar a Proactive Remediation no Intune",
            body: "No Intune Admin Center, vá em **Devices → Scripts and remediations → Remediations → + Create**.\n\nPreencha:\n- **Name:** `SEC-Disable-Credential-Storage`\n- **Description:** `Desabilita armazenamento local de senhas (LSA + RDP) conforme recomendação do Defender`\n\nNa aba **Settings**:\n- **Detection script:** upload do `Detect-DisableCredentialStorage.ps1`\n- **Remediation script:** upload do `Remediate-DisableCredentialStorage.ps1`\n- **Run this script using the logged on credentials:** **No**\n- **Enforce script signature check:** **No**\n- **Run script in 64-bit PowerShell:** **Yes**",
            note: "Executar em 64-bit é obrigatório para garantir acesso correto ao registry. Scripts em 32-bit podem ler chaves de um hive diferente no Windows 64-bit.",
          },
          {
            title: "Configurar o agendamento",
            body: "Na aba **Assignments**, atribua ao grupo de workstations Windows e configure:\n\n- **Schedule:** **Every 1 day**\n- Isso garante que, mesmo que o usuário ou outro processo reverta a configuração, ela será reaplicada no próximo ciclo.\n\nClique em **Create** para finalizar.",
          },
          {
            title: "Monitorar o resultado",
            body: "Após a implantação, acompanhe o status em:\n\n**Devices → Scripts and remediations → Remediations → [nome] → Device status**\n\nColunas importantes:\n- **Detection status:** Without issues = conforme / Needs remediation = estava não conforme\n- **Remediation status:** Success = corrigido pelo script\n\nPara validar manualmente em um device:",
            code: [
              "# Confirmar aplicação no device",
              "$lsa = (Get-ItemProperty \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\").DisableDomainCreds",
              "$rdp = (Get-ItemProperty \"HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal Services\" -ErrorAction SilentlyContinue).DisablePasswordSaving",
              "",
              "Write-Host \"DisableDomainCreds (LSA): $lsa  [esperado: 1]\"",
              "Write-Host \"DisablePasswordSaving (RDP): $rdp  [esperado: 1]\""
            ].join("\n"),
            lang: "powershell",
          },
        ],
      },
    ],
  },

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
            code: [
              "#!/bin/bash",
              "",
              "# --- CONFIGURAÇÕES ---",
              "LIMITE_TENTATIVAS=5",
              "TEMPO_ESPERA_MINUTOS=15",
              "",
              "# Aplica a política de limite de falhas",
              "sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy \"maxFailedLoginAttempts=$LIMITE_TENTATIVAS\"",
              "",
              "# Aplica a política de tempo para resetar o contador (Desbloqueio Automático)",
              "sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy \"policyAttributeMinutesUntilFailedAuthenticationReset=$TEMPO_ESPERA_MINUTOS\"",
              "",
              "# Confirmação da aplicação",
              "echo \"Configurações aplicadas com sucesso:\"",
              "echo \"Limite de tentativas: $LIMITE_TENTATIVAS\"",
              "echo \"Tempo de desbloqueio automático: $TEMPO_ESPERA_MINUTOS minutos\""
            ].join("\n"),
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
            code: [
              "# Verificar política atual",
              "pwpolicy -n /Local/Default -getglobalpolicy",
              "",
              "# Output esperado (entre outros):",
              "# maxFailedLoginAttempts=5",
              "# policyAttributeMinutesUntilFailedAuthenticationReset=15"
            ].join("\n"),
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
            code: [
              "#!/bin/bash",
              "",
              "TAMANHO_MINIMO=14",
              "",
              "sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy \"minChars=$TAMANHO_MINIMO\"",
              "",
              "echo \"Política aplicada: comprimento mínimo de senha = $TAMANHO_MINIMO caracteres\"",
              "pwpolicy -n /Local/Default -getglobalpolicy | grep minChars"
            ].join("\n"),
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
            code: [
              "# Detect-NTLMLevel.ps1",
              "$regPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\"",
              "$value = Get-ItemProperty -Path $regPath -Name \"LmCompatibilityLevel\" -ErrorAction SilentlyContinue",
              "",
              "# 5 = NTLMv2 only, refuse LM & NTLM",
              "if ($null -eq $value -or $value.LmCompatibilityLevel -lt 5) {",
              "    Write-Output \"NTLM não está configurado corretamente. Valor atual: $($value.LmCompatibilityLevel)\"",
              "    exit 1  # Remediação necessária",
              "} else {",
              "    Write-Output \"NTLM configurado corretamente (LmCompatibilityLevel = $($value.LmCompatibilityLevel))\"",
              "    exit 0  # Conforme",
              "}"
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Script de remediação",
            body: "Crie o script de remediação que aplica a configuração:",
            code: [
              "# Remediate-NTLMLevel.ps1",
              "$regPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\"",
              "",
              "# 5 = Send NTLMv2 response only. Refuse LM & NTLM",
              "Set-ItemProperty -Path $regPath -Name \"LmCompatibilityLevel\" -Value 5 -Type DWord -Force",
              "",
              "Write-Output \"LmCompatibilityLevel configurado para 5 (NTLMv2 only)\""
            ].join("\n"),
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
