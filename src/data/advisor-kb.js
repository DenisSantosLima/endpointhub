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

  "Require LDAP client signing to prevent tampering and protect directory authentication": {
    summary: "Exige que os workstations Windows assinem digitalmente as consultas LDAP enviadas ao Active Directory. A assinatura (integrity signing) garante que o pacote não foi alterado em trânsito entre o cliente e o Domain Controller — sem ela, um atacante em posição de MITM pode adulterar respostas de consulta ou usar a sessão para relay de autenticação.",
    risk: "Sem exigência de assinatura, um atacante na mesma rede pode interceptar e modificar tráfego LDAP não assinado (man-in-the-middle), fazendo o cliente tomar decisões com base em registros falsos do diretório. Esse mesmo canal desprotegido é usado em ataques de NTLM relay contra o LDAP/LDAPS para criação de objetos ou escalonamento de privilégio (ex: técnica usada por ferramentas como ntlmrelayx). É um dos vetores mais explorados em comprometimento de Active Directory.",
    links: [
      { label: "Microsoft — How to enable LDAP signing", url: "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server" },
      { label: "Microsoft — AD Hardening Series: Enforcing LDAP Signing", url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-3-%E2%80%93-enforcing-ldap-signing/4066233" },
      { label: "LDAPWiki — LDAP Signing", url: "https://ldapwiki.com/wiki/Wiki.jsp?page=LDAP+Signing" },
    ],
    methods: [
      {
        id: "intune-settings-catalog",
        label: "Via Intune (Settings Catalog — lado cliente)",
        icon: "⚙️",
        platform: "windows",
        steps: [
          {
            title: "Entender os dois lados da configuração",
            body: "Esta recomendação tem **dois lados** que precisam ser configurados juntos:\n\n- **Lado cliente** (workstations Windows): controlado via Intune/GPO — é o que fazemos aqui.\n- **Lado servidor** (Domain Controllers): controlado via GPO aplicado diretamente nos DCs — **não é gerenciável pelo Intune**, precisa ser feito via Group Policy tradicional ou LDP.exe.\n\nSe apenas o lado cliente for configurado, os workstations vão *solicitar* assinatura mas o DC pode aceitar binds sem assinatura de outros clientes. O ideal é configurar os dois lados.",
            note: "Foque primeiro no lado cliente (via Intune) — é o escopo desta ferramenta. Peça ao time de AD para aplicar 'Domain controller: LDAP server signing requirements = Require signing' na Default Domain Controllers Policy.",
          },
          {
            title: "Criar perfil de configuração no Intune",
            body: "No Intune Admin Center: **Devices → Configuration → Create → New policy**\n- Platform: **Windows 10 and later**\n- Profile type: **Settings catalog**",
          },
          {
            title: "Localizar e configurar o setting",
            body: "Clique em **+ Add settings**, busque por:\n```\nLDAP client signing requirements\n```\nLocalize em **Local Policies Security Options** o setting:\n- **Network security: LDAP client signing requirements**\n\nConfigure o valor para:\n- **Require Signing**",
            note: "O valor padrão do Windows já é 'Negotiate signing' — clientes Windows não devem quebrar com essa mudança. O risco de compatibilidade está em dispositivos não-Windows (Linux, appliances, scanners) que fazem bind LDAP sem suporte a SASL signing.",
          },
          {
            title: "Fase de auditoria antes de aplicar amplamente",
            body: "Antes de exigir globalmente, monitore nos Domain Controllers o **Event ID 2887** (Directory Service log) — ele mostra a cada 24h o total de binds LDAP não assinados na rede. Se o número for alto, habilite diagnóstico detalhado para identificar a origem:\n```\nreg add HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\Diagnostics /v \"16 LDAP Interface Events\" /t REG_DWORD /d 2\n```\nIsso ativa o **Event ID 2889**, que loga IP e conta de cada bind não assinado — use para identificar exceções antes de aplicar 'Require'.",
            code: "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics /v \"16 LDAP Interface Events\" /t REG_DWORD /d 2",
            lang: "powershell",
          },
          {
            title: "Atribuir e verificar",
            body: "Atribua o perfil ao grupo de workstations Windows. Após sincronizar, verifique no device:",
            code: [
              "Get-ItemProperty -Path \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LDAP\" -Name \"LDAPClientIntegrity\" -ErrorAction SilentlyContinue",
              "",
              "# Valores: 0 = None | 1 = Negotiate signing | 2 = Require signing (esperado)"
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
            body: "Crie `Detect-LDAPClientSigning.ps1`:",
            code: [
              "$path = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LDAP\"",
              "$value = Get-ItemProperty -Path $path -Name \"LDAPClientIntegrity\" -ErrorAction SilentlyContinue",
              "",
              "if ($null -eq $value -or $value.LDAPClientIntegrity -lt 2) {",
              "    Write-Output \"LDAP client signing nao esta em Require. Valor atual: $($value.LDAPClientIntegrity)\"",
              "    exit 1",
              "} else {",
              "    Write-Output \"Conforme: LDAPClientIntegrity = 2 (Require signing)\"",
              "    exit 0",
              "}"
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Script de remediação",
            body: "Crie `Remediate-LDAPClientSigning.ps1`:",
            code: [
              "$path = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LDAP\"",
              "if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }",
              "Set-ItemProperty -Path $path -Name \"LDAPClientIntegrity\" -Value 2 -Type DWord -Force",
              "Write-Output \"LDAPClientIntegrity configurado para 2 (Require signing)\""
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Deploy no Intune",
            body: "**Devices → Scripts and remediations → Remediations → Create**\n\n- Detection script: `Detect-LDAPClientSigning.ps1`\n- Remediation script: `Remediate-LDAPClientSigning.ps1`\n- Run as: **System (64-bit)**\n- Schedule: **Every 1 day**\n\nAtribua ao grupo de workstations Windows.",
          },
        ],
      },
    ],
  },

  "Encrypt LDAP client traffic to protect sensitive data in transit": {
    summary: "Garante que o tráfego LDAP entre os workstations Windows e os Domain Controllers seja selado (criptografado), não apenas assinado. Quando a assinatura LDAP é negociada via SASL (NTLM ou Kerberos), o Windows normalmente ativa sealing (confidencialidade) junto com signing (integridade) — mas isso só ocorre quando o cliente é configurado para negociar ou exigir o nível correto.",
    risk: "Tráfego LDAP em texto claro pode expor consultas ao diretório — incluindo nomes de usuário, estrutura de OUs, grupos e, em binds simples sem TLS, até credenciais. Um atacante capturando tráfego de rede (packet sniffing) consegue reconstruir informações sensíveis sobre a topologia do AD e, em cenários de simple bind, capturar senhas diretamente.",
    links: [
      { label: "Microsoft — LDAP over SSL (LDAPS) Certificate", url: "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority" },
      { label: "U-Tools — LDAP Signing Requirements for Active Directory", url: "https://u-tools.com/help/LdapMismatch.asp" },
      { label: "KomuraSoft — SMB and LDAP Signing for NTLM Relay Defence", url: "https://comcomponent.com/en/blog/smb-signing-ldap-channel-binding/" },
    ],
    methods: [
      {
        id: "intune-settings-catalog",
        label: "Via Intune (Settings Catalog)",
        icon: "⚙️",
        platform: "windows",
        steps: [
          {
            title: "Relação com 'Require LDAP client signing'",
            body: "Esta recomendação está **diretamente ligada** à recomendação *'Require LDAP client signing'*. No Windows, quando o cliente LDAP negocia autenticação via SASL (NTLM ou Kerberos) com **Negotiate signing** ou **Require signing**, o SSPI ativa integridade (signing) **e** confidencialidade (sealing/criptografia) na mesma negociação — não existe um toggle separado só para 'criptografar sem assinar'.\n\nSe você já aplicou o guia de **Require LDAP client signing**, esta recomendação tende a ser resolvida automaticamente. Confirme antes de duplicar esforço.",
            note: "Ambas as recomendações do Defender podem apontar para o mesmo registry value (LDAPClientIntegrity). Aplicar 'Require signing' uma vez cobre as duas.",
          },
          {
            title: "Configurar via Settings Catalog (caso ainda não aplicado)",
            body: "No Intune: **Devices → Configuration → Create → New policy**\n- Platform: **Windows 10 and later**\n- Profile type: **Settings catalog**\n\nBusque por `LDAP client signing requirements` e configure:\n- **Network security: LDAP client signing requirements** = **Require Signing**",
          },
          {
            title: "Considerar LDAPS (porta 636) para cenários que exigem TLS completo",
            body: "Para cenários que exigem criptografia via TLS (ex: integração com aplicações de terceiros, LDAP simple bind), avalie habilitar **LDAP over SSL (LDAPS)** nos Domain Controllers — isso requer certificado emitido para os DCs e é uma configuração do lado servidor, feita pelo time de AD/PKI, não pelo Intune.",
            note: "LDAPS é o caminho recomendado quando aplicações fazem simple bind (usuário + senha em texto claro) — o sealing via SASL não protege esse tipo de bind.",
          },
          {
            title: "Verificar aplicação",
            body: "No device Windows, confirme o valor:",
            code: [
              "Get-ItemProperty -Path \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LDAP\" -Name \"LDAPClientIntegrity\" -ErrorAction SilentlyContinue",
              "",
              "# 2 = Require signing (ativa integridade + confidencialidade via SASL sealing)"
            ].join("\n"),
            lang: "powershell",
          },
        ],
      },
    ],
  },

  "Set 'Minimum PIN length for startup' to '6 or more characters'": {
    summary: "Define o comprimento mínimo do PIN de inicialização do BitLocker (TPM + PIN) em dispositivos Windows. Um PIN mais longo aumenta exponencialmente o tempo necessário para um ataque de força bruta contra o pré-boot, mesmo em cenários de acesso físico ao equipamento.",
    risk: "PINs curtos (4 dígitos) podem ser testados rapidamente em ataques de força bruta com acesso físico ao dispositivo, especialmente se o TPM não tiver lockout configurado corretamente. Um PIN fraco reduz drasticamente a proteção que o BitLocker oferece contra roubo ou perda do equipamento.",
    links: [
      { label: "Microsoft — Configure minimum PIN length for startup", url: "https://learn.microsoft.com/en-us/intune/configmgr/protect/tech-ref/bitlocker/settings" },
      { label: "Microsoft Graph — bitLockerSystemDrivePolicy", url: "https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-bitlockersystemdrivepolicy?view=graph-rest-beta" },
    ],
    methods: [
      {
        id: "intune-endpoint-security",
        label: "Via Intune (Endpoint Security — Disk Encryption)",
        icon: "🔒",
        platform: "windows",
        steps: [
          {
            title: "Criar ou editar o perfil de Disk Encryption",
            body: "No Intune Admin Center: **Endpoint security → Disk encryption → Create Policy**\n- Platform: **Windows 10, Windows 11, and Windows Server**\n- Profile: **BitLocker**\n\nSe já existir um perfil de BitLocker aplicado, edite-o em vez de criar um novo.",
          },
          {
            title: "Configurar autenticação adicional na inicialização",
            body: "Na seção **BitLocker – Base Settings**, em **Additional authentication at startup**:\n- **Configure additional authentication at startup**: **Enable**\n- **BitLocker system drive policy → Startup PIN**: **Require startup PIN with TPM** (ou **Allow**, conforme a política da organização)\n- **Configure minimum PIN length for startup**: **Enable**\n- **Minimum PIN length**: `6`",
            note: "O mínimo aceito pelo Windows é 4 e o máximo 20 dígitos, mas desde o Windows 10 1703 o padrão recomendado é 6+. PINs abaixo de 6 fazem o Windows ajustar o período de lockout do TPM 2.0 para compensar.",
          },
          {
            title: "Atribuir e forçar re-configuração se necessário",
            body: "Atribua o perfil ao grupo de dispositivos Windows. Dispositivos que já têm BitLocker habilitado com um PIN mais curto **não são forçados a trocar automaticamente** — o usuário só será solicitado a atualizar o PIN na próxima mudança voluntária, a menos que você force a reconfiguração via script.",
          },
          {
            title: "Forçar atualização do PIN existente (opcional)",
            body: "Para ambientes que já têm BitLocker ativo com PIN curto, use um script para forçar a atualização:",
            code: [
              "# Force-BitLockerPinUpdate.ps1",
              "# Verifica o comprimento atual do PIN e notifica o usuario para atualizar",
              "# (o Windows nao permite ler o PIN atual por seguranca; a validacao real",
              "# ocorre no proximo ciclo de alteracao voluntaria pelo usuario)",
              "",
              "$status = manage-bde -status C:",
              "Write-Output $status",
              "Write-Output \"Lembre o usuario de atualizar o PIN do BitLocker para 6+ digitos via Painel de Controle > BitLocker Drive Encryption > Change PIN\""
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Verificar a política aplicada",
            body: "No device, confirme a política efetiva:",
            code: "Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE\" -Name \"MinimumPIN\" -ErrorAction SilentlyContinue",
            lang: "powershell",
          },
        ],
      },
    ],
  },

  "Set 'Enforce password history' to '24 or more password(s)' in macOS": {
    summary: "Impede que usuários reutilizem uma das últimas 24 senhas ao trocar a senha da conta no macOS. Isso força a criação de senhas genuinamente novas a cada troca, em vez de alternar entre 2-3 senhas conhecidas.",
    risk: "Sem histórico de senha, um usuário pode alternar entre a mesma senha antiga e uma nova a cada exigência de troca, anulando o benefício de políticas de expiração de senha. Se uma senha antiga já vazou (ex: em um data breach anterior), reutilizá-la mantém o dispositivo exposto.",
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
            title: "Adicionar o setting de histórico de senha",
            body: "Clique em **+ Add settings**, busque por `password` e localize na categoria **Passcode**:\n- **Password History**\n\nConfigure o valor:\n- **Password History**: `24`",
          },
          {
            title: "Atribuir e verificar",
            body: "Atribua ao grupo de dispositivos macOS. Para validar no terminal:\n```bash\npwpolicy -n /Local/Default -getglobalpolicy\n```\nO output deve conter `usingHistory=24`.",
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
            body: "Crie e faça deploy via Intune Platform Scripts:",
            code: [
              "#!/bin/bash",
              "",
              "HISTORICO_SENHAS=24",
              "",
              "sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy \"usingHistory=$HISTORICO_SENHAS\"",
              "",
              "echo \"Politica aplicada: historico de $HISTORICO_SENHAS senhas\"",
              "pwpolicy -n /Local/Default -getglobalpolicy | grep usingHistory"
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

  "Set 'Maximum password age' to '90 or fewer days, but not 0' in macOS": {
    summary: "Define o número máximo de dias que uma senha pode permanecer sem ser trocada no macOS. Zero significa 'nunca expira', o que a recomendação explicitamente pede para evitar — o valor deve estar entre 1 e 90 dias.",
    risk: "Senhas que nunca expiram permanecem válidas indefinidamente mesmo após vazamentos, comprometimento de credenciais ou saída de funcionários que conheciam a senha compartilhada de uma conta local. Rotação periódica limita a janela de exposição de uma credencial comprometida.",
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
            title: "Adicionar o setting de idade máxima de senha",
            body: "Clique em **+ Add settings**, busque por `password` e localize na categoria **Passcode**:\n- **Maximum Passcode Age In Days**\n\nConfigure o valor:\n- **Maximum Passcode Age In Days**: `90`",
            note: "Nunca configure como `0` — isso desativa a expiração, o oposto do que a recomendação pede.",
          },
          {
            title: "Atribuir e verificar",
            body: "Atribua ao grupo de dispositivos macOS. Para validar no terminal:\n```bash\npwpolicy -n /Local/Default -getglobalpolicy\n```\nO output deve conter `maxMinutesUntilChangePassword=129600` (90 dias × 1440 minutos).",
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
            body: "O `pwpolicy` trabalha com minutos, não dias — o script já faz a conversão. Crie e faça deploy via Intune Platform Scripts:",
            code: [
              "#!/bin/bash",
              "",
              "DIAS_MAXIMOS=90",
              "MINUTOS_MAXIMOS=$((DIAS_MAXIMOS * 24 * 60))",
              "",
              "sudo /usr/bin/pwpolicy -n /Local/Default -setglobalpolicy \"maxMinutesUntilChangePassword=$MINUTOS_MAXIMOS\"",
              "",
              "echo \"Politica aplicada: senha expira em $DIAS_MAXIMOS dias ($MINUTOS_MAXIMOS minutos)\"",
              "pwpolicy -n /Local/Default -getglobalpolicy | grep maxMinutesUntilChangePassword"
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

  "SMB server security hardening against authentication relay attacks": {
    summary: "Exige assinatura digital (SMB signing) nas comunicações SMB do servidor e do cliente Windows. A assinatura garante que os pacotes SMB não foram adulterados em trânsito e — mais importante — impede que autenticações NTLM transportadas sobre SMB sejam usadas em ataques de relay, já que o atacante não possui a chave de sessão necessária para assinar as mensagens retransmitidas.",
    risk: "Sem SMB signing obrigatório, um atacante na mesma rede pode coagir um usuário ou serviço a autenticar (via PetitPotam, bug de impressora, LLMNR/NBT-NS poisoning) e então retransmitir (relay) essa autenticação NTLM contra outro servidor — muitas vezes chegando a Domain Admin em ambientes AD sem esse hardening. É uma das técnicas mais usadas em movimentação lateral e escalonamento de privilégio pós-comprometimento.",
    links: [
      { label: "Microsoft — SMB security hardening in Windows Server and Windows Client", url: "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening" },
      { label: "Microsoft — AD Hardening Series: Enforcing SMB Signing", url: "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%E2%80%93-enforcing-smb-signing/4272168" },
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
            title: "Configurar assinatura no servidor SMB (lado que recebe conexões)",
            body: "Busque por `digitally sign communications` e localize em **Local Policies Security Options**:\n- **Microsoft network server: Digitally sign communications (always)** → **Enabled**\n\nEsse setting controla o SMB Server — cada dispositivo Windows também atua como servidor SMB (compartilhamento de arquivos/impressoras), então essa recomendação se aplica mesmo a workstations comuns.",
          },
          {
            title: "Configurar assinatura no cliente SMB (complementar)",
            body: "Adicione também:\n- **Microsoft network client: Digitally sign communications (always)** → **Enabled**\n\nAmbos os lados (client e server) devem exigir assinatura para fechar o vetor de relay completamente — configurar só um lado deixa brecha para conexões partindo da direção não protegida.",
            note: "⚠️ Teste em um grupo piloto antes de aplicar amplamente. Dispositivos SMBv1 legados, NAS antigos ou impressoras de rede sem suporte a signing vão parar de conectar. Use os Eventos 3021/3022 (SMB Server) e 31998/31999 (SMB Client) no Windows para auditar quem depende de conexões não assinadas antes de reforçar.",
          },
          {
            title: "Atribuir e monitorar",
            body: "Atribua o perfil ao grupo de workstations Windows, priorizando um grupo piloto de 5-10% antes da expansão total.",
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
            body: "Crie `Detect-SMBSigningRequired.ps1`:",
            code: [
              "$serverPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanServer\\\\Parameters\"",
              "$clientPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanWorkstation\\\\Parameters\"",
              "",
              "$server = (Get-ItemProperty -Path $serverPath -Name \"RequireSecuritySignature\" -ErrorAction SilentlyContinue).RequireSecuritySignature",
              "$client = (Get-ItemProperty -Path $clientPath -Name \"RequireSecuritySignature\" -ErrorAction SilentlyContinue).RequireSecuritySignature",
              "",
              "if ($server -eq 1 -and $client -eq 1) {",
              "    Write-Output \"Conforme: SMB signing obrigatorio no server e no client\"",
              "    exit 0",
              "} else {",
              "    Write-Output \"Nao conforme: Server=$server Client=$client (esperado: 1 e 1)\"",
              "    exit 1",
              "}"
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Script de remediação",
            body: "Crie `Remediate-SMBSigningRequired.ps1`:",
            code: [
              "$serverPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanServer\\\\Parameters\"",
              "$clientPath = \"HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanWorkstation\\\\Parameters\"",
              "",
              "Set-ItemProperty -Path $serverPath -Name \"RequireSecuritySignature\" -Value 1 -Type DWord -Force",
              "Set-ItemProperty -Path $serverPath -Name \"EnableSecuritySignature\" -Value 1 -Type DWord -Force",
              "Set-ItemProperty -Path $clientPath -Name \"RequireSecuritySignature\" -Value 1 -Type DWord -Force",
              "Set-ItemProperty -Path $clientPath -Name \"EnableSecuritySignature\" -Value 1 -Type DWord -Force",
              "",
              "Write-Output \"SMB signing configurado como obrigatorio (server e client)\""
            ].join("\n"),
            lang: "powershell",
          },
          {
            title: "Deploy no Intune",
            body: "**Devices → Scripts and remediations → Remediations → Create**\n\n- Detection script: `Detect-SMBSigningRequired.ps1`\n- Remediation script: `Remediate-SMBSigningRequired.ps1`\n- Run as: **System (64-bit)**\n- Schedule: **Every 1 day**\n\nAtribua primeiro a um grupo piloto e monitore falhas de conexão SMB no service desk antes de expandir.",
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
