---
titulo: "Valide e instale módulos automaticamente nos seus scripts de Graph"
resumo: "Nunca assuma que o Microsoft.Graph já está instalado na máquina onde o script vai rodar. Um bloco de validação no início evita falhas silenciosas em servidores e estações de colegas."
data: 2026-08-14
autor: EndpointHub
categoria: PowerShell / Graph
nivel: Básico
tags: ["PowerShell", "Microsoft Graph", "automação"]
lang: pt
slug: "validar-modulos-powershell-graph"
---

Um script que funciona na sua máquina e quebra na do colega quase sempre esbarra na mesma coisa: o módulo não estava instalado lá. Em automação de Intune/Entra via Microsoft Graph, o certo é o script **verificar e instalar** o que precisa antes de rodar a lógica — não assumir que o ambiente já está pronto.

## O padrão

Comece todo script com um bloco que checa cada módulo necessário e instala o que faltar:

```powershell
$modulos = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.DeviceManagement'
)

foreach ($m in $modulos) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Instalando módulo $m..." -ForegroundColor Yellow
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $m -ErrorAction Stop
}
```

`Get-Module -ListAvailable` consulta o que está instalado sem carregar nada. Só instala quando o módulo realmente falta, e usa `-Scope CurrentUser` para não exigir elevação.

## Por que importar submódulos específicos

Importar `Microsoft.Graph.DeviceManagement` em vez do metamódulo inteiro `Microsoft.Graph` deixa o carregamento muito mais rápido — o módulo completo puxa centenas de comandos que você não vai usar. Liste só o que o script consome.

> Dica: rode `Get-Command -Module Microsoft.Graph.DeviceManagement` para descobrir quais cmdlets vêm em cada submódulo e importar apenas os necessários.

## Fechando a conexão

Depois de validar os módulos, conecte com os escopos mínimos e, ao final, encerre a sessão:

```powershell
Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -NoWelcome
# ... sua lógica aqui ...
Disconnect-MgGraph | Out-Null
```

Pedir só os escopos que o script usa é boa higiene de permissão — e facilita a aprovação quando um app registration precisa de consentimento.
