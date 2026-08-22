---
titulo: "Como coletar o hardware hash para o Autopilot"
resumo: "O hardware hash é a identidade do dispositivo no Autopilot. Veja as formas de coletá-lo — PowerShell, OEM, ou Configuration Manager — e como importar em massa no Intune sem erros."
data: 2026-08-14
autor: EndpointHub
categoria: Como fazer
nivel: Básico
tags: ["Autopilot", "Windows", "enrollment", "PowerShell", "hardware hash"]
lang: pt
slug: "windows-autopilot-hash-hardware"
---

Para um dispositivo entrar no Autopilot, o serviço precisa reconhecê-lo — e esse reconhecimento vem do **hardware hash**, uma impressão digital única gerada a partir de componentes da máquina. Sem ele registrado, o Autopilot não sabe que aquele equipamento é seu.

## As três formas de obter o hash

**Pelo OEM ou revendedor.** O cenário ideal: você compra a máquina e o fornecedor já a registra no seu tenant. Zero trabalho de coleta. Vale negociar isso na aquisição.

**Via PowerShell**, para máquinas que você já tem em mãos. O script oficial é o `Get-WindowsAutopilotInfo`:

```powershell
Install-Script -Name Get-WindowsAutopilotInfo -Force
Set-ExecutionPolicy -Scope Process RemoteSigned -Force
Get-WindowsAutopilotInfo -OutputFile .\AutopilotHash.csv
```

Isso gera um CSV com o número de série, o modelo e o hash — pronto para importar.

**Via Configuration Manager**, se você tem SCCM: existe um relatório que coleta o hash das máquinas já gerenciadas, útil para migrar frota legada em lote.

## Importando no Intune

No Intune, vá em Devices → Enrollment → Windows → Windows enrollment → Devices → Import. Envie o CSV. A importação processa em background e pode levar alguns minutos por lote.

> Dica: importe em lotes de até algumas centenas de linhas. CSVs muito grandes de uma vez aumentam a chance de timeout no processamento.

## Erros comuns

O CSV precisa ter exatamente as colunas esperadas (Device Serial Number, Windows Product ID, Hardware Hash) e nada mais. Colunas extras, cabeçalhos renomeados ou codificação errada (salve como UTF-8) fazem a importação falhar silenciosamente. Se um dispositivo não aparecer após a importação, confira se o hash não foi truncado — ele é longo e ferramentas de planilha às vezes o cortam.
