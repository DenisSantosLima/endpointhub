---
titulo: "Enrollment Status Page travada no Autopilot: como diagnosticar"
resumo: "A ESP é onde a maioria dos enrollments do Autopilot emperra. Um método em camadas para descobrir se o problema é app, política, rede ou timeout — e como configurar a ESP para não travar."
data: 2026-08-13
autor: EndpointHub
categoria: Troubleshooting
nivel: Avançado
tags: ["Autopilot", "Windows", "ESP", "enrollment", "troubleshooting"]
lang: pt
slug: "windows-autopilot-esp-travado"
---

A Enrollment Status Page (ESP) é a tela de progresso que o usuário vê durante o provisionamento do Autopilot. Quando ela trava — parada em "Identifying...", "Installing apps..." ou girando indefinidamente — o enrollment inteiro fica refém. Diagnosticar exige método.

## Entenda o que a ESP está esperando

A ESP bloqueia até que o conjunto de apps e políticas marcados como *bloqueantes* seja aplicado. Se um único app bloqueante falha ou demora além do timeout, a ESP não avança. O primeiro passo é sempre saber **o que** ela está esperando.

## Diagnóstico em camadas

**Camada 1 — app problemático.** A causa mais comum é um app Win32 que falha na instalação ou demora demais. Revise a lista de apps bloqueantes na configuração da ESP: quanto menos apps bloqueantes, menor a chance de travar. Um app que não é crítico para o primeiro logon não deveria ser bloqueante.

**Camada 2 — timeout.** A ESP tem um limite de tempo configurável. Se seus apps são pesados e a rede do usuário é lenta, o timeout padrão pode ser curto. Aumentá-lo dá margem, mas trata o sintoma, não a causa.

**Camada 3 — rede.** O Autopilot precisa alcançar os endpoints do Intune, do Entra e do Windows Update. Redes com proxy agressivo ou filtragem SSL quebram o fluxo. Em cenário Hybrid Join, adiciona-se a necessidade de alcançar um controlador de domínio.

**Camada 4 — logs.** Se as camadas acima não resolvem, os logs contam a história. Colete com:

```powershell
mdmdiagnosticstool.exe -area Autopilot -zip C:\AutopilotLogs.zip
```

O pacote traz o histórico de aplicação de políticas e os erros de cada app.

## Configuração preventiva

> A melhor ESP é a que quase não bloqueia. Marque como bloqueante só o mínimo indispensável para o primeiro uso; deixe o resto instalar em background depois do logon.

Configurar a ESP para permitir o reset e o uso do dispositivo em caso de falha (em vez de travar duro) também melhora a experiência: o usuário não fica preso numa tela morta se algo der errado.
