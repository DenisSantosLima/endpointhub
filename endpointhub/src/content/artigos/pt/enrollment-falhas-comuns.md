---
titulo: "As falhas de enrollment mais comuns e como resolvê-las"
resumo: "Um guia de referência das causas recorrentes de falha no enrollment — licença, restrição, join, rede e identidade — organizadas por plataforma, com o primeiro lugar para olhar em cada caso."
data: 2026-08-07
autor: EndpointHub
categoria: Troubleshooting
nivel: Intermediário
tags: ["enrollment", "troubleshooting", "Intune", "Windows", "macOS", "Android"]
lang: pt
slug: "enrollment-falhas-comuns"
---

Enrollment que falha raramente é um mistério — quase sempre cai em um punhado de causas conhecidas. Este é um guia de referência para atacar o problema pela causa mais provável, por plataforma.

## Causas transversais (todas as plataformas)

**Licença ausente.** O usuário precisa de uma licença que inclua Intune. Sem ela, o enrollment é recusado com mensagens genéricas. É o primeiro lugar para olhar — e o mais esquecido.

**Enrollment restriction bloqueando.** Se você restringiu plataformas, versões ou tipo de propriedade, o dispositivo pode estar sendo barrado por design. Confira as restrições atribuídas ao usuário antes de suspeitar de bug.

**Limite de dispositivos atingido.** Se o usuário já registrou o número máximo permitido, o próximo enrollment falha. Aparece como erro genérico, mas a causa é o limite.

## Windows / Autopilot

O suspeito número um é a **Enrollment Status Page** travada num app bloqueante. Depois, problemas de **rede** (endpoints do Intune/Entra/Windows Update inacessíveis por proxy ou filtragem SSL). Em cenário Hybrid Join, a incapacidade de **alcançar um controlador de domínio** durante o provisionamento.

## macOS

O **token do ABM expirado** interrompe todo enrollment via ADE — verifique a data de validade. No enrollment manual, a **aprovação do perfil** não concluída pelo usuário, ou um **keychain de login dessincronizado** bloqueando o registro no Entra de forma silenciosa.

## Android

**App broker ausente** — no Android, o Company Portal precisa estar instalado como broker. Aparelhos ainda no **Device Administrator** descontinuado que não migram para Android Enterprise. E, no Zero-Touch, aparelhos que **não vieram pelo canal autorizado** simplesmente não aparecem no portal.

## O método geral

> Antes de mergulhar em logs, percorra a lista curta: licença, restrição, limite. Só depois vá para as causas específicas da plataforma.

Quando as causas conhecidas não explicam, os logs decidem. No Windows, `mdmdiagnosticstool.exe`. No macOS e Android, os logs do Company Portal e o histórico de enrollment no próprio Intune, em Devices → Enrollment failures, que lista o motivo específico de cada falha recente.
