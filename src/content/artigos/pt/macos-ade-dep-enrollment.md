---
titulo: "Enrollment de macOS via ADE (Automated Device Enrollment)"
resumo: "O equivalente Apple do Autopilot. Como conectar o Apple Business Manager ao Intune, criar o perfil de enrollment e provisionar Macs de forma automatizada e supervisionada."
data: 2026-08-12
autor: EndpointHub
categoria: Como fazer
nivel: Intermediário
tags: ["macOS", "ADE", "DEP", "Apple Business Manager", "enrollment"]
lang: pt
slug: "macos-ade-dep-enrollment"
---

O Automated Device Enrollment (ADE, antigo DEP) é o caminho da Apple para provisionar Macs corporativos automaticamente — o análogo do Autopilot no mundo Windows. Um Mac comprado pelos canais corretos aparece no seu ambiente já destinado à gestão, sem intervenção manual.

## A cadeia de confiança

O ADE depende de uma cadeia de três elos que precisam estar conectados:

O **Apple Business Manager** (ou School Manager) é onde a Apple registra os dispositivos que sua organização comprou. O **token de servidor MDM** conecta o ABM ao Intune. E o **perfil de enrollment** define o que acontece quando o Mac é ligado pela primeira vez.

## Passo a passo da conexão

Primeiro, no Intune, você baixa uma chave pública e a usa no ABM para gerar um token de servidor MDM. Esse token, carregado de volta no Intune, estabelece a ponte. Ele expira anualmente — anote a data de renovação, porque um token vencido interrompe todo o enrollment de Macs novos.

Com o ABM conectado, você atribui os dispositivos comprados ao servidor MDM do Intune e cria um **perfil de enrollment** que define a experiência do Setup Assistant: quais telas pular, se o dispositivo será supervisionado, e se o enrollment é obrigatório e não removível.

## Supervisão e bloqueio de remoção

> Para dispositivos corporativos, marque o enrollment como supervisionado e não removível. Isso impede que o usuário simplesmente saia da gestão.

A supervisão via ADE desbloqueia controles que o enrollment manual não oferece — restrições mais profundas, controle de apps do sistema e a capacidade de aplicar certas políticas de segurança. É a diferença entre um Mac corporativo de verdade e um dispositivo apenas "registrado".

## Platform SSO e Secure Enclave

No fluxo moderno de ADE, vale planejar o Platform SSO com Secure Enclave para o logon — ele integra a identidade do Entra ao login do macOS de forma segura, ancorada no hardware. É um tópico à parte, mas a decisão de habilitá-lo se toma já no desenho do perfil de enrollment.
