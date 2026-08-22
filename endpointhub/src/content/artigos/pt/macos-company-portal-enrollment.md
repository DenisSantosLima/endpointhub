---
titulo: "Enrollment manual de macOS via Company Portal"
resumo: "Quando o Mac não veio pelo ABM, o enrollment é manual via Company Portal. O fluxo passo a passo, os pontos onde costuma falhar, e por que o keychain pode bloquear o registro."
data: 2026-08-11
autor: EndpointHub
categoria: Como fazer
nivel: Intermediário
tags: ["macOS", "Company Portal", "enrollment", "BYOD", "keychain"]
lang: pt
slug: "macos-company-portal-enrollment"
---

Nem todo Mac chega pelo Apple Business Manager. Máquinas compradas no varejo, dispositivos BYOD ou equipamentos antigos precisam do enrollment manual — feito pelo aplicativo Company Portal. O fluxo é direto, mas tem armadilhas específicas do macOS.

## O fluxo básico

O usuário baixa o Company Portal, faz login com a conta corporativa, e o app o guia pela instalação de um perfil de gerenciamento. Diferente do ADE, aqui o usuário participa ativamente e precisa aprovar a instalação do perfil nas Preferências do Sistema — um passo que causa confusão se não for bem comunicado.

## Onde costuma falhar

**Aprovação do perfil.** No macOS, instalar um perfil de MDM exige que o usuário vá até Ajustes do Sistema → Gerenciamento de Dispositivos e aprove manualmente. Se ele fechar antes disso, o enrollment fica incompleto — o dispositivo aparece como parcialmente registrado.

**Permissões do Company Portal.** O app precisa de permissões de acessibilidade e de gerenciamento. macOS mais recentes pedem confirmações extras que, se negadas, quebram o fluxo.

## O problema do keychain

> Um sintoma frustrante: o enrollment falha ou a conta não registra, e a causa raiz é um keychain de login dessincronizado.

Quando o keychain de login do usuário está corrompido ou dessincronizado — comum após troca de senha corporativa ou reinstalação — o registro no Entra pode ser bloqueado silenciosamente. O sintoma não aponta para o keychain, o que torna o diagnóstico difícil.

A resolução envolve redefinir o keychain de login, o que recria as credenciais armazenadas do zero. É um procedimento sensível (o usuário perde senhas salvas no keychain antigo), então convém comunicá-lo antes. Depois do reset, o registro no Entra costuma fluir normalmente.

## Depois do enrollment

Vale lembrar que o macOS não suporta Proactive Remediations do Intune. Qualquer verificação ou correção recorrente pós-enrollment precisa ser feita via shell scripts ou launchd — não espere o mesmo ferramental do Windows.
