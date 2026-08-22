---
titulo: "Qual app é o broker de MAM no iOS e no Android?"
resumo: "Uma confusão comum em App Protection Policies: no iOS o broker é o Microsoft Authenticator, no Android é o Company Portal. Entenda por que, e como diagnosticar quando o MAM não dispara."
data: 2026-08-10
autor: EndpointHub
categoria: Troubleshooting
nivel: Intermediário
tags: ["MAM", "iOS", "Android", "App Protection", "Entra"]
lang: pt
slug: "mam-broker-ios-android"
---

Quando uma App Protection Policy (MAM sem enrollment) simplesmente não dispara em um dispositivo, o primeiro suspeito costuma ser o **broker** — o app que negocia a identidade e aplica a política. E é aqui que muita gente erra, porque o broker é diferente em cada plataforma.

## O broker por plataforma

No **iOS/iPadOS**, o broker é o **Microsoft Authenticator**. Sem ele instalado, o fluxo de proteção não tem como ancorar a identidade do usuário, e a política não se aplica ao app-alvo (Outlook, Edge, Teams etc.).

No **Android**, o broker é o **Company Portal** — mesmo em cenário MAM puro, em que o dispositivo *não* está enrolado no Intune. O Company Portal não gerencia o device, mas serve de broker de identidade.

> Regra prática: iOS → Authenticator; Android → Company Portal. Trocar um pelo outro na cabeça é o erro nº 1 nesses chamados.

## Diagnóstico em camadas

Quando o MAM não dispara, o problema quase sempre é uma destas três camadas — verifique nesta ordem:

1. **Broker ausente.** O app broker correto não está instalado. Sem ele, nada acontece.
2. **Token velho.** Há um token de sessão antigo em cache que precede a atribuição da política. Fazer sign-out/sign-in no app-alvo força a renovação.
3. **Sem gatilho de autenticação móvel.** A política se aplica na primeira autenticação *dentro do app gerenciado*. Se o usuário nunca reautenticou depois de a política ser atribuída, ela não entra em vigor.

## Passo a passo de verificação

Confirme a atribuição da política ao grupo do usuário no portal do Intune. Verifique se o app-alvo está na lista de apps gerenciados da política. No dispositivo, confirme a presença do broker correto para a plataforma. Peça ao usuário para sair e entrar novamente no app-alvo — isso resolve os casos de token velho e de gatilho ausente de uma vez.

Se após isso a política ainda não aplicar, o próximo passo é olhar os logs de sign-in no Entra para o usuário, filtrando pelo app, e ver se a condição de MAM aparece na avaliação.
