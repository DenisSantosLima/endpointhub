---
titulo: "Enrollment restrictions no Intune: controlando o que entra"
resumo: "Restrições de enrollment definem quais plataformas, versões e tipos de propriedade podem se registrar. Como usá-las para bloquear dispositivos indesejados e impor padrões desde a porta de entrada."
data: 2026-08-08
autor: EndpointHub
categoria: Hardening
nivel: Intermediário
tags: ["Intune", "enrollment", "restrictions", "compliance", "hardening"]
lang: pt
slug: "enrollment-restrictions-intune"
---

Nem todo dispositivo deveria conseguir se registrar no seu ambiente. As **enrollment restrictions** do Intune são o filtro de entrada — decidem quais plataformas, versões mínimas e tipos de propriedade têm permissão de enrollment. Configurá-las bem evita que aparelhos fora do padrão entrem e virem passivo de segurança.

## Os dois tipos de restrição

**Device platform restrictions** controlam quais sistemas operacionais podem se registrar e em quais versões mínimas. Você pode, por exemplo, bloquear enrollment de Android abaixo de uma versão, ou impedir totalmente uma plataforma que sua organização não suporta.

**Device limit restrictions** definem quantos dispositivos um único usuário pode registrar. O padrão costuma ser generoso demais — reduzir esse limite evita que uma conta comprometida ou um usuário descuidado inunde o ambiente de dispositivos.

## Bloqueando dispositivos pessoais

Um uso poderoso: bloquear enrollment de dispositivos **pessoais** (personally-owned) para determinadas plataformas, permitindo só os corporativos. Isso força que celulares e tablets pessoais usem o caminho de MAM (proteção só do app) em vez de MDM (gestão do dispositivo inteiro) — respeitando a privacidade do dono e reduzindo seu escopo de gestão.

> A distinção corporate vs. personal no enrollment é o que separa "eu gerencio o aparelho" de "eu protejo só os dados corporativos nele".

## Ordem de avaliação

As restrições têm prioridade. Quando um dispositivo tenta se registrar, o Intune avalia as restrições atribuídas ao usuário na ordem de prioridade e aplica a primeira que casar. Restrições mal ordenadas geram comportamento inesperado — uma restrição permissiva no topo pode anular uma mais restritiva abaixo. Revise a ordem sempre que criar uma nova.

## Restrições como parte do hardening

Enrollment restrictions são frequentemente esquecidas no desenho de segurança, mas são a primeira linha: se um dispositivo fora do padrão nunca consegue entrar, você não precisa remediar depois. Trate-as como parte do baseline de hardening, não como configuração opcional.
