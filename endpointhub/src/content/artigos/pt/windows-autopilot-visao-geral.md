---
titulo: "Windows Autopilot: visão geral e quando usar cada modo"
resumo: "User-driven, self-deploying, pre-provisioning e Autopilot for existing devices — o que muda entre eles e como escolher o modo certo para cada cenário de enrollment."
data: 2026-08-16
autor: EndpointHub
categoria: Como fazer
nivel: Intermediário
tags: ["Autopilot", "Windows", "enrollment", "Intune", "Entra"]
lang: pt
slug: "windows-autopilot-visao-geral"
---

O Windows Autopilot transforma o provisionamento de máquinas novas: em vez de imagem dourada e reimaginação, o dispositivo sai da caixa, conecta na internet e se configura sozinho a partir das políticas do Intune. Mas "Autopilot" não é um único fluxo — são quatro modos, e escolher errado gera atrito.

## Os quatro modos

**User-driven** é o mais comum. O usuário final liga a máquina, informa as credenciais corporativas, e o Autopilot faz o join no Entra e aplica o perfil. Ideal para entrega direta ao colaborador, inclusive por correio.

**Self-deploying** não pede credenciais de usuário — a máquina se provisiona sozinha, ancorada no TPM do dispositivo. Serve para quiosques, sinalização digital e dispositivos compartilhados sem usuário fixo.

**Pre-provisioning** (antigo White Glove) divide o processo em duas fases: a TI ou o parceiro adianta a parte pesada (apps, políticas) antes de entregar, e o usuário só faz o login final, que fica rápido. Reduz o tempo de espera na mão do usuário.

**Autopilot for existing devices** aplica o fluxo a máquinas que já existem, durante um wipe-and-reload via Configuration Manager ou reinstalação. Útil para migrar frota legada sem tocar fisicamente em cada equipamento.

## Como escolher

> A pergunta central é: quem está na frente da máquina no primeiro boot, e ela tem um usuário fixo?

Se há um usuário e ele mesmo faz o setup, user-driven. Se não há usuário atribuído, self-deploying. Se o tempo de setup na mão do usuário precisa ser curto, pre-provisioning. Se a frota já está em campo e você quer padronizar sem trocar hardware, existing devices.

## Pré-requisitos que não podem faltar

Independente do modo, o dispositivo precisa estar registrado no serviço de Autopilot (via hardware hash ou compra já registrada pelo fornecedor), ter uma licença que cubra Intune e Entra ID P1, e alcançar os endpoints do Microsoft na primeira conexão. Falhas de Autopilot quase sempre voltam a um destes três pontos.
