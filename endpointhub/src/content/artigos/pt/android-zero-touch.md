---
titulo: "Android Zero-Touch Enrollment: provisionamento sem toque"
resumo: "O equivalente Android do Autopilot e do ADE. Como o Zero-Touch registra aparelhos corporativos automaticamente na primeira inicialização, e o que configurar no portal e no Intune."
data: 2026-08-09
autor: EndpointHub
categoria: Como fazer
nivel: Avançado
tags: ["Android", "Zero-Touch", "enrollment", "Android Enterprise", "Intune"]
lang: pt
slug: "android-zero-touch"
---

O Zero-Touch Enrollment é a resposta do Android ao provisionamento sem intervenção — o mesmo espírito do Autopilot no Windows e do ADE no macOS. Aparelhos comprados pelos canais habilitados chegam já destinados à sua organização e se registram sozinhos no primeiro boot, sem QR code, sem NFC, sem toque manual.

## Como funciona a cadeia

O fluxo depende de três peças conectadas. O **portal Zero-Touch** (gerenciado pelo revendedor ou pela sua organização) é onde os aparelhos comprados aparecem. A **configuração** vincula esses aparelhos ao seu EMM — no caso, o Intune. E o **aparelho**, ao ser ligado e conectado à internet, consulta o portal, descobre que pertence à sua organização e inicia o enrollment automaticamente.

## Requisitos

O aparelho precisa ter sido comprado de um revendedor autorizado que participe do programa Zero-Touch — não é qualquer varejo. Precisa também ser um modelo compatível (a maioria dos aparelhos corporativos Android recentes é). E sua conta corporativa do Google precisa estar vinculada ao portal Zero-Touch.

## Configuração no lado do Intune

No Intune, você configura um perfil de enrollment para Android Enterprise (tipicamente Fully Managed ou Dedicated, já que Zero-Touch é para dispositivos corporativos). Esse perfil define o que o aparelho recebe ao se registrar. No portal Zero-Touch, você associa a configuração ao seu EMM apontando para o token do Intune.

> Zero-Touch e Fully Managed andam juntos: o Zero-Touch é o mecanismo de entrega; o Fully Managed é o modo de gestão que ele aplica.

## Quando usar em vez de outros métodos

Para volume corporativo, Zero-Touch é imbatível — você provisiona centenas de aparelhos sem tocar em nenhum. Para poucos aparelhos ou aparelhos que não vieram pelo canal certo, os métodos manuais (QR code, token do Google, afiliação de conta) resolvem, mas exigem interação física. Zero-Touch é o caminho de escala.
