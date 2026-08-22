---
titulo: "Hybrid Entra Join vs. Cloud-only: qual escolher no enrollment"
resumo: "A decisão de join define todo o resto da sua estratégia de endpoint. Entenda as diferenças práticas entre Hybrid Entra Join e Entra Join puro, e por que cloud-only é o caminho recomendado para novos projetos."
data: 2026-08-15
autor: EndpointHub
categoria: Como fazer
nivel: Avançado
tags: ["Entra", "Hybrid Join", "Windows", "enrollment", "Autopilot"]
lang: pt
slug: "windows-hybrid-vs-cloud-join"
---

Antes de configurar qualquer perfil de enrollment, você precisa responder uma pergunta que condiciona tudo depois: o dispositivo será **Hybrid Entra Join** (ingressado tanto no Active Directory local quanto no Entra) ou **Entra Join puro** (só na nuvem)?

## O que cada um significa na prática

No **Hybrid Entra Join**, a máquina continua ingressada no AD on-premises e também é sincronizada para o Entra. Ela depende de linha de visão com um controlador de domínio para operações como logon inicial e aplicação de GPO. É o modelo de transição para quem vem de um ambiente AD tradicional.

No **Entra Join puro** (cloud-only), a máquina existe apenas na nuvem. Sem dependência de controlador de domínio, sem GPO — a gestão é 100% via Intune. É mais simples, mais resiliente e mais rápido de provisionar.

## Por que cloud-only é o recomendado

> Para projetos novos, a Microsoft e a prática de mercado convergem: comece cloud-only, a menos que haja um bloqueador concreto.

O Hybrid Join carrega complexidade real: o Autopilot precisa alcançar um controlador de domínio durante o provisionamento, o que quebra o cenário de "enviar a máquina pelo correio para o home office" — sem VPN ou linha de visão com o DC, o join falha. Além disso, você mantém duas fontes de verdade (AD e Entra) e toda a fricção de sincronização.

Cloud-only elimina isso. O trade-off aparece quando você tem dependências legadas: aplicações que exigem autenticação Kerberos contra recursos on-premises, impressoras ou drives mapeados por caminho de domínio, ou GPOs críticas ainda não migradas para políticas de Intune.

## O caminho de migração

Se você está preso ao Hybrid hoje, o alvo é migrar as dependências uma a uma: GPO → políticas de configuração do Intune; scripts de logon → Proactive Remediations; acesso a recursos on-premises → Cloud Kerberos Trust ou reengenharia para SSO moderno. Conforme cada dependência cai, o cloud-only deixa de ser um risco e vira o padrão.
