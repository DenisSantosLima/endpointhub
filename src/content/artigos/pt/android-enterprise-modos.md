---
titulo: "Android Enterprise: os modos de enrollment explicados"
resumo: "Fully Managed, Work Profile, Corporate-owned with work profile e Dedicated. Cada modo serve a um cenário — entenda as diferenças de propriedade, privacidade e controle antes de escolher."
data: 2026-08-10
autor: EndpointHub
categoria: Como fazer
nivel: Intermediário
tags: ["Android", "Android Enterprise", "enrollment", "Work Profile", "BYOD"]
lang: pt
slug: "android-enterprise-modos"
---

O Android Enterprise substituiu o antigo Device Administrator e trouxe modos de enrollment que separam com clareza o que é corporativo do que é pessoal. Escolher o modo certo depende de quem é dono do aparelho e de quanto controle versus privacidade o cenário exige.

## Os quatro modos

**Fully Managed (COBO — Corporate Owned, Business Only).** O dispositivo é da empresa e inteiramente gerenciado. Máximo controle, sem espaço pessoal. Para aparelhos de trabalho dedicados.

**Work Profile (BYOD).** O aparelho é do funcionário; cria-se um contêiner de trabalho isolado ao lado do espaço pessoal. A TI gerencia só o contêiner — não vê nem toca no lado pessoal. É o modo da privacidade preservada.

**Corporate-owned with work profile (COPE).** O dispositivo é da empresa, mas o funcionário tem um espaço pessoal dentro de limites. Equilíbrio entre controle corporativo e uso pessoal permitido.

**Dedicated (COSU — Corporate Owned, Single Use).** Aparelhos de propósito único: quiosques, coletores de dados, sinalização. Bloqueados numa função, sem experiência de usuário tradicional.

## Como decidir

> A primeira pergunta é sempre a propriedade: o aparelho é da empresa ou do funcionário?

Se é do funcionário, Work Profile — é o único modo que respeita a privacidade do dono. Se é da empresa e o funcionário usa também no pessoal, COPE. Se é da empresa e é só trabalho, Fully Managed. Se é da empresa e faz uma coisa só, Dedicated.

## O broker de identidade

Um ponto que confunde: no Android, o broker de identidade para o enrollment e para o MAM é o **Company Portal** — diferente do iOS, onde esse papel é do Microsoft Authenticator. Ter o app broker correto instalado é pré-requisito para o fluxo funcionar.

## Fim de linha do Device Administrator

Se você ainda tem dispositivos no antigo modo Device Administrator, saiba que ele está descontinuado. O Google e a Microsoft empurram tudo para o Android Enterprise — planeje a migração dos aparelhos legados antes que percam gestão.
