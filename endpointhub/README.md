# EndpointHub

Plataforma pública de ferramentas e conhecimento sobre Microsoft Intune e Defender for Endpoint.

- **Ferramentas** — análises que rodam 100% no navegador. O usuário insere os dados exportados do próprio tenant; nada é enviado ou armazenado.
- **Artigos** — guias práticos, troubleshooting, hardening e automação, escritos em Markdown.

A plataforma é **agnóstica de cliente**: não há nomes de empresa nem dados embutidos.

## Stack
Astro (site estático + SEO) com ilhas React para as ferramentas interativas.

## Rodar em desenvolvimento
```
npm install
npm run dev
```
Abre em http://localhost:4321

## Build de produção
```
npm run build
```
Saída estática em `dist/` — publicável em Cloudflare Pages, Netlify, etc.

## Escrever um artigo
Crie um arquivo `.md` em `src/content/artigos/` com o frontmatter:
```
---
titulo: "..."
resumo: "..."
data: 2026-08-18
categoria: Como fazer | Troubleshooting | Hardening | PowerShell / Graph
nivel: Básico | Intermediário | Avançado
tags: ["...", "..."]
---
Conteúdo em Markdown aqui.
```
O build valida os campos automaticamente. Use `rascunho: true` para não publicar ainda.

## Adicionar uma ferramenta
Crie o componente React em `src/components/` e uma página em
`src/pages/ferramentas/<nome>.astro` que o hidrate com `client:only="react"`.
