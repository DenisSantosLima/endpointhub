import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

// Artigos multilíngues. Cada .md declara seu idioma (lang) e um slug
// compartilhado entre traduções (mesmo slug em pt/en/es = mesmo artigo).
const artigos = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/artigos' }),
  schema: z.object({
    titulo: z.string(),
    resumo: z.string(),
    data: z.date(),
    autor: z.string().default('EndpointHub'),
    categoria: z.enum(['Como fazer', 'Troubleshooting', 'Hardening', 'PowerShell / Graph']),
    tags: z.array(z.string()).default([]),
    nivel: z.enum(['Básico', 'Intermediário', 'Avançado']).default('Intermediário'),
    lang: z.enum(['pt', 'en', 'es']).default('pt'),
    slug: z.string(),
    rascunho: z.boolean().default(false),
  }),
});

export const collections = { artigos };
