import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

// Gera um índice de busca (metadados) de todos os artigos publicados,
// para os três idiomas. Consumido no cliente pelo modal de busca.
export const GET: APIRoute = async () => {
  const artigos = await getCollection('artigos', ({ data }) => !data.rascunho);
  const index = artigos.map((a) => ({
    titulo: a.data.titulo,
    resumo: a.data.resumo,
    categoria: a.data.categoria,
    tags: a.data.tags,
    nivel: a.data.nivel,
    lang: a.data.lang,
    slug: a.data.slug,
  }));
  return new Response(JSON.stringify(index), {
    headers: { 'Content-Type': 'application/json' },
  });
};
