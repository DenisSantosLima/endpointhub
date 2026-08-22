// Dicionário de UI. Cada idioma tem as mesmas chaves.
// Artigos NÃO ficam aqui — são conteúdo, tratado por pasta de idioma.

export const LANGS = ['pt', 'en', 'es'] as const;
export type Lang = (typeof LANGS)[number];
export const DEFAULT_LANG: Lang = 'pt';

export const LANG_LABEL: Record<Lang, string> = { pt: 'PT', en: 'EN', es: 'ES' };
export const LANG_NAME: Record<Lang, string> = { pt: 'Português', en: 'English', es: 'Español' };

export const ui = {
  pt: {
    'nav.inicio': 'Início',
    'nav.ferramentas': 'Ferramentas',
    'nav.artigos': 'Artigos',
    'footer.tagline': 'EndpointHub — ferramentas e conhecimento de endpoint management.',
    'footer.privacy': 'Processamento 100% local · nenhum dado é enviado.',

    'home.eyebrow': 'Endpoint management · Intune & Defender',
    'home.h1': 'Ferramentas e conhecimento para quem administra endpoints.',
    'home.lead': 'Insira os dados exportados do seu tenant e faça os cruzamentos na hora — sem instalar nada, sem enviar dado para servidor. E aprenda a fazer as coisas com guias práticos.',
    'home.cta.tools': 'Ver ferramentas',
    'home.cta.articles': 'Ler artigos',
    'home.tools': 'Ferramentas',
    'home.latest': 'Últimos artigos',

    'tools.eyebrow': 'Ferramentas',
    'tools.h1': 'Análises que rodam no seu navegador',
    'tools.lead': 'Cada ferramenta recebe os arquivos que você exporta do seu próprio tenant, processa localmente e mostra o resultado. Nenhum dado é enviado ou armazenado.',
    'tools.ready': 'Pronto',
    'tools.soon': 'Em breve',

    'articles.eyebrow': 'Artigos',
    'articles.h1': 'Guias e how-to de Intune & Defender',
    'articles.lead': 'Conteúdo prático para administrar, proteger e automatizar endpoints. Sem enrolação — passo a passo, comandos e casos reais.',
    'articles.all': 'Todos',
    'articles.empty': 'Nenhum artigo publicado ainda neste idioma.',
    'articles.back': '← Todos os artigos',
    'articles.notInLang': 'Este artigo ainda não está disponível neste idioma.',
    'articles.readIn': 'Ler em',

    't.saneamento.nome': 'Saneamento de bases',
    't.saneamento.desc': 'Cruza Intune × Defender × Entra × inventário (CMDB). Mostra estoque ainda gerenciado, órfãos em cada base e objetos duplicados. Cruzamento por serial e por AAD Object ID.',
    't.cobertura.nome': 'Cobertura da frota',
    't.cobertura.desc': 'Equipamentos "em uso" no inventário que estão fora do Intune e/ou Defender — o inverso do saneamento. Superfície ativa sem gestão.',
    't.duplicatas.nome': 'Duplicatas no Entra',
    't.duplicatas.desc': 'Agrupa objetos de dispositivo por nome e sinaliza os repetidos, indicando qual é o gerenciado e qual é candidato a exclusão.',
    't.scripts.nome': 'Gerador de scripts',
    't.scripts.desc': 'A partir dos CSVs, gera comandos de offboarding (Intune Retire+Delete, MDE offboard, exclusão de objeto no Entra) via Graph/MDE.',
    't.analytics.nome': 'Endpoint Analytics',
    't.analytics.desc': 'Painel de análise do Intune: dispositivos, conformidade, configuração, sistemas operacionais, aplicativos e Windows Update. A partir do export de dispositivos.',
  },
  en: {
    'nav.inicio': 'Home',
    'nav.ferramentas': 'Tools',
    'nav.artigos': 'Articles',
    'footer.tagline': 'EndpointHub — endpoint management tools and knowledge.',
    'footer.privacy': '100% local processing · no data is ever sent.',

    'home.eyebrow': 'Endpoint management · Intune & Defender',
    'home.h1': 'Tools and knowledge for endpoint administrators.',
    'home.lead': 'Load the data you export from your own tenant and run the cross-checks instantly — nothing to install, no data sent to any server. And learn how to do things with practical guides.',
    'home.cta.tools': 'Browse tools',
    'home.cta.articles': 'Read articles',
    'home.tools': 'Tools',
    'home.latest': 'Latest articles',

    'tools.eyebrow': 'Tools',
    'tools.h1': 'Analyses that run in your browser',
    'tools.lead': 'Each tool takes the files you export from your own tenant, processes them locally, and shows the result. No data is sent or stored.',
    'tools.ready': 'Ready',
    'tools.soon': 'Soon',

    'articles.eyebrow': 'Articles',
    'articles.h1': 'Intune & Defender guides and how-tos',
    'articles.lead': 'Practical content to manage, secure, and automate endpoints. No fluff — step by step, commands, and real cases.',
    'articles.all': 'All',
    'articles.empty': 'No articles published in this language yet.',
    'articles.back': '← All articles',
    'articles.notInLang': 'This article is not available in this language yet.',
    'articles.readIn': 'Read in',

    't.saneamento.nome': 'Base reconciliation',
    't.saneamento.desc': 'Cross-checks Intune × Defender × Entra × inventory (CMDB). Surfaces stock still managed, orphans in each base, and duplicate objects. Matched by serial and by AAD Object ID.',
    't.cobertura.nome': 'Fleet coverage',
    't.cobertura.desc': 'Devices marked "in use" in inventory but missing from Intune and/or Defender — the inverse of reconciliation. Active surface with no management.',
    't.duplicatas.nome': 'Entra duplicates',
    't.duplicatas.desc': 'Groups device objects by name and flags duplicates, indicating which is managed and which is a deletion candidate.',
    't.scripts.nome': 'Script generator',
    't.scripts.desc': 'From the CSVs, generates offboarding commands (Intune Retire+Delete, MDE offboard, Entra object deletion) via Graph/MDE.',
    't.analytics.nome': 'Endpoint Analytics',
    't.analytics.desc': 'Intune analytics dashboard: devices, compliance, configuration, operating systems, applications and Windows Update. Built from the device export.',
  },
  es: {
    'nav.inicio': 'Inicio',
    'nav.ferramentas': 'Herramientas',
    'nav.artigos': 'Artículos',
    'footer.tagline': 'EndpointHub — herramientas y conocimiento de endpoint management.',
    'footer.privacy': 'Procesamiento 100% local · ningún dato se envía.',

    'home.eyebrow': 'Endpoint management · Intune & Defender',
    'home.h1': 'Herramientas y conocimiento para quien administra endpoints.',
    'home.lead': 'Carga los datos exportados de tu tenant y haz los cruces al instante — sin instalar nada, sin enviar datos a ningún servidor. Y aprende a hacer las cosas con guías prácticas.',
    'home.cta.tools': 'Ver herramientas',
    'home.cta.articles': 'Leer artículos',
    'home.tools': 'Herramientas',
    'home.latest': 'Últimos artículos',

    'tools.eyebrow': 'Herramientas',
    'tools.h1': 'Análisis que corren en tu navegador',
    'tools.lead': 'Cada herramienta recibe los archivos que exportas de tu propio tenant, los procesa localmente y muestra el resultado. Ningún dato se envía ni se almacena.',
    'tools.ready': 'Listo',
    'tools.soon': 'Pronto',

    'articles.eyebrow': 'Artículos',
    'articles.h1': 'Guías y how-to de Intune & Defender',
    'articles.lead': 'Contenido práctico para administrar, proteger y automatizar endpoints. Sin rodeos — paso a paso, comandos y casos reales.',
    'articles.all': 'Todos',
    'articles.empty': 'Aún no hay artículos publicados en este idioma.',
    'articles.back': '← Todos los artículos',
    'articles.notInLang': 'Este artículo aún no está disponible en este idioma.',
    'articles.readIn': 'Leer en',

    't.saneamento.nome': 'Saneamiento de bases',
    't.saneamento.desc': 'Cruza Intune × Defender × Entra × inventario (CMDB). Muestra stock aún gestionado, huérfanos en cada base y objetos duplicados. Cruce por serial y por AAD Object ID.',
    't.cobertura.nome': 'Cobertura de la flota',
    't.cobertura.desc': 'Equipos "en uso" en el inventario que están fuera de Intune y/o Defender — lo inverso del saneamiento. Superficie activa sin gestión.',
    't.duplicatas.nome': 'Duplicados en Entra',
    't.duplicatas.desc': 'Agrupa objetos de dispositivo por nombre y marca los repetidos, indicando cuál es el gestionado y cuál es candidato a eliminación.',
    't.scripts.nome': 'Generador de scripts',
    't.scripts.desc': 'A partir de los CSV, genera comandos de offboarding (Intune Retire+Delete, MDE offboard, eliminación de objeto en Entra) vía Graph/MDE.',
    't.analytics.nome': 'Endpoint Analytics',
    't.analytics.desc': 'Panel de análisis de Intune: dispositivos, cumplimiento, configuración, sistemas operativos, aplicaciones y Windows Update. A partir del export de dispositivos.',
  },
} as const;

export function useTranslations(lang: Lang) {
  return function t(key: keyof (typeof ui)['pt']): string {
    return (ui[lang] as any)[key] ?? (ui.pt as any)[key] ?? key;
  };
}

// Extrai o idioma do início do pathname; default = pt (sem prefixo).
export function langFromUrl(url: URL): Lang {
  const seg = url.pathname.split('/').filter(Boolean)[0];
  if (seg === 'en' || seg === 'es') return seg;
  return 'pt';
}

// Gera o href de uma rota para um idioma. pt = sem prefixo; en/es = /en, /es.
export function localizedPath(path: string, lang: Lang): string {
  const clean = path.replace(/^\/(en|es)(?=\/|$)/, '') || '/';
  if (lang === 'pt') return clean;
  return `/${lang}${clean === '/' ? '' : clean}`;
}
