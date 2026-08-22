import { defineConfig } from 'astro/config';
import react from '@astrojs/react';

// EndpointHub — site estático de ferramentas + artigos sobre Intune/Defender.
// Nenhum backend: tudo roda no navegador; dados do usuário nunca saem da máquina.
export default defineConfig({
  site: 'https://endpointhub.pages.dev', // ajuste para seu domínio final
  integrations: [react()],
  vite: {
    optimizeDeps: {
      include: ['react', 'react-dom', 'react-dom/client'],
    },
  },
});
