/* ============================================================
   Log Analyser — Knowledge Base de Códigos de Erro Conhecidos
   Cada chave é o código EXATO como aparece no log (hex ou decimal).
   Usado pelo LogAnalyser.jsx para enriquecer linhas de erro
   detectadas com causa provável e correção sugerida.

   Estrutura:
   {
     source: string        — 'intune-win32' | 'msi' | 'wu' | 'mde' | 'mdm' | 'generic'
     title: string         — nome curto do erro
     cause: string         — causa mais comum
     fix: string           — o que verificar/fazer
   }
   ============================================================ */

export const ERROR_CODES = {

  "0x87D1041C": {
    source: "intune-win32",
    title: "Timeout aguardando instalação do Win32 app",
    cause: "O instalador excedeu o tempo máximo configurado no Intune (padrão 60 min) sem retornar. Comum em pacotes grandes, instaladores que abrem UI interativa, ou dependência de rede lenta para baixar componentes adicionais.",
    fix: "Verifique se o instalador roda silenciosamente (sem prompt de UI) e aumente o 'Installation time required' nas propriedades avançadas do app no Intune. Teste a instalação manual com os mesmos parâmetros silenciosos usados no app.",
  },
  "0x87D13B66": {
    source: "intune-win32",
    title: "Falha nos requirement rules ou detection rules",
    cause: "O Intune avaliou as regras de requisito (requirement rules) ou detecção (detection rules) e o resultado não bateu com o esperado após a instalação.",
    fix: "Revise a detection rule (arquivo/registry/MSI product code) — confirme que o caminho e a versão batem exatamente com o que o instalador produz. Teste a detection rule manualmente no device.",
  },
  "0x87D1050C": {
    source: "intune-win32",
    title: "Intune Management Extension não encontrou o conteúdo do app",
    cause: "Falha ao baixar o pacote .intunewin do Azure Storage — geralmente proxy/firewall bloqueando o endpoint de download, ou o pacote foi corrompido no upload.",
    fix: "Confirme que o device tem acesso aos endpoints do Intune (*.manage.microsoft.com, *.blob.core.windows.net). Tente re-upload do .intunewin. Verifique o log IntuneManagementExtension.log para a URL exata que falhou.",
  },
  "0x87D30060": {
    source: "intune-win32",
    title: "App dependency não instalada",
    cause: "O Win32 app definido como dependência (Application Dependencies) não foi instalado com sucesso antes da tentativa do app principal.",
    fix: "Verifique o status da dependência separadamente. Corrija a instalação da dependência primeiro — o Intune não tenta o app principal até a cadeia de dependências estar OK.",
  },
  "1603": {
    source: "msi",
    title: "Fatal error durante instalação MSI (genérico)",
    cause: "Erro genérico do Windows Installer — pode ser permissão insuficiente, arquivo em uso, espaço em disco, ou uma ação customizada (custom action) do MSI falhando internamente.",
    fix: "Rode o MSI manualmente com log verboso: `msiexec /i pacote.msi /l*v install.log` e procure a linha 'Return Value 3' no log gerado para achar a ação real que falhou.",
  },
  "1618": {
    source: "msi",
    title: "Outra instalação já em andamento",
    cause: "O Windows Installer está ocupado com outra instalação/desinstalação simultânea (mutex bloqueado).",
    fix: "Normalmente resolve sozinho no retry automático do Intune. Se persistir, verifique se há outro processo msiexec travado no Task Manager do device.",
  },
  "1633": {
    source: "msi",
    title: "Plataforma do pacote não suportada",
    cause: "Tentativa de instalar um MSI x86 em contexto que espera x64 (ou vice-versa), ou arquitetura do pacote incompatível com o device.",
    fix: "Confirme a arquitetura do instalador e ajuste a configuração 'Install behavior' (System/User) e o pacote correto para a arquitetura do device alvo.",
  },
  "0x80070002": {
    source: "generic",
    title: "Arquivo não encontrado",
    cause: "O processo tentou acessar um caminho de arquivo que não existe — comum em scripts com caminho hardcoded, ou origem de conteúdo removida/corrompida.",
    fix: "Confirme se o caminho referenciado no log realmente existe no device. Em Proactive Remediations, valide o caminho do script; em Win32 apps, valide o instalador.",
  },
  "0x80070005": {
    source: "generic",
    title: "Acesso negado",
    cause: "O processo não tinha permissão suficiente para executar a ação — comum quando um script/instalador precisa rodar como SYSTEM mas está configurado para rodar como usuário logado, ou há um UAC/AppLocker bloqueando.",
    fix: "Verifique o contexto de execução (System vs. User) do script ou app no Intune. Confira políticas de AppLocker/WDAC e antivírus que possam estar bloqueando o executável.",
  },
  "0x8007000E": {
    source: "generic",
    title: "Memória ou recursos insuficientes",
    cause: "O processo não conseguiu alocar memória — geralmente em devices com poucos recursos ou muitos processos concorrentes durante o ESP (Enrollment Status Page).",
    fix: "Verifique a carga de CPU/memória do device durante a instalação. Em ambientes de provisionamento em massa, evite empilhar muitos apps síncronos no mesmo momento do ESP.",
  },
  "0x8024200D": {
    source: "wu",
    title: "Windows Update — falha genérica ao baixar",
    cause: "Falha de download de uma atualização — geralmente conectividade instável com os endpoints do Windows Update ou WSUS/Delivery Optimization mal configurado.",
    fix: "Verifique conectividade com *.update.microsoft.com e *.delivery.mp.microsoft.com. Rode `Get-WindowsUpdateLog` ou revise o Update compliance no Intune para esse device.",
  },
  "0x80240438": {
    source: "wu",
    title: "Atualização não aplicável a este device",
    cause: "O Windows Update Agent determinou que a atualização não se aplica à build/edição atual do device — comum quando o feature update já foi superado por outro ou o hardware não é compatível.",
    fix: "Confirme a build atual do device (`winver`) e compare com o Feature Update Profile no Intune. Geralmente não requer ação — é esperado quando o device já está atualizado.",
  },
  "0x800705B4": {
    source: "wu",
    title: "Timeout no Windows Update",
    cause: "A operação de update excedeu o tempo limite — comum em conexões lentas ou quando o serviço Windows Update está travado.",
    fix: "Reinicie o serviço wuauserv (`Restart-Service wuauserv`) e tente novamente. Se recorrente em vários devices, investigue a rede/proxy até os endpoints de Delivery Optimization.",
  },
  "0x80070490": {
    source: "mde",
    title: "Elemento não encontrado — sensor MDE",
    cause: "O serviço Sense (Defender for Endpoint) não encontrou uma configuração ou chave esperada — comum logo após onboarding incompleto ou conflito com outro AV third-party ainda ativo.",
    fix: "Rode `MpCmdRun.exe -GetFiles` para coletar diagnóstico do sensor. Confirme que não há outro antivírus ativo em modo não-passivo e refaça o onboarding se necessário.",
  },
  "0x800106BA": {
    source: "mde",
    title: "Serviço Sense não está respondendo",
    cause: "O serviço WinDefend/Sense está parado, travado ou foi bloqueado por GPO/Tamper Protection mal configurado.",
    fix: "Verifique o status do serviço: `Get-Service WinDefend, Sense`. Confirme que o Tamper Protection está habilitado (não desabilitado indevidamente) e que não há GPO conflitante desativando o Defender.",
  },
  "0xC0000409": {
    source: "generic",
    title: "STATUS_STACK_BUFFER_OVERRUN",
    cause: "Crash de aplicação por estouro de buffer — geralmente aponta para um binário corrompido, incompatível com a arquitetura do SO, ou uma versão desatualizada com bug conhecido.",
    fix: "Atualize o aplicativo para a versão mais recente do fabricante. Se for recorrente, colete o dump de crash (Event Viewer → Windows Logs → Application) para análise mais profunda.",
  },

};

/* Extrai o primeiro código de erro reconhecível de uma string de log
   (hex de 8 dígitos tipo 0x87D1041C, ou decimal isolado tipo 1603) */
export function extractErrorCode(text) {
  if (!text) return null;
  const hex = text.match(/0x[0-9A-Fa-f]{8}/);
  if (hex) return hex[0].toUpperCase().replace("0X", "0x");
  const dec = text.match(/\b(1603|1618|1633|1601|1602|1619|1620|1621|1622|1623|1624|1625)\b/);
  if (dec) return dec[1];
  return null;
}

/* Retorna o guia para um código, ou null se não catalogado */
export function getErrorInfo(code) {
  if (!code) return null;
  return ERROR_CODES[code] || null;
}

export const ERROR_CODE_NAMES = new Set(Object.keys(ERROR_CODES));
