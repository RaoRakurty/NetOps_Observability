// @ts-check
// Correlix documentation portal — Docusaurus config.
// Content lives in ./docs as portable Markdown (frontmatter: title/description),
// so it can also be lifted into the marketing website as it comes online.

const { themes } = require('prism-react-renderer');

// baseUrl is env-driven so the SAME build serves two homes:
//   • embedded in the product at same-origin /docs/  (default — the in-app "?" Help panel)
//   • standalone at docs.correlix.io with '/'         (build with DOCS_BASE_URL=/)
const baseUrl = process.env.DOCS_BASE_URL || '/docs/';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Correlix Docs',
  tagline: 'Network observability & AI-driven root-cause — product documentation',
  favicon: 'img/favicon.svg',

  // Update these when the docs site domain is finalized.
  url: 'https://docs.correlix.io',
  baseUrl,

  organizationName: 'correlix',
  projectName: 'correlix-docs',

  // Broken links are a docs-quality bug. While the portal is still being filled
  // in we warn (so the build succeeds); tighten to 'throw' once every section is
  // written so a dangling link fails CI.
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  i18n: { defaultLocale: 'en', locales: ['en'] },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/', // docs are the site root (a pure docs portal)
          sidebarPath: require.resolve('./sidebars.js'),
          // "Edit this page" — point at the repo once the docs move to their own repo.
          editUrl: undefined,
          showLastUpdateTime: true,
          breadcrumbs: true,
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/social-card.png',
      // Dark-first to match the product's trading-floor NOC aesthetic; the toggle
      // stays so operators on bright monitors can flip to light.
      colorMode: {
        defaultMode: 'dark',
        respectPrefersColorScheme: true,
      },
      // Compact "on this page" so long how-tos stay scannable.
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      navbar: {
        title: 'Correlix',
        logo: { alt: 'Correlix', src: 'img/logo.svg' },
        hideOnScroll: true,
        items: [
          { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Documentation' },
          { to: '/getting-started/quickstart', label: 'Quickstart', position: 'left' },
          { to: '/onboard-devices/overview', label: 'Onboard Devices', position: 'left' },
          { to: '/iris-ai/overview', label: 'Iris AI', position: 'left' },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Get started',
            items: [
              { label: 'Introduction', to: '/' },
              { label: 'Quickstart', to: '/getting-started/quickstart' },
              { label: 'Onboard network devices', to: '/onboard-devices/overview' },
            ],
          },
          {
            title: 'Product',
            items: [
              { label: 'Monitoring & alerting', to: '/monitoring/overview' },
              { label: 'Incidents & correlation', to: '/incidents/overview' },
              { label: 'Iris AI', to: '/iris-ai/overview' },
            ],
          },
          {
            title: 'Reference',
            items: [
              { label: 'Connectivity requirements', to: '/reference/connectivity-requirements' },
              { label: 'Glossary', to: '/reference/glossary' },
              { label: 'Troubleshooting', to: '/reference/troubleshooting' },
            ],
          },
        ],
        copyright: `Correlix — network observability & AI-driven root-cause. Docs built ${new Date().getFullYear()}.`,
      },
      prism: {
        theme: themes.oneLight,
        darkTheme: themes.oneDark,
        additionalLanguages: ['bash', 'yaml', 'json', 'promql'],
      },
      docs: {
        sidebar: { hideable: true, autoCollapseCategories: true },
      },
    }),
};

module.exports = config;
