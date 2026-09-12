// @ts-check
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Correlix documentation portal.
//
// Content lives in ./docs as portable Markdown with a `page_type` in front
// matter (task | concept | reference | index | release). The rules those types
// obey are in STYLE.md, and tests/voice.test.js enforces the mechanical half.
//
// The same build serves two homes:
//   • embedded in the product at same-origin /docs/   (the in-app Help drawer)
//   • standalone at docs.correlix.io with '/'          (DOCS_BASE_URL=/)

const { themes } = require('prism-react-renderer');

const baseUrl = process.env.DOCS_BASE_URL || '/docs/';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Correlix Documentation',
  tagline: 'Install, operate and investigate with Correlix',
  favicon: 'img/favicon.svg',

  url: 'https://docs.correlix.io',
  baseUrl,

  organizationName: 'correlix',
  projectName: 'correlix-docs',

  // A dead link in an administration guide costs an operator their time in the
  // middle of an incident. Both are hard failures.
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',
  onBrokenAnchors: 'warn',

  i18n: { defaultLocale: 'en', locales: ['en'] },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/', // a pure documentation portal: docs are the root
          sidebarPath: require.resolve('./sidebars.js'),
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
      // Dark by default because this portal is also served inside the product's
      // Help drawer, which is dark. A reader's own OS setting still wins.
      colorMode: {
        defaultMode: 'dark',
        respectPrefersColorScheme: true,
      },
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      navbar: {
        // The wordmark is the product's own mark (the eye-as-O), copied from
        // src/frontend/public/brand. No separate title text: the wordmark
        // already says Correlix, and "Correlix Correlix Documentation" is the
        // kind of thing nobody notices until a customer screenshots it.
        title: 'Documentation',
        logo: {
          alt: 'Correlix',
          src: 'img/correlix-wordmark-light.png',
          srcDark: 'img/correlix-wordmark-dark.png',
          width: 122,
          height: 14,
        },
        hideOnScroll: false,
        items: [
          { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Contents' },
          { to: '/getting-started/quickstart', label: 'Quickstart', position: 'right' },
          { to: '/reference/api', label: 'API', position: 'right' },
          { to: '/release-notes/whats-new', label: "What's new", position: 'right' },
        ],
      },
      footer: {
        style: 'light',
        links: [
          {
            title: 'Get started',
            items: [
              { label: 'What Correlix does', to: '/getting-started/overview' },
              { label: 'Core concepts', to: '/getting-started/concepts' },
              { label: 'Onboard your first device', to: '/getting-started/quickstart' },
            ],
          },
          {
            title: 'Deploy and operate',
            items: [
              { label: 'Install on a Linux host', to: '/deploy/install-linux' },
              { label: 'Verify a deployment', to: '/deploy/verify-deployment' },
              { label: 'Upgrade', to: '/deploy/upgrade' },
              { label: 'Onboard devices', to: '/onboard-devices/overview' },
            ],
          },
          {
            title: 'Investigate',
            items: [
              { label: 'How root-cause analysis works', to: '/investigate/rca-explained' },
              { label: 'Protocol diagnostics', to: '/investigate/protocol-diagnostics' },
              { label: 'Iris', to: '/iris-ai/overview' },
              { label: 'BGP operations', to: '/bgp/overview' },
            ],
          },
          {
            title: 'Reference',
            items: [
              { label: 'REST API', to: '/reference/api' },
              { label: 'Feature flags', to: '/reference/feature-flags' },
              { label: 'Glossary', to: '/reference/glossary' },
              { label: 'What an empty result means', to: '/reference/honest-states' },
            ],
          },
        ],
        copyright: `Correlix documentation. Built ${new Date().toISOString().slice(0, 10)}.`,
      },
      prism: {
        theme: themes.github,
        darkTheme: themes.vsDark,
        additionalLanguages: ['bash', 'yaml', 'json', 'ini', 'sql', 'diff'],
      },
      docs: {
        sidebar: { hideable: true, autoCollapseCategories: false },
      },
    }),
};

module.exports = config;
