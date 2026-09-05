// @ts-check
// The documentation sidebar is declared EXPLICITLY rather than generated from
// the folder tree.
//
// Why: a page's place in the navigation has to be free to change without
// changing its URL. Ten page paths are load-bearing outside this portal —
// src/backend/ai/docs_index_test.go asserts that specific questions retrieve
// specific slugs, and src/backend/ai/docs_corpus/ mirrors these files
// byte-for-byte so Iris can cite them. Declaring the order here lets the reader
// see a coherent structure while those paths stay put.
//
// Adding a page means adding it here AND running scripts/sync-docs-corpus.sh.

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'intro',

    {
      type: 'category',
      label: 'Get started',
      collapsed: false,
      items: [
        'getting-started/overview',
        'getting-started/concepts',
        'getting-started/quickstart',
      ],
    },

    {
      type: 'category',
      label: 'Deploy',
      link: { type: 'doc', id: 'deploy/overview' },
      items: [
        'deploy/requirements',
        'deploy/sizing',
        'deploy/reference-capacity',
        'deploy/install-linux',
        'deploy/install-air-gapped',
        'deploy/enable-tls',
        'deploy/optional-modules',
        'deploy/verify-deployment',
        'deploy/upgrade',
        'deploy/back-up-and-restore',
        'deploy/manage-snapshots',
        'deploy/third-party-components',
      ],
    },

    {
      type: 'category',
      label: 'Operate',
      items: [
        {
          type: 'category',
          label: 'Operator guide',
          link: { type: 'doc', id: 'noc-guide/overview' },
          items: [
            'noc-guide/where-to-start',
            'noc-guide/reading-logs',
            'noc-guide/from-signal-to-ticket',
          ],
        },
        {
          type: 'category',
          label: 'Onboard devices',
          link: { type: 'doc', id: 'onboard-devices/overview' },
          items: [
            'onboard-devices/supported-devices',
            'onboard-devices/snmp-profiles',
            'onboard-devices/vendor-snmp-configs',
            'onboard-devices/snmp-discovery',
            'onboard-devices/add-devices-manually',
            'onboard-devices/streaming-gnmi',
            'onboard-devices/data-sources',
            'onboard-devices/verify-monitoring',
          ],
        },
        {
          type: 'category',
          label: 'Send data',
          link: { type: 'doc', id: 'send-data/overview' },
          items: [
            'send-data/metrics',
            'send-data/syslog',
            'send-data/traps',
            'send-data/flows',
            'send-data/debug-the-pipeline',
          ],
        },
        {
          type: 'category',
          label: 'Monitoring and alerting',
          link: { type: 'doc', id: 'monitoring/overview' },
          items: [
            'monitoring/create-a-monitor',
            'monitoring/manage-alerts',
            'monitoring/maintenance-windows',
            'monitoring/link-quality',
            'monitoring/host-monitoring',
          ],
        },
        {
          type: 'category',
          label: 'Incidents',
          link: { type: 'doc', id: 'incidents/overview' },
          items: [
            'incidents/reading-an-incident',
            'incidents/working-incidents',
            'incidents/anomalies-and-correlations',
          ],
        },
        {
          type: 'category',
          label: 'Incident response',
          link: { type: 'doc', id: 'incident-response/overview' },
          items: [
            'incident-response/notifications',
            'incident-response/integrations',
            'incident-response/rca-ticketing',
            'incident-response/rca-time-intelligence',
          ],
        },
        {
          type: 'category',
          label: 'Infrastructure',
          link: { type: 'doc', id: 'infrastructure/overview' },
          items: [
            'infrastructure/devices',
            'infrastructure/interfaces-and-optics',
            'infrastructure/topology-canvas',
            'infrastructure/geomap',
            'infrastructure/paths-and-tunnels',
            'infrastructure/wan-interface-metrics',
            'infrastructure/wireless',
            'infrastructure/nms-integrations',
          ],
        },
        {
          type: 'category',
          label: 'Explore your data',
          link: { type: 'doc', id: 'explore/overview' },
          items: [
            'explore/metrics',
            'explore/logs',
            'explore/flows',
            'explore/events',
          ],
        },
        {
          type: 'category',
          label: 'Automation and source of truth',
          link: { type: 'doc', id: 'automation/overview' },
          items: [
            'automation/sites-and-inventory',
            'automation/import-and-sync',
          ],
        },
        {
          type: 'category',
          label: 'Dashboards and reports',
          link: { type: 'doc', id: 'dashboards-reports/overview' },
          items: [
            'dashboards-reports/built-in-dashboards',
            'dashboards-reports/reports',
          ],
        },
      ],
    },

    {
      type: 'category',
      label: 'Investigate',
      link: { type: 'doc', id: 'investigate/overview' },
      items: [
        'investigate/rca-explained',
        'investigate/read-an-rca-case',
        'investigate/rate-an-rca-case',
        'investigate/investigate-a-symptom',
        'investigate/protocol-diagnostics',
        'investigate/collect-from-a-device',
        'investigate/send-to-tac',
        'investigate/igp-health',
        'investigate/interfaces-by-routing-instance',
        {
          type: 'category',
          label: 'Iris',
          link: { type: 'doc', id: 'iris-ai/overview' },
          items: [
            'iris-ai/setup',
            'iris-ai/ask-iris',
            'iris-ai/skills',
            'iris-ai/memory',
          ],
        },
      ],
    },

    {
      type: 'category',
      label: 'Security',
      link: { type: 'doc', id: 'security/overview' },
      items: [
        'security/ctem',
        'security/run-a-scan',
        'security/investigate-a-finding',
        'security/exposures',
        'security/exposure-stories',
        'security/compliance',
        'security/detection-rules',
        'security/threat-detection',
        'security/vulnerabilities',
        'security/saved-views',
        'security/config-backup',
        'security/config-drift',
        'security/packet-capture',
        'security/transport-security',
        'security/architecture',
      ],
    },

    {
      type: 'category',
      label: 'BGP operations',
      link: { type: 'doc', id: 'bgp/overview' },
      items: [
        'bgp/watchlist',
        'bgp/investigate-a-prefix',
        'bgp/rpki',
        'bgp/as-paths',
        'bgp/geofeed',
        'bgp/alerting',
        'bgp/bogons',
        'bgp/bmp',
      ],
    },

    {
      type: 'category',
      label: 'Administration',
      link: { type: 'doc', id: 'administration/overview' },
      items: [
        'administration/identity-access',
        'administration/tenants-orgs',
        'administration/authentication',
        'administration/okta-sso',
        'administration/api-access',
        'administration/audit-log',
        'administration/regions',
        'administration/system-settings',
        'administration/processors',
        'administration/sensitive-data-access',
        'administration/telemetry-coverage',
        'administration/licence',
      ],
    },

    {
      type: 'category',
      label: 'Reference',
      collapsed: false,
      items: [
        'reference/licensing',
        'reference/api',
        'reference/feature-flags',
        'reference/alert-rules',
        'reference/connectivity-requirements',
        'reference/metrics',
        'reference/glossary',
        'reference/honest-states',
        'reference/troubleshooting',
      ],
    },

    {
      type: 'category',
      label: 'Release notes',
      link: { type: 'doc', id: 'release-notes/whats-new' },
      items: [
        'release-notes/2026-09',
        'release-notes/2026-08',
        'release-notes/2026-07',
      ],
    },
  ],
};

module.exports = sidebars;
