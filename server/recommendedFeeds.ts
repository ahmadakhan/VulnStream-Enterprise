/** Disabled provider integrations shown on fresh and existing deployments. */
export const RECOMMENDED_FEEDS = [
  {
    id: 'feed-opencve',
    name: 'OpenCVE CVE Enrichment',
    type: 'OPENCVE_API' as const,
    url: 'https://app.opencve.io/api/v2/cves',
    authType: 'BEARER' as const,
    rateLimitPerMin: 30,
    enabled: false,
    vendorSeed: true,
  },
  {
    id: 'feed-vulncheck-kev',
    name: 'VulnCheck Known Exploited Vulnerabilities',
    type: 'VULNCHECK_KEV' as const,
    url: 'https://api.vulncheck.com/v3/index/vulncheck-kev',
    authType: 'BEARER' as const,
    rateLimitPerMin: 60,
    enabled: false,
    vendorSeed: true,
  },
] as const;
