import { createHash } from 'node:crypto';
import { existsSync, realpathSync, statSync } from 'node:fs';
import puppeteer from 'puppeteer-core';
import type { Browser, Page } from 'puppeteer-core';
import type { Config } from './config';

const PDF_CACHE_TTL_MS = 5 * 60_000;
const PDF_CACHE_MAX = 64;
const COMMON_CHROME_PATHS = [
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/local/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
];

const pdfCache = new Map<string, { content: Uint8Array; expires: number }>();
let cacheAccess = 0;
const browserCache = new Map<string, Promise<Browser>>();

export function resolveChromeExecutablePath(config?: Config): string | undefined {
  const configured = config?.CHROME_EXECUTABLE_PATH || process.env.CHROME_EXECUTABLE_PATH;
  // The value becomes a spawned process, so it is accepted only as an absolute
  // path to an existing executable file; a directory, a relative name resolved
  // through PATH, or an empty string is treated as "no Chrome configured".
  const executable = (candidate: string | undefined) => {
    if (!candidate || !candidate.startsWith('/')) return undefined;
    try {
      // realpathSync throws for a missing path and resolves a symlink to its
      // target, so a directory can be rejected by asking for its stats here.
      const resolved = realpathSync(candidate);
      return statSync(resolved).isFile() ? resolved : undefined;
    } catch {
      return undefined;
    }
  };
  return executable(configured) ?? COMMON_CHROME_PATHS.map(executable).find(Boolean);
}

export interface PdfAttachment {
  filename: string;
  content: Uint8Array;
  contentType: 'application/pdf';
}

export function advisoryFilename(advisoryId: string): string {
  const match = advisoryId.match(/^ADV-\d{1,2}[A-Z][a-z]{2}\d{4}/);
  return `${match ? match[0] : advisoryId.replace(/[^A-Za-z0-9._-]/g, '_')}.pdf`;
}

export async function renderAdvisoryPdf(html: string, config?: Config): Promise<Uint8Array> {
  const key = createHash('sha1').update(html).digest('hex');
  const cached = pdfCache.get(key);
  if (cached && cached.expires > Date.now()) return cached.content;

  const executablePath = resolveChromeExecutablePath(config);
  if (!executablePath) throw new Error('No Chrome executable available for PDF rendering');

  const launchKey = executablePath;
  let browserPromise = browserCache.get(launchKey);
  if (!browserPromise) {
    browserPromise = puppeteer.launch({
      executablePath,
      // puppeteer-core 23+ selects Chrome's new headless mode with `true`.
      // The removed 'new' string fails the type check and the launch option.
      headless: true,
      // Deliberately no --no-sandbox: Chrome renders operator-visible advisory
      // HTML, and the container's seccomp profile supports Chrome's own
      // sandbox. If a host cannot run it, disable ATTACH_ADVISORY_PDF rather
      // than removing the sandbox of a browser rendering untrusted content.
      args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--hide-scrollbars',
        '--no-first-run',
        '--no-default-browser-check',
      ],
      timeout: 15000,
    });
    browserCache.set(launchKey, browserPromise);
  }

  const browser = await browserPromise;
  let page: Page | undefined;
  try {
    page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.setContent(html, { waitUntil: 'load' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '12mm', right: '8mm', bottom: '12mm', left: '8mm' },
    });
    const content = Buffer.isBuffer(pdf) ? new Uint8Array(pdf) : new Uint8Array(pdf);
    pdfCache.set(key, { content, expires: Date.now() + PDF_CACHE_TTL_MS });
    if (++cacheAccess > PDF_CACHE_MAX * 2) evictPdfCache();
    return content;
  } finally {
    try {
      if (page) await page.close();
    } catch {
      void 0;
    }
  }
}

function evictPdfCache(): void {
  const now = Date.now();
  cacheAccess = 0;
  for (const [k, v] of pdfCache) if (v.expires < now) pdfCache.delete(k);
  while (pdfCache.size > PDF_CACHE_MAX) {
    const first = pdfCache.keys().next().value;
    if (first === undefined) break;
    pdfCache.delete(first);
  }
}

export async function closePdfRenderer(): Promise<void> {
  for (const promise of browserCache.values()) {
    try {
      (await promise).close();
    } catch {
      void 0;
    }
  }
  browserCache.clear();
  pdfCache.clear();
}
