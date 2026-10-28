import { test } from 'node:test';
import assert from 'node:assert/strict';
import { searchNvdCpes, loadNvdApiKey, isNvdRateLimitError, nvdRetryAfterSeconds } from '../server/cpeSearch';
import type { RequestOptions, Requester } from '../server/network';
import { loadConfig } from '../server/config';
import { encrypt } from '../server/secrets';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'),
});

test('searchNvdCpes parses verified NVD CPE configurations and forwards the API key', async () => {
  let calledUrl = '';
  let calledOptions: RequestOptions | undefined;
  const requester: Requester = async (url, options) => {
    calledOptions = options;
    calledUrl = url;
    return {
      status: 200,
      body: JSON.stringify({
        totalResults: 3,
        products: [
          {
            cpe: {
              cpeName: 'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
              cpeNameId: 'id-1',
              titles: [{ title: 'Windows 10' }],
            },
          },
          {
            cpe: {
              cpeName: 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:*:*',
              cpeNameId: 'id-2',
            },
          },
          { cpe: { cpeName: 'not-a-cpe', cpeNameId: 'id-3' } },
        ],
      }),
      headers: {},
    };
  };

  const { results, totalResults } = await searchNvdCpes(
    requester,
    'secret-key',
    'microsoft',
    'windows_10',
    50,
  );

  assert.equal(totalResults, 3);
  assert.equal(results.length, 2);
  const url = new URL(calledUrl);
  assert.equal(url.origin + url.pathname, 'https://services.nvd.nist.gov/rest/json/cpes/2.0');
  assert.equal(url.searchParams.has('apiKey'), false, 'API 2.0 rejects API keys in URLs');
  assert.equal(calledOptions?.headers?.apiKey, 'secret-key');
  assert.equal(calledOptions?.sameHostRedirects, true);
  assert.equal(url.searchParams.get('keywordSearch'), 'microsoft windows 10');
  assert.equal(results[0].cpeName, 'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*');
  assert.equal(results[0].part, 'a');
  assert.equal(results[0].vendor, 'microsoft');
  assert.equal(results[0].product, 'windows_10');
  assert.equal(results[0].version, '10.0.19041');
  assert.equal(results[0].targetHw, '*');
  assert.equal(results[0].title, 'Windows 10');
  assert.equal(results[1].part, 'o');
});

test('searchNvdCpes omits the API key and falls back to public rate budget', async () => {
  let calledUrl = '';
  const requester: Requester = async (url) => {
    calledUrl = url;
    return { status: 200, body: JSON.stringify({ totalResults: 0, products: [] }), headers: {} };
  };

  const { results } = await searchNvdCpes(requester, '', 'cisco', 'ios', 20);

  assert.equal(results.length, 0);
  assert.ok(!calledUrl.includes('apiKey='), 'should not append an apiKey when none configured');
  assert.ok(calledUrl.includes('keywordSearch=cisco+ios'));
  assert.ok(calledUrl.includes('resultsPerPage=20'));
});

test('searchNvdCpes surfaces NVD rate-limit errors with retry-after guidance', async () => {
  const requester: Requester = async () => ({
    status: 429,
    body: '',
    headers: { 'retry-after': '45' },
  });

  let thrown: unknown;
  try {
    await searchNvdCpes(requester, '', 'vendor', 'product', 10);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, 'expected searchNvdCpes to reject on NVD 429');
  assert.equal(isNvdRateLimitError(thrown), true);
  assert.equal(nvdRetryAfterSeconds(thrown as never), 45);
});

test('searchNvdCpes throws on non-JSON or unexpected NVD responses', async () => {
  const requester: Requester = async () => ({ status: 200, body: '<html>error page</html>', headers: {} });
  await assert.rejects(searchNvdCpes(requester, '', 'vendor', 'product', 10), /non-JSON/);

  const requester500: Requester = async () => ({ status: 500, body: '', headers: {} });
  await assert.rejects(searchNvdCpes(requester500, '', 'vendor', 'product', 10), /HTTP 500/);
});

test('loadNvdApiKey decrypts the configured NVD feed key', async () => {
  const secret = encrypt('nvd-real-key', config.ENCRYPTION_KEY, 'feed:feed-nvd');
  const db = {
    query: async () => ({
      rows: [
        {
          data: {
            id: 'feed-nvd',
            type: 'NVD_API',
            authType: 'API_KEY',
            enabled: true,
            authSecretKey: secret,
          },
        },
      ],
    }),
  } as unknown as Parameters<typeof loadNvdApiKey>[0];

  assert.equal(await loadNvdApiKey(db, config), 'nvd-real-key');
});

test('loadNvdApiKey returns empty when no NVD key is configured', async () => {
  const db = {
    query: async () => ({
      rows: [
        { data: { id: 'feed-mitre', type: 'MITRE_CVE', authType: 'NONE', enabled: true, authSecretKey: '' } },
      ],
    }),
  } as unknown as Parameters<typeof loadNvdApiKey>[0];

  assert.equal(await loadNvdApiKey(db, config), '');
});

test('an invalid key retries once without credentials using the same CPE query', async () => {
  const calls: { url: string; options: RequestOptions | undefined }[] = [];
  const requester: Requester = async (url, options) => {
    calls.push({ url, options });
    if (calls.length === 1) return { status: 404, body: '', headers: { message: 'Invalid apiKey.' } };
    return { status: 200, body: JSON.stringify({ totalResults: 0, products: [] }), headers: {} };
  };
  assert.deepEqual(
    await searchNvdCpes(requester, 'expired-key', 'Cisco', 'adaptive_security_appliance', 50),
    { results: [], totalResults: 0 },
  );
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, calls[1].url);
  assert.equal(calls[0].options?.headers?.apiKey, 'expired-key');
  assert.equal(calls[1].options?.headers?.apiKey, undefined);
  assert.equal(new URL(calls[0].url).searchParams.get('keywordSearch'), 'Cisco adaptive security appliance');
});

test('a genuine 404 is an upstream error rather than an empty dictionary result', async () => {
  for (const apiKey of ['', 'configured-key']) {
    let calls = 0;
    const requester: Requester = async () => {
      calls++;
      return { status: 404, body: '', headers: { message: 'Invalid parameter: unsupported.' } };
    };
    await assert.rejects(searchNvdCpes(requester, apiKey, 'vendor', 'product', 50), /HTTP 404/);
    assert.equal(calls, 1);
  }
});

test('a public fallback preserves rate-limit guidance and never repeats indefinitely', async () => {
  let calls = 0;
  const requester: Requester = async () =>
    ++calls === 1
      ? { status: 404, body: '', headers: { message: 'Invalid apiKey.' } }
      : { status: 429, body: '', headers: { 'retry-after': '30' } };
  await assert.rejects(
    searchNvdCpes(requester, 'bad-key', 'vendor', 'product', 50),
    (error: unknown) => isNvdRateLimitError(error) && nvdRetryAfterSeconds(error) === 30,
  );
  assert.equal(calls, 2);
});

test('malformed JSON payloads cannot masquerade as zero matching CPEs', async () => {
  for (const data of [
    {},
    { products: [] },
    { products: [], totalResults: -1 },
    { products: null, totalResults: 0 },
  ]) {
    const requester: Requester = async () => ({ status: 200, body: JSON.stringify(data), headers: {} });
    await assert.rejects(
      searchNvdCpes(requester, '', 'vendor', 'product', 50),
      /invalid CPE search response/,
    );
  }
});
