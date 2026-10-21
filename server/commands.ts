import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Db } from './db';
import { get, list, put, remove, appendAudit } from './db';
import {
  feedSchema,
  feedImportSchema,
  assetSchema,
  recipientSchema,
  webhookSchema,
  cveSchema,
  settingsSchema,
  templateSchema,
  HttpError,
} from './validation';
import { encrypt, randomToken } from './secrets';
import { DEFAULT_SETTINGS } from '../shared/state';
import { compileCustomizedTemplate } from '../src/utils/templateCompiler';
import type { Config } from './config';
import type { AppSettings, Finding } from '../src/types';

export interface CommandRequest {
  action: string;
  id?: string;
  data?: unknown;
  actor: string;
  ipAddress?: string;
}

export interface CommandResult {
  success: boolean;
  imported?: number;
  errors?: string[];
}

/**
 * The single write path for operator mutations. Every caller — the HTTP command
 * route and the seeding script — goes through here, so validation and encryption
 * cannot be bypassed by a second code path.
 */
export async function applyCommand(
  db: Db,
  config: Config,
  request: CommandRequest,
): Promise<CommandResult> {
  const { action, id, data, actor, ipAddress = '' } = request;
  const now = new Date().toISOString(),
    newId = id || randomUUID();
  const checkExisting = async (kind: string) => {
    const previous = await get<any>(db, kind, newId);
    if (id && !previous) throw new HttpError(404, 'Record not found');
    return previous;
  };
  if (action === 'feed.save') {
    const input = feedSchema.parse(data),
      old = await checkExisting('feeds');
    await put(db, 'feeds', newId, {
      ...old,
      ...input,
      id: newId,
      authSecretKey: input.authSecretKey
        ? encrypt(input.authSecretKey, config.ENCRYPTION_KEY, `feed:${newId}`)
        : (old?.url === input.url && old?.authType === input.authType ? old?.authSecretKey : '') || '',
      healthStatus: 'UNTESTED',
      lastSync: old?.lastSync || null,
      latencyMs: 0,
      itemCountLastRun: old?.itemCountLastRun || 0,
      ssrfValidated: false,
    });
  } else if (action === 'feed.import') {
    const input = feedImportSchema.parse(data);
    for (const feed of input) {
      const old = await get<any>(db, 'feeds', feed.id);
      await put(db, 'feeds', feed.id, {
        ...old,
        ...feed,
        id: feed.id,
        authSecretKey: feed.authSecretKey
          ? encrypt(feed.authSecretKey, config.ENCRYPTION_KEY, `feed:${feed.id}`)
          : old?.authSecretKey || '',
        healthStatus: 'UNTESTED',
        lastSync: feed.lastSync ?? old?.lastSync ?? null,
        latencyMs: feed.latencyMs ?? 0,
        itemCountLastRun: feed.itemCountLastRun ?? 0,
        ssrfValidated: false,
        vendorSeed: feed.vendorSeed ?? old?.vendorSeed ?? false,
      });
    }
    await appendAudit(db, 'Feeds imported', `${input.length} feeds`, actor, 'FEED', 'INFO', ipAddress);
    return { success: true, imported: input.length, errors: [] };
  } else if (action === 'asset.save') {
    const input = assetSchema.parse(data),
      old = await checkExisting('watchlist');
    await put(db, 'watchlist', newId, { ...input, id: newId, createdAt: old?.createdAt || now });
  } else if (action === 'asset.import') {
    const input = z.array(assetSchema).min(1).max(1000).parse(data);
    for (const item of input) {
      const assetId = randomUUID();
      await put(db, 'watchlist', assetId, { ...item, id: assetId, createdAt: now });
    }
    await appendAudit(db, 'Assets imported', `${input.length} assets`, actor, 'WATCHLIST', 'INFO', ipAddress);
    return { success: true, imported: input.length, errors: [] };
  } else if (action === 'recipient.save') {
    const input = recipientSchema.parse(data);
    await checkExisting('recipients');
    const exists = (await list<any>(db, 'recipients')).some((r) => r.email === input.email && r.id !== id);
    if (exists) throw new HttpError(409, 'Recipient already exists');
    await put(db, 'recipients', newId, { ...input, id: newId, deliverySuccessRate: 0 });
  } else if (action === 'webhook.save') {
    const input = webhookSchema.parse(data);
    await checkExisting('webhooks');
    await put(db, 'webhooks', newId, {
      ...input,
      id: newId,
      url: encrypt(input.url, config.ENCRYPTION_KEY, `webhook-url:${newId}`),
      secretToken: encrypt(input.secretToken || randomToken(), config.ENCRYPTION_KEY, `webhook:${newId}`),
      deliveryCount: 0,
    });
  } else if (action === 'cve.save') {
    const input = cveSchema.parse(data);
    await put(db, 'cveData', input.cveId, {
      ...input,
      vex: undefined,
      sourceFeeds: ['operator-import'],
    });
  } else if (action === 'settings.save') {
    const old = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    await put(
      db,
      'settings',
      'main',
      settingsSchema.parse({ ...old, ...z.record(z.string(), z.unknown()).parse(data) }),
    );
  } else if (action === 'template.save') {
    const input = z.object({ templateCustomization: templateSchema }).parse(data);
    await put(db, 'template', 'main', {
      templateCustomization: input.templateCustomization,
      advisoryTemplate: compileCustomizedTemplate(input.templateCustomization),
    });
  } else if (action === 'finding.status') {
    const input = z
      .object({
        status: z.enum(['MONITORED', 'REMEDIATION_AVAILABLE', 'PATCH_APPLIED', 'RESOLVED', 'FALSE_POSITIVE']),
        note: z.string().max(2000).optional(),
      })
      .parse(data);
    const f = await get<Finding>(db, 'findings', newId);
    if (!f) throw new HttpError(404, 'Finding not found');
    await put(db, 'findings', newId, {
      ...f,
      status: input.status,
      timeline: [
        ...f.timeline,
        { timestamp: now, action: input.status, system: actor, details: input.note || '' },
      ],
    });
  } else if (/^(feed|asset|recipient|webhook)\.(delete|toggle)$/.test(action)) {
    const [entity, operation] = action.split('.'),
      kind = (
        { feed: 'feeds', asset: 'watchlist', recipient: 'recipients', webhook: 'webhooks' } as Record<
          string,
          string
        >
      )[entity];
    if (!id) throw new HttpError(400, 'Record ID required');
    const old = await get<any>(db, kind, id);
    if (!old) throw new HttpError(404, 'Record not found');
    if (operation === 'delete') await remove(db, kind, id);
    else
      await put(db, kind, id, {
        ...old,
        [entity === 'asset' ? 'active' : 'enabled']: !old[entity === 'asset' ? 'active' : 'enabled'],
      });
  } else throw new HttpError(400, 'Unknown command');
   await appendAudit(
     db,
     action,
     `Record ${id || newId}`,
     actor,
     action.startsWith('asset') ? 'WATCHLIST' : 'SECURITY',
     'INFO',
     ipAddress,
   );
  return { success: true };
}
