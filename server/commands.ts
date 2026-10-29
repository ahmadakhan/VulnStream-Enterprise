import { syncCorrelationAsset } from './correlation/inventory.ts';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Db } from './db.ts';
import { get, getForUpdate, list, put, remove, appendAudit, schemaLockKey } from './db.ts';
import {
  feedSchema,
  feedImportSchema,
  assetSchema,
  watchlistImportSchema,
  recipientSchema,
  webhookSchema,
  cveSchema,
  aliasSchema,
  settingsSchema,
  templateSchema,
  HttpError,
} from './validation.ts';
import { encrypt, randomToken } from './secrets.ts';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { emailConfigSchema } from './validation.ts';
import { emailEndpoint } from './emailProviders.ts';
import {
  compileCustomizedTemplate,
  compileDailyDigestTemplate,
} from '../src/utils/templateCompiler.ts';
import type { Config } from './config';
import { isSmtpEmailProvider, type AliasEntry, type AppSettings, type Finding, type EmailConfiguration, type WatchListItem } from '../src/types/index.ts';

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
export async function applyCommand(db: Db, config: Config, request: CommandRequest): Promise<CommandResult> {
  const { action, id, data, actor, ipAddress = '' } = request;
  const now = new Date().toISOString(),
    newId = id || randomUUID();
  const checkExisting = async (kind: string) => {
    const previous = await getForUpdate<any>(db, kind, newId);
    if (id && !previous) throw new HttpError(404, 'Record not found');
    return previous;
  };
  if (action === 'feed.save') {
    const input = feedSchema.parse(data),
      old = await checkExisting('feeds');
    const sameSource =
      old?.url === input.url &&
      old?.type === input.type &&
      old?.authType === input.authType &&
      !input.authSecretKey;
    await put(db, 'feeds', newId, {
      ...old,
      ...input,
      id: newId,
      authSecretKey:
        input.authType === 'NONE'
          ? ''
          : input.authSecretKey
            ? encrypt(input.authSecretKey, config.ENCRYPTION_KEY, `feed:${newId}`)
            : (sameSource ? old?.authSecretKey : '') || '',
      healthStatus: 'UNTESTED',
      lastSync: sameSource ? old?.lastSync || null : null,
      latencyMs: 0,
      itemCountLastRun: sameSource ? old?.itemCountLastRun || 0 : 0,
      ssrfValidated: false,
      etag: sameSource ? old?.etag : undefined,
      consecutiveFailures: sameSource ? old?.consecutiveFailures : 0,
      circuitOpenUntil: sameSource ? old?.circuitOpenUntil : null,
    });
  } else if (action === 'feed.import') {
    const input = feedImportSchema.parse(data);
    for (const feed of input) {
      const old = await getForUpdate<any>(db, 'feeds', feed.id);
      const sameSource =
        old?.url === feed.url &&
        old?.type === feed.type &&
        old?.authType === feed.authType &&
        !feed.authSecretKey;
      await put(db, 'feeds', feed.id, {
        ...old,
        ...feed,
        id: feed.id,
        authSecretKey:
          feed.authType === 'NONE'
            ? ''
            : feed.authSecretKey
              ? encrypt(feed.authSecretKey, config.ENCRYPTION_KEY, `feed:${feed.id}`)
              : (sameSource ? old?.authSecretKey : '') || '',
        healthStatus: 'UNTESTED',
        lastSync: sameSource ? (old?.lastSync ?? null) : null,
        latencyMs: 0,
        itemCountLastRun: sameSource ? (old?.itemCountLastRun ?? 0) : 0,
        ssrfValidated: false,
        vendorSeed: feed.vendorSeed ?? old?.vendorSeed ?? false,
        etag: sameSource ? old?.etag : undefined,
        consecutiveFailures: sameSource ? (old?.consecutiveFailures ?? 0) : 0,
        circuitOpenUntil: sameSource ? (old?.circuitOpenUntil ?? null) : null,
      });
    }
    await appendAudit(db, 'Feeds imported', `${input.length} feeds`, actor, 'FEED', 'INFO', ipAddress);
    return { success: true, imported: input.length, errors: [] };
  } else if (action === 'asset.save') {
    const input = assetSchema.parse(data),
      old = await checkExisting('watchlist');
    const asset = { ...input, id: newId, createdAt: old?.createdAt || now };
    await put(db, 'watchlist', newId, asset);
    await syncCorrelationAsset(db, asset);
  } else if (action === 'asset.import') {
    const input = z.array(assetSchema).min(1).max(1000).parse(data);
    const identity = (item: z.infer<typeof assetSchema>) =>
      JSON.stringify([
        item.assetTag,
        item.vendor.toLowerCase(),
        item.product.toLowerCase(),
        item.cpes.map((cpe) => cpe.trim().toLowerCase()).sort(),
        [...(item.purls || [])].sort(),
      ]);
    const existing = new Map((await list<any>(db, 'watchlist')).map((item) => [identity(item), item]));
    const unique = new Map(input.map((item) => [identity(item), item]));
    for (const [key, item] of unique) {
      const old = existing.get(key),
        assetId = old?.id || randomUUID();
      const asset = { ...old, ...item, id: assetId, createdAt: old?.createdAt || now };
      await put(db, 'watchlist', assetId, asset);
      await syncCorrelationAsset(db,asset);
    }
    await appendAudit(
      db,
      'Assets imported',
      `${unique.size} unique assets upserted`,
      actor,
      'WATCHLIST',
      'INFO',
      ipAddress,
    );
    return { success: true, imported: unique.size, errors: [] };
  } else if (action === 'watchlist.import') {
    if (!Array.isArray(data)) throw new HttpError(400, 'Expected an array of assets');
    // Pre-validate all rows before inserting any, collecting per-row errors with line numbers.
    const validItems: { id: string; [key: string]: unknown }[] = [];
    const rowErrors: string[] = [];
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      const rowNumber = i + 1;
      try {
        watchlistImportSchema.element.parse(row);
        validItems.push(row as { id: string; [key: string]: unknown });
      } catch (e: any) {
        rowErrors.push(`Row ${rowNumber}: ${e instanceof z.ZodError ? e.issues.map(issue => `${issue.path?.join('.') || 'root'}: ${issue.message}`).join('; ') : e.message}`);
      }
    }
    if (rowErrors.length) {
      return { success: false, imported: 0, errors: rowErrors };
    }
    let imported = 0;
    for (const item of validItems) {
      const old = await getForUpdate<any>(db, 'watchlist', item.id);
      const merged = {
        ...old,
        ...item,
        id: item.id,
        createdAt: item.createdAt || old?.createdAt || now,
        exposure: item.exposure ?? old?.exposure,
      };
      await put(db, 'watchlist', item.id, merged);
      await syncCorrelationAsset(db,merged as WatchListItem);
      imported += 1;
    }
    await appendAudit(db, 'Assets imported', `${imported} assets`, actor, 'WATCHLIST', 'INFO', ipAddress);
    return { success: true, imported, errors: [] };
  } else if (action === 'alias.save') {
    const input = aliasSchema.parse(data),
      old = await checkExisting('aliases');
    await put(db, 'aliases', newId, {
      ...input,
      id: newId,
      createdAt: old?.createdAt || now,
      source: 'MANUAL',
    });
  } else if (action === 'alias.delete') {
    if (!id) throw new HttpError(400, 'Record ID required');
    if (!(await getForUpdate<any>(db, 'aliases', id))) throw new HttpError(404, 'Record not found');
    await remove(db, 'aliases', id);
  } else if (action === 'alias.promote') {
    // Promoting turns a learned relation into a permanent operator alias. It
    // keeps the row id but stops the automatic lifecycle from expiring it.
    if (!id) throw new HttpError(400, 'Record ID required');
    const row = await getForUpdate<AliasEntry>(db, 'aliases', id);
    if (!row) throw new HttpError(404, 'Record not found');
    if (row.source !== 'AUTO')
      throw new HttpError(400, 'Only an automatically learned alias can be promoted');
    await put(db, 'aliases', id, {
      ...row,
      source: 'MANUAL',
      provenance: 'OPERATOR',
      aliases: [...row.aliases].sort(),
      createdAt: row.createdAt || now,
      firstSeenAt: row.firstSeenAt || row.createdAt || now,
      lastSeenAt: now,
      expiresAt: undefined,
      revokedAliases: undefined,
      revokedAt: undefined,
      notes: row.notes
        ? `${row.notes} Promoted to a permanent operator alias.`
        : 'Promoted to a permanent operator alias.',
    });
    await appendAudit(
      db,
      'Alias promoted',
      `${row.scope} ${row.canonical} -> ${row.aliases.join(', ')}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
    );
  } else if (action === 'alias.revoke') {
    // Revocation is a tombstone, not a deletion: the relation must not be
    // re-learned on the next pipeline run just because the same evidence is
    // still present. The pairs move to `revokedAliases`, which is never used
    // for matching.
    if (!id) throw new HttpError(400, 'Record ID required');
    const row = await getForUpdate<AliasEntry>(db, 'aliases', id);
    if (!row) throw new HttpError(404, 'Record not found');
    if (row.source !== 'AUTO')
      throw new HttpError(400, 'Only an automatically learned alias can be revoked');
    // The tombstone gets its own id so a *different* spelling of the same
    // canonical name can still be learned later. It carries the rejected pairs
    // in `revokedAliases`, which is never used for matching.
    await remove(db, 'aliases', id);
    await put(db, 'aliases', `revoked:${id}`, {
      ...row,
      id: `revoked:${id}`,
      source: 'REVOKED',
      provenance: undefined,
      aliases: [],
      revokedAliases: [...row.aliases].sort(),
      expiresAt: undefined,
      revokedAt: now,
      notes: 'Revoked by an operator. This naming relation will not be learned again automatically.',
    });
    await appendAudit(
      db,
      'Alias revoked',
      `${row.scope} ${row.canonical} -/-> ${row.aliases.join(', ')}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
    );
  } else if (action === 'recipient.save') {
    const input = recipientSchema.parse(data);
    // A row lock cannot protect a uniqueness predicate for a row that does not
    // exist yet: two concurrent creates both see no match and both insert.
    // Serialize recipient writes for the transaction instead.
    await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, [
      'recipients-unique',
    ]);
    const old = await checkExisting('recipients');
    const exists = (await list<any>(db, 'recipients')).some((r) => r.email === input.email && r.id !== id);
    if (exists) throw new HttpError(409, 'Recipient already exists');
    // Editing a recipient must not erase the delivery health computed from the
    // outbox. Only a genuinely new recipient starts at zero.
    await put(db, 'recipients', newId, {
      ...input,
      id: newId,
      deliverySuccessRate: old?.deliverySuccessRate ?? 0,
    });
  } else if (action === 'webhook.save') {
    const input = webhookSchema.parse(data);
    const old = await checkExisting('webhooks');
    await put(db, 'webhooks', newId, {
      ...input,
      id: newId,
      url: encrypt(input.url, config.ENCRYPTION_KEY, `webhook-url:${newId}`),
      // An edit with a blank secret keeps the stored credential. Rotating it
      // silently would break the receiver without an explicit operator action.
      secretToken: input.secretToken
        ? encrypt(input.secretToken, config.ENCRYPTION_KEY, `webhook:${newId}`)
        : old?.secretToken || encrypt(randomToken(), config.ENCRYPTION_KEY, `webhook:${newId}`),
      deliveryCount: old?.deliveryCount ?? 0,
    });
  } else if (action === 'cve.save') {
    const input = cveSchema.parse(data);
    const withdrawn = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', input.cveId);
    if (withdrawn && Date.parse(input.modifiedDate) <= Date.parse(withdrawn.modifiedDate))
      throw new HttpError(409, 'CVE revision has been withdrawn; a newer authoritative revision is required');
    await put(db, 'cveData', input.cveId, {
      ...input,
      vex: undefined,
      sourceFeeds: ['operator-import'],
    });
  } else if (action === 'email.configure') {
    const input = emailConfigSchema.parse(data);
    const old = (await getForUpdate<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    const smtpProvider = isSmtpEmailProvider(input.provider);
    // A stored credential is only reusable when it still belongs to the same
    // destination. Changing a custom API endpoint, SMTP host, or SMTP username
    // must require the operator to enter the secret again instead of silently
    // sending the previous credential to a different service or account.
    const sameApiDestination =
      old.provider === input.provider &&
      (input.provider !== 'API' ||
        (old.apiEndpoint === input.apiEndpoint && old.apiSourceDomain === input.apiSourceDomain));
    const sameSmtpIdentity =
      old.provider === input.provider &&
      old.smtpHost === input.smtpHost &&
      old.smtpUsername === input.smtpUsername;
    const apiKey = smtpProvider
      ? ''
      : input.apiKey
        ? encrypt(input.apiKey, config.ENCRYPTION_KEY, `email-provider:${input.provider}`)
        : sameApiDestination
          ? old.apiKey
          : '';
    const smtpPassword =
      smtpProvider && (input.provider !== 'SMTP' || !!input.smtpHost)
        ? input.smtpPassword
          ? encrypt(input.smtpPassword, config.ENCRYPTION_KEY, `email-smtp:${input.provider}`)
          : sameSmtpIdentity
            ? old.smtpPassword
            : ''
        : '';
    const mailjetApiSecret =
      input.provider === 'MAILJET_API' && input.mailjetApiSecret
        ? encrypt(input.mailjetApiSecret, config.ENCRYPTION_KEY, `email-mailjet:${input.provider}`)
        : old.provider === input.provider
          ? old.mailjetApiSecret
          : '';
    if (!smtpProvider && !apiKey)
      throw new HttpError(400, 'Enter an API token for the selected provider');
    if (input.provider === 'MAILJET_API' && !input.mailjetApiSecret && !mailjetApiSecret)
      throw new HttpError(400, 'Enter your Mailjet API secret');
    if (smtpProvider && input.smtpHost) {
      const allowedHosts = config.EGRESS_ALLOWED_HOSTS.split(',').map((host) => host.trim().toLowerCase());
      if (!allowedHosts.includes(input.smtpHost.toLowerCase().trim()))
        throw new HttpError(400, `Add ${input.smtpHost} to EGRESS_ALLOWED_HOSTS before configuring this SMTP host`);
      const presetRequiresAuth = input.provider !== 'SMTP_CUSTOM' && input.provider !== 'SMTP';
      if (presetRequiresAuth && (!input.smtpUsername || !smtpPassword))
        throw new HttpError(400, 'SMTP username and password or API secret are required');
      if (!presetRequiresAuth && Boolean(input.smtpUsername) !== Boolean(smtpPassword))
        throw new HttpError(400, 'Provide both SMTP username and password, or leave both blank');
    }
    const endpoint = emailEndpoint(input);
    if (endpoint && !config.EGRESS_ALLOWED_HOSTS.split(',').map((host) => host.trim().toLowerCase()).includes(new URL(endpoint).hostname))
      throw new HttpError(400, `Allow ${new URL(endpoint).hostname} in EGRESS_ALLOWED_HOSTS before configuring this provider`);
    await put(db, 'emailConfig', 'main', { ...input, apiKey, smtpPassword, mailjetApiSecret });
  } else if (action === 'settings.save') {
    const old = (await getForUpdate<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    await put(
      db,
      'settings',
      'main',
      settingsSchema.parse({ ...old, ...z.record(z.string(), z.unknown()).parse(data) }),
    );
  } else if (action === 'template.save') {
    const input = z.object({ templateCustomization: templateSchema }).parse(data);
    const existing = (await getForUpdate<any>(db, 'template', 'main')) || {};
    await put(db, 'template', 'main', {
      ...existing,
      templateCustomization: input.templateCustomization,
      advisoryTemplate: compileCustomizedTemplate(input.templateCustomization),
    });
  } else if (action === 'dailyDigestTemplate.save') {
    const input = z.object({ dailyDigestCustomization: templateSchema }).parse(data);
    const existing = (await getForUpdate<any>(db, 'template', 'main')) || {};
    await put(db, 'template', 'main', {
      ...existing,
      dailyDigestCustomization: input.dailyDigestCustomization,
      dailyDigestTemplate: compileDailyDigestTemplate(input.dailyDigestCustomization),
    });
  } else if (action === 'finding.status') {
    const input = z
      .object({
        status: z.enum(['MONITORED', 'REMEDIATION_AVAILABLE', 'PATCH_APPLIED', 'RESOLVED', 'FALSE_POSITIVE']),
        note: z.string().max(2000).optional(),
      })
      .parse(data);
    const f = await getForUpdate<Finding>(db, 'findings', newId);
    if (!f) throw new HttpError(404, 'Finding not found');
    await put(db, 'findings', newId, {
      ...f,
      status: input.status,
      timeline: [
        ...(f.timeline ?? []),
        { timestamp: now, action: input.status, system: actor, details: input.note || '' },
      ],
    });
  } else if (action === 'finding.delete') {
    if (!id) throw new HttpError(400, 'Record ID required');
    const old = await getForUpdate<any>(db, 'findings', id);
    if (!old) throw new HttpError(404, 'Finding not found');
    await remove(db, 'findings', id);
    // A deleted finding may have been referenced by an open advisory; clear
    // the link so the advisory does not resurrect the record on its next write.
    await db.query('UPDATE records SET data = jsonb_set(data, \'{findingIds}\', (data->\'findingIds\') - $1::text) WHERE kind=\'advisories\' AND data ? \'findingIds\'', [id]);
  } else if (/^(feed|asset|recipient|webhook)\.(delete|toggle)$/.test(action)) {
    const [entity, operation] = action.split('.'),
      kind = (
        { feed: 'feeds', asset: 'watchlist', recipient: 'recipients', webhook: 'webhooks' } as Record<
          string,
          string
        >
      )[entity];
    if (!id) throw new HttpError(400, 'Record ID required');
    const old = await getForUpdate<any>(db, kind, id);
    if (!old) throw new HttpError(404, 'Record not found');
    if (entity === 'feed' && operation === 'delete' && (old.vendorSeed || old.type === 'NVD_API'))
      throw new HttpError(403, 'Vendor-seeded feeds and NVD sources cannot be deleted');
    if (entity === 'asset') await syncCorrelationAsset(db,{...old,active:operation === 'delete' ? false : !old.active});
    if (operation === 'delete') {
      await remove(db, kind, id);
      // Source checkpoints are internal state keyed by feed id; deleting the
      // feed must not leave a stale cursor/snapshot that a later feed with the
      // same id could accidentally resume from.
      if (entity === 'feed') {
        await remove(db, 'feedCursors', id);
        await remove(db, 'feedSnapshots', id);
      }
    } else
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
