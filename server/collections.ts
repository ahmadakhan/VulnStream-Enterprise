import type pg from 'pg';
import type { CollectionKind, CollectionPage } from '../shared/state.ts';
import { isCollectionKind } from '../shared/state.ts';

/**
 * Query shape shared by `/api/collections/:kind`. All filtering and ordering is
 * done in PostgreSQL so a large installation never has to ship an entire
 * collection to the browser just to render one page.
 */
export interface CollectionQuery {
  limit: number;
  offset: number;
  search?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  filters?: Record<string, string | string[] | number | boolean | undefined>;
}

const SORTS: Partial<Record<CollectionKind, Record<string, string>>> = {
  cveData: {
    score: "(data->'cvss'->>'score')::numeric",
    published: "(data->>'publishedDate')::timestamptz",
    modified: "(data->>'modifiedDate')::timestamptz",
    updated: 'updated_at',
  },
  findings: {
    published: "(data->'cve'->>'publishedDate')::timestamptz",
    modified: "(data->'cve'->>'modifiedDate')::timestamptz",
    updated: 'updated_at',
  },
  advisories: { created: "(data->>'createdDate')::timestamptz", updated: 'updated_at' },
  alertedCves: { alerted: "(data->>'lastAlertedAt')::timestamptz" },
  emailLogs: { sent: "(data->>'sentAt')::timestamptz" },
  webhookLogs: { sent: "(data->>'sentAt')::timestamptz" },
  executions: { started: "(data->>'startTime')::timestamptz" },
  intelligenceArticles: { published: "(data->>'publishedDate')::timestamptz" },
  intelligenceMatches: { updated: 'updated_at' },
};

const DEFAULT_ORDER: Partial<Record<CollectionKind, string>> = {
  cveData: "(data->>'modifiedDate')::timestamptz DESC, id DESC",
  findings:
    "(data->'cve'->>'publishedDate')::timestamptz DESC, (data->'cve'->>'modifiedDate')::timestamptz DESC, id DESC",
  advisories: "(data->>'createdDate')::timestamptz DESC, id DESC",
  alertedCves: "(data->>'lastAlertedAt')::timestamptz DESC, id DESC",
  emailLogs: "(data->>'sentAt')::timestamptz DESC, id DESC",
  webhookLogs: "(data->>'sentAt')::timestamptz DESC, id DESC",
  executions: "(data->>'startTime')::timestamptz DESC, id DESC",
  intelligenceArticles: "(data->>'publishedDate')::timestamptz DESC, id DESC",
};

const orderClause = (kind: CollectionKind, query: CollectionQuery): string => {
  if (kind === 'auditLogs') return 'seq DESC';
  const sort = query.sort && SORTS[kind]?.[query.sort];
  if (sort) return `${sort} ${query.order === 'asc' ? 'ASC' : 'DESC'}, id DESC`;
  return DEFAULT_ORDER[kind] || 'updated_at DESC, id DESC';
};

const likeValue = (search?: string) =>
  search && search.trim() ? `%${search.trim().toLowerCase()}%` : undefined;

function recordConditions(kind: CollectionKind, query: CollectionQuery) {
  const params: unknown[] = [kind];
  const clauses = ['kind=$1'];
  const param = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const like = likeValue(query.search);
  const filters = query.filters ?? {};
  const isAll = (value: unknown) => value === undefined || value === '' || value === 'ALL';

  switch (kind) {
    case 'cveData': {
      if (like)
        clauses.push(
          `(lower(data->>'cveId') LIKE ${param(like)}
            OR lower(COALESCE(data->>'title','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'description','')) LIKE ${param(like)}
            OR lower(COALESCE(data->'sourceFeeds'::text,'')) LIKE ${param(like)}
            OR lower(COALESCE(data->'cpeMatches'::text,'')) LIKE ${param(like)}
            OR lower(COALESCE(data->'purls'::text,'')) LIKE ${param(like)})`,
        );
      if (filters.kev === true || filters.kev === 'true' || filters.kev === 'KEV_ONLY')
        clauses.push(`(data->'cisaKev'->>'isKev')::boolean IS TRUE`);
      if (typeof filters.epssMin === 'number' && Number.isFinite(filters.epssMin))
        clauses.push(`(data->'epss'->>'score')::numeric >= ${param(filters.epssMin)}`);
      if (filters.dateFilter === 'IN_SCOPE') {
        const hours = typeof filters.scopeHours === 'number' ? filters.scopeHours : 24;
        const hoursParam = param(hours);
        clauses.push(
          `((data->>'publishedDate')::timestamptz >= now() - (${hoursParam} * interval '1 hour')
            OR (data->>'modifiedDate')::timestamptz >= now() - (${hoursParam} * interval '1 hour'))`,
        );
      } else if (filters.dateFilter === 'RECENT_MODIFIED') {
        clauses.push(`(data->>'modifiedDate')::timestamptz >= now() - interval '7 days'`);
      } else if (filters.dateFilter === 'RECENT_PUBLISHED') {
        clauses.push(`(data->>'publishedDate')::timestamptz >= now() - interval '7 days'`);
      }
      break;
    }
    case 'findings': {
      if (like)
        clauses.push(
          `(lower(data->>'cveId') LIKE ${param(like)}
            OR lower(COALESCE(data->>'matchedAssetName','')) LIKE ${param(like)}
            OR lower(COALESCE(data->'cve'->>'title','')) LIKE ${param(like)})`,
        );
      if (!isAll(filters.severity))
        clauses.push(`data->'cve'->'cvss'->>'severity' = ${param(String(filters.severity))}`);
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      if (!isAll(filters.notificationStatus))
        clauses.push(`data->>'notificationStatus' = ${param(String(filters.notificationStatus))}`);
      break;
    }
    case 'advisories': {
      if (like)
        clauses.push(
          `(lower(data->>'id') LIKE ${param(like)}
            OR lower(COALESCE(data->>'title','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'executiveSummary','')) LIKE ${param(like)})`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'deliveryStatus' = ${param(String(filters.status))}`);
      break;
    }
    case 'alertedCves': {
      if (like)
        clauses.push(
          `(lower(data->>'cveId') LIKE ${param(like)}
            OR lower(COALESCE(data->>'advisoryId','')) LIKE ${param(like)}
            OR lower(COALESCE(data->'recipientEmails'::text,'')) LIKE ${param(like)})`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'emailLogs': {
      if (like)
        clauses.push(
          `(lower(data->>'recipientEmail') LIKE ${param(like)}
            OR lower(COALESCE(data->>'subject','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'advisoryId','')) LIKE ${param(like)})`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'webhookLogs': {
      if (like)
        clauses.push(
          `(lower(COALESCE(data->>'endpointName','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'advisoryId','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'cveId','')) LIKE ${param(like)})`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'executions': {
      if (like)
        clauses.push(
          `(lower(data->>'id') LIKE ${param(like)} OR lower(COALESCE(data->>'status','')) LIKE ${param(like)})`,
        );
      if (!isAll(filters.status))
        clauses.push(`data->>'status' = ${param(String(filters.status))}`);
      break;
    }
    case 'intelligenceArticles': {
      if (like)
        clauses.push(
          `(lower(COALESCE(data->>'title','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'summary','')) LIKE ${param(like)}
            OR lower(COALESCE(data->'cveIds'::text,'')) LIKE ${param(like)})`,
        );
      break;
    }
    case 'intelligenceMatches': {
      if (like)
        clauses.push(
          `(lower(COALESCE(data->>'assetName','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'evidence','')) LIKE ${param(like)}
            OR lower(COALESCE(data->>'cveId','')) LIKE ${param(like)})`,
        );
      const articleIds = filters.articleIds;
      if (Array.isArray(articleIds) && articleIds.length)
        clauses.push(`data->'articleIds' ?| ${param(articleIds)}::text[]`);
      break;
    }
    default: {
      // Small configuration collections still get a useful generic search.
      if (like) clauses.push(`lower(data::text) LIKE ${param(like)}`);
    }
  }
  return { clauses, params };
}

function auditConditions(query: CollectionQuery) {
  const params: unknown[] = [];
  const clauses: string[] = [];
  const param = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const like = likeValue(query.search);
  const filters = query.filters ?? {};
  if (like)
    clauses.push(
      `(lower(data->>'event') LIKE ${param(like)}
        OR lower(COALESCE(data->>'details','')) LIKE ${param(like)}
        OR lower(COALESCE(data->>'actor','')) LIKE ${param(like)}
        OR COALESCE(data->>'ipAddress','') LIKE ${param(like)})`,
    );
  if (filters.category && filters.category !== 'ALL')
    clauses.push(`data->>'category' = ${param(String(filters.category))}`);
  if (filters.level && filters.level !== 'ALL')
    clauses.push(`data->>'level' = ${param(String(filters.level))}`);
  return { clauses, params };
}

export async function queryCollection<T = unknown>(
  pool: pg.Pool,
  kind: string,
  query: CollectionQuery,
): Promise<CollectionPage<T>> {
  if (!isCollectionKind(kind))
    throw Object.assign(new Error('Unknown collection'), { status: 404 });
  const limit = Math.max(1, Math.min(1000, Math.floor(query.limit) || 50));
  const offset = Math.max(0, Math.floor(query.offset) || 0);

  if (kind === 'auditLogs') {
    const { clauses, params } = auditConditions(query);
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const count = (
      await pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM audit ${where}`, params)
    ).rows[0].count;
    const items = (
      await pool.query(
        `SELECT data FROM audit ${where} ORDER BY seq DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limit, offset],
      )
    ).rows.map((row) => row.data as T);
    return { items, total: Number(count), limit, offset };
  }

  const { clauses, params } = recordConditions(kind as CollectionKind, query);
  const where = `WHERE ${clauses.join(' AND ')}`;
  const count = (
    await pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM records ${where}`, params)
  ).rows[0].count;
  const items = (
    await pool.query(
      `SELECT data FROM records ${where} ORDER BY ${orderClause(kind as CollectionKind, query)} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset],
    )
  ).rows.map((row) => row.data as T);
  return { items, total: Number(count), limit, offset };
}
