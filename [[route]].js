/**
 * Cloudflare Pages Function
 * File: functions/api/[[route]].js
 *
 * This file goes in your repo at:  functions/api/[[route]].js
 * Cloudflare Pages will automatically serve it at /api/*
 *
 * Make sure your D1 database is bound as "DB" in:
 * Pages dashboard → Settings → Functions → D1 database bindings
 *   Variable name: DB
 *   Database:      (select your D1 database)
 */

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS }
  });
}

function buildIcs(cal) {
  const now = new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15) + 'Z';
  return [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    `PRODID:-//calendar-8wm.pages.dev//${cal.slug}//EN`,
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    `X-WR-CALNAME:${cal.name}`,
    `X-WR-CALDESC:${cal.description || ''}`,
    'X-WR-TIMEZONE:UTC',
    'BEGIN:VEVENT',
    `DTSTART:${now}`,
    `DTEND:${now}`,
    `DTSTAMP:${now}`,
    `UID:init-${cal.slug}@calendar-8wm`,
    `SUMMARY:Subscribed to ${cal.name}`,
    `DESCRIPTION:${cal.description || 'Your calendar feed is active.'}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ].join('\r\n');
}

export async function onRequest(context) {
  const { request, env, params } = context;
  const method = request.method;
  const route  = (params.route || []).join('/'); // e.g. "calendars" or "calendars/123" or "calendars/my-slug/ics"

  // Preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  // ── GET /api/calendars ──────────────────────────────────────
  if (method === 'GET' && route === 'calendars') {
    const url     = new URL(request.url);
    const showAll = url.searchParams.get('all') === '1';
    const q = showAll
      ? `SELECT * FROM calendars ORDER BY created_at DESC`
      : `SELECT * FROM calendars WHERE status = 'active' ORDER BY created_at DESC`;
    const { results } = await env.DB.prepare(q).all();
    return json(results);
  }

  // ── GET /api/calendars/:slug/ics ────────────────────────────
  const icsMatch = route.match(/^calendars\/([^/]+)\/ics$/);
  if (method === 'GET' && icsMatch) {
    const cal = await env.DB.prepare(
      `SELECT * FROM calendars WHERE slug = ? AND status = 'active'`
    ).bind(icsMatch[1]).first();
    if (!cal) return new Response('Calendar not found', { status: 404 });
    return new Response(buildIcs(cal), {
      status: 200,
      headers: {
        'Content-Type':        'text/calendar; charset=utf-8',
        'Content-Disposition': `attachment; filename="${cal.slug}.ics"`,
        'Cache-Control':       'no-cache',
        ...CORS,
      }
    });
  }

  // ── POST /api/calendars ─────────────────────────────────────
  if (method === 'POST' && route === 'calendars') {
    const body = await request.json().catch(() => null);
    if (!body?.name || !body?.slug) return json({ error: 'name and slug required' }, 400);
    if (!/^[a-z0-9-]+$/.test(body.slug)) return json({ error: 'slug must be lowercase letters, numbers and hyphens' }, 400);
    try {
      const result = await env.DB.prepare(
        `INSERT INTO calendars (name, slug, description, color, status) VALUES (?,?,?,?,?)`
      ).bind(body.name, body.slug, body.description || '', body.color || '#6ee7b7', body.status || 'active').run();
      return json({ id: result.meta.last_row_id, ...body }, 201);
    } catch (e) {
      if (e.message?.includes('UNIQUE')) return json({ error: 'A calendar with that slug already exists' }, 409);
      return json({ error: e.message }, 500);
    }
  }

  // ── PUT /api/calendars/:id ──────────────────────────────────
  const idMatch = route.match(/^calendars\/(\d+)$/);
  if (method === 'PUT' && idMatch) {
    const id   = parseInt(idMatch[1]);
    const body = await request.json().catch(() => null);
    if (!body?.name || !body?.slug) return json({ error: 'name and slug required' }, 400);
    try {
      await env.DB.prepare(
        `UPDATE calendars SET name=?, slug=?, description=?, color=?, status=?, updated_at=datetime('now') WHERE id=?`
      ).bind(body.name, body.slug, body.description || '', body.color || '#6ee7b7', body.status || 'active', id).run();
      return json({ id, ...body });
    } catch (e) {
      if (e.message?.includes('UNIQUE')) return json({ error: 'A calendar with that slug already exists' }, 409);
      return json({ error: e.message }, 500);
    }
  }

  // ── DELETE /api/calendars/:id ───────────────────────────────
  if (method === 'DELETE' && idMatch) {
    await env.DB.prepare(`DELETE FROM calendars WHERE id=?`).bind(parseInt(idMatch[1])).run();
    return json({ deleted: true });
  }

  return new Response('Not found', { status: 404 });
}
