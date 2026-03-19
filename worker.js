/**
 * Cloudflare Worker — Calendar Subscribe API
 * ============================================
 * Handles:
 *   GET    /api/calendars              → list calendars (public: active only; admin: all)
 *   POST   /api/calendars              → create calendar (admin)
 *   PUT    /api/calendars/:id          → update calendar (admin)
 *   DELETE /api/calendars/:id          → delete calendar (admin)
 *   GET    /api/calendars/:slug/ics    → serve .ics feed (public)
 *
 * Setup:
 *   1. Create a D1 database in Cloudflare dashboard
 *   2. Run schema.sql against it
 *   3. Bind the D1 database as "DB" in your wrangler.toml:
 *        [[d1_databases]]
 *        binding = "DB"
 *        database_name = "your-db-name"
 *        database_id   = "your-db-id"
 *   4. Set ADMIN_PASSWORD as a Worker secret:
 *        wrangler secret put ADMIN_PASSWORD
 *   5. Update the CORS_ORIGIN below to your GitHub Pages URL
 */

const CORS_ORIGIN = 'https://YOUR_USERNAME.github.io'; // ← change this

// ── CORS headers ──────────────────────────────────────────────
function cors(origin) {
  return {
    'Access-Control-Allow-Origin':  origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Pass',
    'Access-Control-Max-Age':       '86400',
  };
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors(CORS_ORIGIN), ...extra }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── Auth helper ───────────────────────────────────────────────
function isAdmin(request, env) {
  const header = request.headers.get('X-Admin-Pass');
  return header && header === env.ADMIN_PASSWORD;
}

// ── ICS builder ───────────────────────────────────────────────
function buildIcs(cal) {
  const now = new Date().toISOString().replace(/[-:]/g,'').split('.')[0] + 'Z';
  return [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    `PRODID:-//CalendarSubscribe//${cal.slug}//EN`,
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    `X-WR-CALNAME:${cal.name}`,
    `X-WR-CALDESC:${cal.description || ''}`,
    'X-WR-TIMEZONE:UTC',
    // Add VEVENT entries here if you store events in a separate table.
    // Example placeholder event:
    'BEGIN:VEVENT',
    `DTSTART:${now}`,
    `DTEND:${now}`,
    `DTSTAMP:${now}`,
    `UID:placeholder-${cal.slug}@calendars`,
    `SUMMARY:Subscribe to ${cal.name}`,
    `DESCRIPTION:${cal.description || 'Calendar feed active.'}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ].join('\r\n');
}

// ── Main handler ──────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // Preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors(CORS_ORIGIN) });
    }

    // ── GET /api/calendars ──────────────────────────────────
    if (method === 'GET' && path === '/api/calendars') {
      const showAll = isAdmin(request, env) && url.searchParams.get('all') === '1';
      const q = showAll
        ? `SELECT * FROM calendars ORDER BY created_at DESC`
        : `SELECT * FROM calendars WHERE status = 'active' ORDER BY created_at DESC`;
      const { results } = await env.DB.prepare(q).all();
      return json(results);
    }

    // ── GET /api/calendars/:slug/ics ────────────────────────
    const icsMatch = path.match(/^\/api\/calendars\/([^/]+)\/ics$/);
    if (method === 'GET' && icsMatch) {
      const slug = icsMatch[1];
      const cal  = await env.DB.prepare(
        `SELECT * FROM calendars WHERE slug = ? AND status = 'active'`
      ).bind(slug).first();
      if (!cal) return new Response('Calendar not found', { status: 404 });

      const icsContent = buildIcs(cal);
      return new Response(icsContent, {
        status: 200,
        headers: {
          'Content-Type':        'text/calendar; charset=utf-8',
          'Content-Disposition': `attachment; filename="${cal.slug}.ics"`,
          'Cache-Control':       'no-cache',
          ...cors(CORS_ORIGIN),
        }
      });
    }

    // ── POST /api/calendars ─────────────────────────────────
    if (method === 'POST' && path === '/api/calendars') {
      if (!isAdmin(request, env)) return err('Unauthorized', 401);
      const body = await request.json().catch(() => null);
      if (!body?.name || !body?.slug) return err('name and slug are required');

      // Validate slug format
      if (!/^[a-z0-9-]+$/.test(body.slug)) return err('slug must be lowercase letters, numbers, and hyphens only');

      try {
        const result = await env.DB.prepare(
          `INSERT INTO calendars (name, slug, description, color, status)
           VALUES (?, ?, ?, ?, ?)`
        ).bind(
          body.name,
          body.slug,
          body.description || '',
          body.color       || '#6ee7b7',
          body.status      || 'active'
        ).run();
        return json({ id: result.meta.last_row_id, ...body }, 201);
      } catch (e) {
        if (e.message?.includes('UNIQUE')) return err('A calendar with that slug already exists', 409);
        return err(e.message, 500);
      }
    }

    // ── PUT /api/calendars/:id ──────────────────────────────
    const idMatch = path.match(/^\/api\/calendars\/(\d+)$/);
    if (method === 'PUT' && idMatch) {
      if (!isAdmin(request, env)) return err('Unauthorized', 401);
      const id   = parseInt(idMatch[1]);
      const body = await request.json().catch(() => null);
      if (!body?.name || !body?.slug) return err('name and slug are required');

      try {
        await env.DB.prepare(
          `UPDATE calendars
           SET name = ?, slug = ?, description = ?, color = ?, status = ?, updated_at = datetime('now')
           WHERE id = ?`
        ).bind(body.name, body.slug, body.description || '', body.color || '#6ee7b7', body.status || 'active', id).run();
        return json({ id, ...body });
      } catch (e) {
        if (e.message?.includes('UNIQUE')) return err('A calendar with that slug already exists', 409);
        return err(e.message, 500);
      }
    }

    // ── DELETE /api/calendars/:id ───────────────────────────
    if (method === 'DELETE' && idMatch) {
      if (!isAdmin(request, env)) return err('Unauthorized', 401);
      const id = parseInt(idMatch[1]);
      await env.DB.prepare(`DELETE FROM calendars WHERE id = ?`).bind(id).run();
      return json({ deleted: true });
    }

    return err('Not found', 404);
  }
};
