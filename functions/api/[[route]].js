/**
 * Cloudflare Pages Function
 * File: functions/api/[[route]].js
 *
 * Routes:
 *   GET    /api/calendars                       list calendars
 *   POST   /api/calendars                       create calendar
 *   PUT    /api/calendars/:id                   update calendar
 *   DELETE /api/calendars/:id                   delete calendar + all its events
 *
 *   GET    /api/calendars/:id/events            list events for a calendar
 *   POST   /api/calendars/:id/events            create event
 *   PUT    /api/calendars/:id/events/:eid       update event
 *   DELETE /api/calendars/:id/events/:eid       delete event
 *
 *   GET    /api/calendars/:slug/ics             .ics feed (public)
 */

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...CORS }
  });
}

// ── ICS builder ───────────────────────────────────────────────

function foldLine(line) {
  if (line.length <= 75) return line;
  const out = [line.slice(0, 75)];
  for (let i = 75; i < line.length; i += 74) out.push(' ' + line.slice(i, i + 74));
  return out.join('\r\n');
}

function icsEsc(s) {
  return String(s||'').replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\n/g,'\\n');
}

function toDate(d) { return d.replace(/-/g,''); }

function toDateTime(d, t) {
  return `${d.replace(/-/g,'')}T${t.replace(':','')}00Z`;
}

function buildIcs(cal, events) {
  const stamp = new Date().toISOString().replace(/[-:.]/g,'').slice(0,15)+'Z';
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    `PRODID:-//calendar-8wm.pages.dev//${cal.slug}//EN`,
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    foldLine(`X-WR-CALNAME:${icsEsc(cal.name)}`),
    foldLine(`X-WR-CALDESC:${icsEsc(cal.description||'')}`),
    'X-WR-TIMEZONE:UTC',
  ];

  for (const ev of events) {
    lines.push('BEGIN:VEVENT');
    lines.push(`UID:ev-${ev.id}@calendar-8wm`);
    lines.push(`DTSTAMP:${stamp}`);

    if (ev.all_day) {
      lines.push(`DTSTART;VALUE=DATE:${toDate(ev.start_date)}`);
      // ICS all-day end is exclusive — add one day
      const end = new Date(ev.end_date || ev.start_date);
      end.setDate(end.getDate() + 1);
      lines.push(`DTEND;VALUE=DATE:${end.toISOString().slice(0,10).replace(/-/g,'')}`);
    } else if (ev.start_time) {
      lines.push(`DTSTART:${toDateTime(ev.start_date, ev.start_time)}`);
      lines.push(`DTEND:${toDateTime(ev.end_date||ev.start_date, ev.end_time||ev.start_time)}`);
    } else {
      lines.push(`DTSTART;VALUE=DATE:${toDate(ev.start_date)}`);
      lines.push(`DTEND;VALUE=DATE:${toDate(ev.end_date||ev.start_date)}`);
    }

    lines.push(foldLine(`SUMMARY:${icsEsc(ev.title)}`));
    if (ev.description) lines.push(foldLine(`DESCRIPTION:${icsEsc(ev.description)}`));
    if (ev.location)    lines.push(foldLine(`LOCATION:${icsEsc(ev.location)}`));
    if (ev.url)         lines.push(foldLine(`URL:${ev.url}`));
    lines.push('END:VEVENT');
  }

  lines.push('END:VCALENDAR');
  return lines.join('\r\n');
}

// ── Main handler ──────────────────────────────────────────────

export async function onRequest(context) {
  const { request, env, params } = context;
  const method = request.method;
  const route  = (params.route || []).join('/');

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  // ── GET /api/calendars ──────────────────────────────────────
  if (method === 'GET' && route === 'calendars') {
    const all = new URL(request.url).searchParams.get('all') === '1';
    const { results } = await env.DB.prepare(
      all ? `SELECT * FROM calendars ORDER BY created_at DESC`
          : `SELECT * FROM calendars WHERE status='active' ORDER BY created_at DESC`
    ).all();
    return json(results);
  }

  // ── GET /api/calendars/:slug/ics ────────────────────────────
  const icsMatch = route.match(/^calendars\/([^/]+)\/ics$/);
  if (method === 'GET' && icsMatch) {
    const id = icsMatch[1];
    const cal = await env.DB.prepare(
      `SELECT * FROM calendars WHERE (slug=? OR CAST(id AS TEXT)=?) AND status='active'`
    ).bind(id, id).first();
    if (!cal) return new Response('Not found', { status: 404 });

    const { results: events } = await env.DB.prepare(
      `SELECT * FROM events WHERE calendar_id=? ORDER BY start_date ASC, start_time ASC`
    ).bind(cal.id).all();

    return new Response(buildIcs(cal, events), {
      status: 200,
      headers: { 'Content-Type': 'text/calendar; charset=utf-8', 'Content-Disposition': `attachment; filename="${cal.slug}.ics"`, 'Cache-Control': 'no-cache', ...CORS }
    });
  }

  // ── POST /api/calendars ─────────────────────────────────────
  if (method === 'POST' && route === 'calendars') {
    const b = await request.json().catch(()=>null);
    if (!b?.name || !b?.slug) return json({ error: 'name and slug required' }, 400);
    if (!/^[a-z0-9-]+$/.test(b.slug)) return json({ error: 'slug: lowercase letters, numbers, hyphens only' }, 400);
    try {
      const r = await env.DB.prepare(
        `INSERT INTO calendars (name,slug,description,color,status) VALUES (?,?,?,?,?)`
      ).bind(b.name, b.slug, b.description||'', b.color||'#6ee7b7', b.status||'active').run();
      return json({ id: r.meta.last_row_id, ...b }, 201);
    } catch(e) {
      return json({ error: e.message?.includes('UNIQUE') ? 'Slug already exists' : e.message }, e.message?.includes('UNIQUE')?409:500);
    }
  }

  const calId = route.match(/^calendars\/(\d+)$/);

  // ── PUT /api/calendars/:id ──────────────────────────────────
  if (method === 'PUT' && calId) {
    const id = parseInt(calId[1]);
    const b  = await request.json().catch(()=>null);
    if (!b?.name || !b?.slug) return json({ error: 'name and slug required' }, 400);
    try {
      await env.DB.prepare(
        `UPDATE calendars SET name=?,slug=?,description=?,color=?,status=?,updated_at=datetime('now') WHERE id=?`
      ).bind(b.name, b.slug, b.description||'', b.color||'#6ee7b7', b.status||'active', id).run();
      return json({ id, ...b });
    } catch(e) {
      return json({ error: e.message?.includes('UNIQUE') ? 'Slug already exists' : e.message }, e.message?.includes('UNIQUE')?409:500);
    }
  }

  // ── DELETE /api/calendars/:id ───────────────────────────────
  if (method === 'DELETE' && calId) {
    const id = parseInt(calId[1]);
    await env.DB.prepare(`DELETE FROM events WHERE calendar_id=?`).bind(id).run();
    await env.DB.prepare(`DELETE FROM calendars WHERE id=?`).bind(id).run();
    return json({ deleted: true });
  }

  // ── GET /api/calendars/:id/events ──────────────────────────
  const evList = route.match(/^calendars\/(\d+)\/events$/);
  const evItem = route.match(/^calendars\/(\d+)\/events\/(\d+)$/);

  if (method === 'GET' && evList) {
    const { results } = await env.DB.prepare(
      `SELECT * FROM events WHERE calendar_id=? ORDER BY start_date ASC, start_time ASC`
    ).bind(parseInt(evList[1])).all();
    return json(results);
  }

  // ── POST /api/calendars/:id/events ─────────────────────────
  if (method === 'POST' && evList) {
    const calId = parseInt(evList[1]);
    const b = await request.json().catch(()=>null);
    if (!b?.title || !b?.start_date) return json({ error: 'title and start_date required' }, 400);
    const r = await env.DB.prepare(
      `INSERT INTO events (calendar_id,title,description,location,start_date,start_time,end_date,end_time,all_day,url)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(calId, b.title, b.description||'', b.location||'', b.start_date, b.start_time||null,
           b.end_date||b.start_date, b.end_time||null, b.all_day?1:0, b.url||'').run();
    return json({ id: r.meta.last_row_id, calendar_id: calId, ...b }, 201);
  }

  // ── PUT /api/calendars/:id/events/:eid ──────────────────────
  if (method === 'PUT' && evItem) {
    const calId = parseInt(evItem[1]);
    const eid   = parseInt(evItem[2]);
    const b = await request.json().catch(()=>null);
    if (!b?.title || !b?.start_date) return json({ error: 'title and start_date required' }, 400);
    await env.DB.prepare(
      `UPDATE events SET title=?,description=?,location=?,start_date=?,start_time=?,end_date=?,end_time=?,all_day=?,url=?,updated_at=datetime('now')
       WHERE id=? AND calendar_id=?`
    ).bind(b.title, b.description||'', b.location||'', b.start_date, b.start_time||null,
           b.end_date||b.start_date, b.end_time||null, b.all_day?1:0, b.url||'', eid, calId).run();
    return json({ id: eid, calendar_id: calId, ...b });
  }

  // ── DELETE /api/calendars/:id/events/:eid ──────────────────
  if (method === 'DELETE' && evItem) {
    await env.DB.prepare(`DELETE FROM events WHERE id=? AND calendar_id=?`)
      .bind(parseInt(evItem[2]), parseInt(evItem[1])).run();
    return json({ deleted: true });
  }

  return new Response('Not found', { status: 404 });
}
