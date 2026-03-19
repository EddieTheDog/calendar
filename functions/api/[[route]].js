/**
 * Cloudflare Pages Function  —  functions/api/[[route]].js
 * Full platform: auth, 2FA, calendars, events, moderation, reports, admin
 */

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, s=200) {
  return new Response(JSON.stringify(data), { status: s, headers: { 'Content-Type':'application/json', ...CORS }});
}
function err(msg, s=400) { return json({ error: msg }, s); }

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function uuid() { return crypto.randomUUID(); }
function tok(req) { const h=req.headers.get('Authorization')||''; return h.startsWith('Bearer ')?h.slice(7).trim():null; }

async function getUser(req, env) {
  const t = tok(req); if (!t) return null;
  return env.DB.prepare(
    `SELECT s.id as session_id, s.expires_at, u.* FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.id=? AND s.expires_at>datetime('now')`
  ).bind(t).first();
}
async function needUser(req, env) {
  const u = await getUser(req, env);
  if (!u) throw { s:401, m:'Not logged in' };
  if (u.banned) throw { s:403, m:'Account banned'+(u.ban_reason?': '+u.ban_reason:'') };
  return u;
}
async function needStaff(req, env) {
  const u = await needUser(req, env);
  if (u.role!=='staff'&&u.role!=='admin') throw { s:403, m:'Staff only' };
  return u;
}
async function needAdmin(req, env) {
  const u = await needUser(req, env);
  if (u.role!=='admin') throw { s:403, m:'Admin only' };
  return u;
}

// ── TOTP ─────────────────────────────────────────────────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  s = s.toUpperCase().replace(/=+$/,'');
  let bits=0,val=0; const out=[];
  for (const c of s) { val=(val<<5)|B32.indexOf(c); bits+=5; if(bits>=8){bits-=8;out.push((val>>bits)&255);} }
  return new Uint8Array(out);
}
async function totpCode(secret, offset=0) {
  const key = await crypto.subtle.importKey('raw',b32decode(secret),{name:'HMAC',hash:'SHA-1'},false,['sign']);
  const t   = Math.floor(Date.now()/30000)+offset;
  const msg = new Uint8Array(8); let n=t; for(let i=7;i>=0;i--){msg[i]=n&0xff;n>>=8;}
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC',key,msg));
  const off = sig[19]&0xf;
  return String(((sig[off]&0x7f)<<24|sig[off+1]<<16|sig[off+2]<<8|sig[off+3])%1000000).padStart(6,'0');
}
async function verifyTOTP(secret, code) {
  for (const d of [-1,0,1]) { if (await totpCode(secret,d)===String(code).padStart(6,'0')) return true; }
  return false;
}
function randSecret() { const a=new Uint8Array(20); crypto.getRandomValues(a); return Array.from(a).map(b=>B32[b%32]).join(''); }

// ── ICS ───────────────────────────────────────────────────────
function fold(l) { if(l.length<=75)return l; const o=[l.slice(0,75)]; for(let i=75;i<l.length;i+=74)o.push(' '+l.slice(i,i+74)); return o.join('\r\n'); }
function ie(s) { return String(s||'').replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\n/g,'\\n'); }
function d2i(d) { return d.replace(/-/g,''); }
function dt2i(d,t) { return `${d.replace(/-/g,'')}T${t.replace(':','')}00Z`; }
function buildIcs(cal, events) {
  const stamp = new Date().toISOString().replace(/[-:.]/g,'').slice(0,15)+'Z';
  const L = ['BEGIN:VCALENDAR','VERSION:2.0',`PRODID:-//calendar-8wm//${cal.slug}//EN`,'CALSCALE:GREGORIAN','METHOD:PUBLISH',
    fold(`X-WR-CALNAME:${ie(cal.name)}`),fold(`X-WR-CALDESC:${ie(cal.description||'')}`),'X-WR-TIMEZONE:UTC'];
  for (const ev of events) {
    L.push('BEGIN:VEVENT',`UID:ev-${ev.id}@cal`,`DTSTAMP:${stamp}`);
    if (ev.all_day) {
      L.push(`DTSTART;VALUE=DATE:${d2i(ev.start_date)}`);
      const e=new Date(ev.end_date||ev.start_date); e.setDate(e.getDate()+1);
      L.push(`DTEND;VALUE=DATE:${e.toISOString().slice(0,10).replace(/-/g,'')}`);
    } else if (ev.start_time) {
      L.push(`DTSTART:${dt2i(ev.start_date,ev.start_time)}`,`DTEND:${dt2i(ev.end_date||ev.start_date,ev.end_time||ev.start_time)}`);
    } else {
      L.push(`DTSTART;VALUE=DATE:${d2i(ev.start_date)}`,`DTEND;VALUE=DATE:${d2i(ev.end_date||ev.start_date)}`);
    }
    L.push(fold(`SUMMARY:${ie(ev.title)}`));
    if(ev.description)L.push(fold(`DESCRIPTION:${ie(ev.description)}`));
    if(ev.location)L.push(fold(`LOCATION:${ie(ev.location)}`));
    if(ev.url)L.push(fold(`URL:${ev.url}`));
    L.push('END:VEVENT');
  }
  L.push('END:VCALENDAR'); return L.join('\r\n');
}

// ══════════════════════════════════════════════════════════════
export async function onRequest(context) {
  const { request:req, env, params } = context;
  const method = req.method;
  const route  = (params.route||[]).join('/');
  const url    = new URL(req.url);
  if (method==='OPTIONS') return new Response(null,{status:204,headers:CORS});

  try {

  // ── AUTH ─────────────────────────────────────────────────────

  if (method==='POST' && route==='auth/register') {
    const b = await req.json().catch(()=>null);
    if (!b?.username||!b?.email||!b?.password) return err('username, email and password required');
    if (b.username.length<3) return err('Username must be at least 3 characters');
    if (!/^[a-zA-Z0-9_-]+$/.test(b.username)) return err('Username: letters, numbers, _ - only');
    if (b.password.length<6) return err('Password must be at least 6 characters');
    const hash = await sha256(b.password);
    try {
      const r = await env.DB.prepare(`INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'user')`)
        .bind(b.username.trim(),b.email.trim().toLowerCase(),hash).run();
      const token = uuid();
      await env.DB.prepare(`INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,datetime('now','+30 days'))`).bind(token,r.meta.last_row_id).run();
      return json({token,username:b.username,role:'user',id:r.meta.last_row_id},201);
    } catch(e) {
      if(e.message?.includes('UNIQUE')) return err(e.message.includes('username')?'Username taken':'Email already registered',409);
      throw e;
    }
  }

  if (method==='POST' && route==='auth/login') {
    const b = await req.json().catch(()=>null);
    if (!b?.username||!b?.password) return err('username and password required');
    if (b.admin_gate) { return b.password==='ABC123' ? json({admin_gate:true}) : err('Incorrect admin password',401); }
    const hash = await sha256(b.password);
    const user = await env.DB.prepare(`SELECT * FROM users WHERE (username=? OR email=?) AND password_hash=?`)
      .bind(b.username,b.username.toLowerCase(),hash).first();
    if (!user) return err('Incorrect username or password',401);
    if (user.banned) return err('Account banned'+(user.ban_reason?': '+user.ban_reason:''),403);
    if (user.totp_enabled&&user.totp_secret) {
      if (!b.totp_code) return json({requires_totp:true},200);
      if (!await verifyTOTP(user.totp_secret,String(b.totp_code))) return err('Invalid 2FA code',401);
    }
    const token = uuid();
    await env.DB.prepare(`INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,datetime('now','+30 days'))`).bind(token,user.id).run();
    await env.DB.prepare(`UPDATE users SET last_login=datetime('now') WHERE id=?`).bind(user.id).run();
    return json({token,username:user.username,role:user.role,id:user.id,verified_badge:user.verified_badge});
  }

  if (method==='POST' && route==='auth/logout') {
    const t=tok(req); if(t) await env.DB.prepare(`DELETE FROM sessions WHERE id=?`).bind(t).run();
    return json({ok:true});
  }

  if (method==='GET' && route==='auth/me') {
    const u = await getUser(req,env); if(!u) return err('Not logged in',401);
    return json({id:u.id,username:u.username,email:u.email,role:u.role,verified_badge:u.verified_badge,totp_enabled:u.totp_enabled,decline_count:u.decline_count});
  }

  if (method==='POST' && route==='auth/2fa/setup') {
    const u=await needUser(req,env); const secret=randSecret();
    await env.DB.prepare(`UPDATE users SET totp_secret=?,totp_enabled=0 WHERE id=?`).bind(secret,u.id).run();
    return json({secret,otpauth:`otpauth://totp/CalendarHub:${encodeURIComponent(u.username)}?secret=${secret}&issuer=CalendarHub`});
  }

  if (method==='POST' && route==='auth/2fa/verify') {
    const u=await needUser(req,env); const b=await req.json().catch(()=>null);
    const full=await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(u.id).first();
    if (!full?.totp_secret) return err('Set up 2FA first');
    if (!await verifyTOTP(full.totp_secret,String(b?.code||''))) return err('Invalid code',401);
    await env.DB.prepare(`UPDATE users SET totp_enabled=1 WHERE id=?`).bind(u.id).run();
    return json({ok:true,message:'2FA enabled'});
  }

  if (method==='POST' && route==='auth/2fa/disable') {
    const u=await needUser(req,env); const b=await req.json().catch(()=>null);
    const full=await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(u.id).first();
    if (!full?.totp_secret||!full?.totp_enabled) return err('2FA not enabled');
    if (!await verifyTOTP(full.totp_secret,String(b?.code||''))) return err('Invalid code',401);
    await env.DB.prepare(`UPDATE users SET totp_enabled=0,totp_secret=NULL WHERE id=?`).bind(u.id).run();
    return json({ok:true});
  }

  // ── PUBLIC CALENDARS ─────────────────────────────────────────

  if (method==='GET' && route==='calendars') {
    const all=url.searchParams.get('all')==='1';
    const u=all?await getUser(req,env):null;
    const staff=u&&(u.role==='staff'||u.role==='admin');
    const q = staff
      ? `SELECT c.*,u.username as owner_username,u.verified_badge as owner_badge FROM calendars c LEFT JOIN users u ON c.owner_id=u.id ORDER BY c.created_at DESC`
      : `SELECT c.*,u.username as owner_username,u.verified_badge as owner_badge FROM calendars c LEFT JOIN users u ON c.owner_id=u.id WHERE c.approval_status='approved' AND c.status='active' ORDER BY c.created_at DESC`;
    const {results}=await env.DB.prepare(q).all();
    return json(results);
  }

  const icsM=route.match(/^calendars\/([^/]+)\/ics$/);
  if (method==='GET'&&icsM) {
    const cal=await env.DB.prepare(`SELECT * FROM calendars WHERE (slug=? OR CAST(id AS TEXT)=?) AND status='active' AND approval_status='approved'`).bind(icsM[1],icsM[1]).first();
    if(!cal) return new Response('Not found',{status:404});
    const {results:evs}=await env.DB.prepare(`SELECT * FROM events WHERE calendar_id=? ORDER BY start_date,start_time`).bind(cal.id).all();
    return new Response(buildIcs(cal,evs),{status:200,headers:{'Content-Type':'text/calendar;charset=utf-8','Content-Disposition':`attachment;filename="${cal.slug}.ics"`,'Cache-Control':'no-cache',...CORS}});
  }

  // ── USER SUBMISSIONS ─────────────────────────────────────────

  if (method==='GET' && route==='my/calendars') {
    const u=await needUser(req,env);
    const {results}=await env.DB.prepare(`SELECT * FROM calendars WHERE owner_id=? ORDER BY created_at DESC`).bind(u.id).all();
    return json(results);
  }

  if (method==='POST' && route==='my/calendars') {
    const u=await needUser(req,env);
    const b=await req.json().catch(()=>null);
    if (!b?.name||!b?.slug) return err('name and slug required');
    if (!/^[a-z0-9-]+$/.test(b.slug)) return err('slug: lowercase, numbers, hyphens only');
    const full=await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(u.id).first();
    if (full.decline_count>=3) return err('Your account has 3 declined calendars. Contact an admin.',403);
    const {results:pend}=await env.DB.prepare(`SELECT id FROM calendars WHERE owner_id=? AND approval_status='pending'`).bind(u.id).all();
    if (pend.length>=2) return err('You can only have 2 calendars pending at a time.',429);
    try {
      const r=await env.DB.prepare(`INSERT INTO calendars(name,slug,description,color,status,owner_id,approval_status) VALUES(?,?,?,?,?,?,'pending')`)
        .bind(b.name,b.slug,b.description||'',b.color||'#6ee7b7','active',u.id).run();
      return json({id:r.meta.last_row_id,approval_status:'pending',...b},201);
    } catch(e) {
      if(e.message?.includes('UNIQUE')) return err('Slug already taken',409); throw e;
    }
  }

  const myCalM=route.match(/^my\/calendars\/(\d+)$/);
  if (method==='PUT'&&myCalM) {
    const u=await needUser(req,env); const id=parseInt(myCalM[1]);
    const cal=await env.DB.prepare(`SELECT * FROM calendars WHERE id=? AND owner_id=?`).bind(id,u.id).first();
    if (!cal) return err('Not found or not yours',404);
    const b=await req.json().catch(()=>null); if(!b?.name||!b?.slug) return err('name and slug required');
    const ns=cal.approval_status==='declined'?'pending':cal.approval_status;
    await env.DB.prepare(`UPDATE calendars SET name=?,slug=?,description=?,color=?,approval_status=?,updated_at=datetime('now') WHERE id=?`)
      .bind(b.name,b.slug,b.description||'',b.color||'#6ee7b7',ns,id).run();
    return json({id,approval_status:ns,...b});
  }

  if (method==='DELETE'&&myCalM) {
    const u=await needUser(req,env); const id=parseInt(myCalM[1]);
    const cal=await env.DB.prepare(`SELECT * FROM calendars WHERE id=? AND owner_id=?`).bind(id,u.id).first();
    if (!cal) return err('Not found or not yours',404);
    if (cal.approval_status==='approved') return err('Cannot delete an approved calendar. Contact staff.',403);
    await env.DB.prepare(`DELETE FROM events WHERE calendar_id=?`).bind(id).run();
    await env.DB.prepare(`DELETE FROM calendars WHERE id=?`).bind(id).run();
    return json({deleted:true});
  }

  // ── EVENTS ───────────────────────────────────────────────────

  const evL=route.match(/^calendars\/(\d+)\/events$/);
  const evI=route.match(/^calendars\/(\d+)\/events\/(\d+)$/);

  if (method==='GET'&&evL) {
    const {results}=await env.DB.prepare(`SELECT * FROM events WHERE calendar_id=? ORDER BY start_date,start_time`).bind(parseInt(evL[1])).all();
    return json(results);
  }
  async function checkCalAccess(req,env,calId) {
    const u=await needUser(req,env);
    const cal=await env.DB.prepare(`SELECT * FROM calendars WHERE id=?`).bind(calId).first();
    if(!cal) throw {s:404,m:'Calendar not found'};
    if(cal.owner_id!==u.id&&u.role!=='staff'&&u.role!=='admin') throw {s:403,m:'Not authorised'};
    return {u,cal};
  }
  if (method==='POST'&&evL) {
    const {cal}=await checkCalAccess(req,env,parseInt(evL[1]));
    const b=await req.json().catch(()=>null); if(!b?.title||!b?.start_date) return err('title and start_date required');
    const r=await env.DB.prepare(`INSERT INTO events(calendar_id,title,description,location,start_date,start_time,end_date,end_time,all_day,url) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .bind(cal.id,b.title,b.description||'',b.location||'',b.start_date,b.start_time||null,b.end_date||b.start_date,b.end_time||null,b.all_day?1:0,b.url||'').run();
    return json({id:r.meta.last_row_id,calendar_id:cal.id,...b},201);
  }
  if (method==='PUT'&&evI) {
    const {cal}=await checkCalAccess(req,env,parseInt(evI[1]));
    const eid=parseInt(evI[2]); const b=await req.json().catch(()=>null);
    if(!b?.title||!b?.start_date) return err('title and start_date required');
    await env.DB.prepare(`UPDATE events SET title=?,description=?,location=?,start_date=?,start_time=?,end_date=?,end_time=?,all_day=?,url=?,updated_at=datetime('now') WHERE id=? AND calendar_id=?`)
      .bind(b.title,b.description||'',b.location||'',b.start_date,b.start_time||null,b.end_date||b.start_date,b.end_time||null,b.all_day?1:0,b.url||'',eid,cal.id).run();
    return json({id:eid,calendar_id:cal.id,...b});
  }
  if (method==='DELETE'&&evI) {
    const {cal}=await checkCalAccess(req,env,parseInt(evI[1]));
    await env.DB.prepare(`DELETE FROM events WHERE id=? AND calendar_id=?`).bind(parseInt(evI[2]),cal.id).run();
    return json({deleted:true});
  }

  // ── REPORTS ──────────────────────────────────────────────────

  const repM=route.match(/^calendars\/(\d+)\/report$/);
  if (method==='POST'&&repM) {
    const b=await req.json().catch(()=>null); if(!b?.reason) return err('reason required');
    const u=await getUser(req,env);
    await env.DB.prepare(`INSERT INTO reports(calendar_id,reporter_id,reason,details) VALUES(?,?,?,?)`)
      .bind(parseInt(repM[1]),u?u.id:null,b.reason,b.details||'').run();
    await env.DB.prepare(`UPDATE calendars SET report_count=report_count+1 WHERE id=?`).bind(parseInt(repM[1])).run();
    return json({ok:true});
  }

  // ── MODERATION ───────────────────────────────────────────────

  if (method==='GET'&&route==='mod/pending') {
    await needStaff(req,env);
    const {results}=await env.DB.prepare(`SELECT c.*,u.username as owner_username,u.email as owner_email FROM calendars c LEFT JOIN users u ON c.owner_id=u.id WHERE c.approval_status='pending' ORDER BY c.created_at ASC`).all();
    return json(results);
  }
  if (method==='GET'&&route==='mod/reports') {
    await needStaff(req,env);
    const {results}=await env.DB.prepare(`SELECT r.*,c.name as cal_name,c.slug as cal_slug,u.username as reporter FROM reports r JOIN calendars c ON r.calendar_id=c.id LEFT JOIN users u ON r.reporter_id=u.id WHERE r.status='open' ORDER BY r.created_at DESC`).all();
    return json(results);
  }

  const modCalBase=route.match(/^mod\/calendar\/(\d+)\//);
  if (modCalBase) {
    const mod=await needStaff(req,env); const cid=parseInt(modCalBase[1]);
    if (method==='GET'&&route.endsWith('/log')) {
      const {results}=await env.DB.prepare(`SELECT ml.*,u.username as mod_username FROM moderation_log ml LEFT JOIN users u ON ml.moderator_id=u.id WHERE ml.calendar_id=? ORDER BY ml.created_at ASC`).bind(cid).all();
      return json(results);
    }
    if (method==='POST'&&route.endsWith('/approve')) {
      const b=await req.json().catch(()=>({}));
      await env.DB.prepare(`UPDATE calendars SET approval_status='approved',decline_reason=NULL WHERE id=?`).bind(cid).run();
      await env.DB.prepare(`INSERT INTO moderation_log(calendar_id,moderator_id,action,comment) VALUES(?,?,'approve',?)`).bind(cid,mod.id,b.comment||null).run();
      return json({ok:true});
    }
    if (method==='POST'&&route.endsWith('/decline')) {
      const b=await req.json().catch(()=>null); if(!b?.reason) return err('reason required');
      const cal=await env.DB.prepare(`SELECT * FROM calendars WHERE id=?`).bind(cid).first();
      const dc=(cal.decline_count||0)+1;
      await env.DB.prepare(`UPDATE calendars SET approval_status='declined',decline_reason=?,decline_count=? WHERE id=?`).bind(b.reason,dc,cid).run();
      await env.DB.prepare(`INSERT INTO moderation_log(calendar_id,moderator_id,action,reason,comment) VALUES(?,?,'decline',?,?)`).bind(cid,mod.id,b.reason,b.comment||null).run();
      if (cal.owner_id) await env.DB.prepare(`UPDATE users SET decline_count=decline_count+1 WHERE id=?`).bind(cal.owner_id).run();
      return json({ok:true,decline_count:dc});
    }
    if (method==='POST'&&route.endsWith('/comment')) {
      const b=await req.json().catch(()=>null); if(!b?.comment) return err('comment required');
      await env.DB.prepare(`INSERT INTO moderation_log(calendar_id,moderator_id,action,comment) VALUES(?,?,'comment',?)`).bind(cid,mod.id,b.comment).run();
      return json({ok:true});
    }
    if (method==='POST'&&route.endsWith('/warn')) {
      const b=await req.json().catch(()=>null); if(!b?.warning) return err('warning text required');
      await env.DB.prepare(`UPDATE calendars SET warning_text=? WHERE id=?`).bind(b.warning,cid).run();
      await env.DB.prepare(`INSERT INTO moderation_log(calendar_id,moderator_id,action,comment) VALUES(?,?,'warn',?)`).bind(cid,mod.id,b.warning).run();
      return json({ok:true});
    }
    if (method==='POST'&&route.endsWith('/remove-warning')) {
      await env.DB.prepare(`UPDATE calendars SET warning_text=NULL WHERE id=?`).bind(cid).run();
      await env.DB.prepare(`INSERT INTO moderation_log(calendar_id,moderator_id,action,comment) VALUES(?,?,'remove_warning','Warning removed')`).bind(cid,mod.id).run();
      return json({ok:true});
    }
    if (method==='POST'&&route.endsWith('/badge')) {
      const b=await req.json().catch(()=>({}));
      await env.DB.prepare(`UPDATE calendars SET verified_badge=? WHERE id=?`).bind(b.grant?1:0,cid).run();
      await env.DB.prepare(`INSERT INTO moderation_log(calendar_id,moderator_id,action) VALUES(?,?,?)`).bind(cid,mod.id,b.grant?'badge':'unbadge').run();
      return json({ok:true});
    }
  }

  const modRepBase=route.match(/^mod\/reports\/(\d+)\/(dismiss|reviewed)$/);
  if (method==='POST'&&modRepBase) {
    await needStaff(req,env);
    await env.DB.prepare(`UPDATE reports SET status=? WHERE id=?`).bind(modRepBase[2],parseInt(modRepBase[1])).run();
    return json({ok:true});
  }

  // ── ADMIN ────────────────────────────────────────────────────

  if (method==='GET'&&route==='admin/users') {
    await needAdmin(req,env);
    const {results}=await env.DB.prepare(`SELECT id,username,email,role,verified_badge,decline_count,banned,ban_reason,created_at,last_login FROM users ORDER BY created_at DESC`).all();
    return json(results);
  }

  const adminUserRole=route.match(/^admin\/users\/(\d+)\/role$/);
  if (method==='POST'&&adminUserRole) {
    await needAdmin(req,env); const b=await req.json().catch(()=>null);
    if (!['user','staff','admin'].includes(b?.role)) return err('Invalid role');
    await env.DB.prepare(`UPDATE users SET role=? WHERE id=?`).bind(b.role,parseInt(adminUserRole[1])).run();
    return json({ok:true});
  }

  const adminUserBan=route.match(/^admin\/users\/(\d+)\/(ban|unban)$/);
  if (method==='POST'&&adminUserBan) {
    await needAdmin(req,env); const uid=parseInt(adminUserBan[1]); const b=await req.json().catch(()=>({}));
    if (adminUserBan[2]==='ban') await env.DB.prepare(`UPDATE users SET banned=1,ban_reason=? WHERE id=?`).bind(b.reason||'Banned',uid).run();
    else await env.DB.prepare(`UPDATE users SET banned=0,ban_reason=NULL WHERE id=?`).bind(uid).run();
    return json({ok:true});
  }

  const adminUserBadge=route.match(/^admin\/users\/(\d+)\/badge$/);
  if (method==='POST'&&adminUserBadge) {
    await needAdmin(req,env); const b=await req.json().catch(()=>({}));
    await env.DB.prepare(`UPDATE users SET verified_badge=? WHERE id=?`).bind(b.grant?1:0,parseInt(adminUserBadge[1])).run();
    return json({ok:true});
  }

  const adminCalDel=route.match(/^admin\/calendars\/(\d+)$/);
  if (method==='DELETE'&&adminCalDel) {
    await needAdmin(req,env); const id=parseInt(adminCalDel[1]);
    for (const t of ['events','moderation_log','reports'])
      await env.DB.prepare(`DELETE FROM ${t} WHERE calendar_id=?`).bind(id).run();
    await env.DB.prepare(`DELETE FROM calendars WHERE id=?`).bind(id).run();
    return json({deleted:true});
  }
  if (method==='PUT'&&adminCalDel) {
    await needStaff(req,env); const id=parseInt(adminCalDel[1]); const b=await req.json().catch(()=>null);
    if(!b?.name||!b?.slug) return err('name and slug required');
    await env.DB.prepare(`UPDATE calendars SET name=?,slug=?,description=?,color=?,status=?,approval_status=?,updated_at=datetime('now') WHERE id=?`)
      .bind(b.name,b.slug,b.description||'',b.color||'#6ee7b7',b.status||'active',b.approval_status||'approved',id).run();
    return json({id,...b});
  }

  return new Response('Not found',{status:404,headers:CORS});

  } catch(e) {
    if (e.s) return err(e.m,e.s);
    console.error(e); return err('Server error: '+e.message,500);
  }
}
