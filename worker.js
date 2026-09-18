import { connect } from "cloudflare:sockets";

/*
  dollax26
  Cloudflare Worker VPN Panel
  Smooth modern UI + multi-protocol VPN management
  Default super-admin:
    username: dollax26
    password: hesan356xbox123
*/

const PANEL_DEFAULT = "dollax26";
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

const CF_PORTS = [
  80, 8080, 8880, 2052, 2082, 2086, 2095,
  443, 2053, 2083, 2087, 2096, 8443
];

const TLS_PORTS = [
  443, 2053, 2083, 2087, 2096, 8443
];

const DEFAULT_INBOUNDS = [
  {
    name: "VLESS Edge",
    protocol: "vless",
    ports: [443, 8443],
    tls: [443, 8443],
    plain: []
  },
  {
    name: "VMess Edge",
    protocol: "vmess",
    ports: [8080, 80],
    tls: [],
    plain: [8080, 80]
  },
  {
    name: "Trojan Edge",
    protocol: "trojan",
    ports: [2096, 2053],
    tls: [2096, 2053],
    plain: []
  },
  {
    name: "Shadowsocks Edge",
    protocol: "shadowsocks",
    ports: [8080, 80],
    tls: [],
    plain: [8080, 80]
  }
];

function DB(env) {
  return env.IOT_DB;
}

function now() {
  return Date.now();
}

function id() {
  return crypto.randomUUID();
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json;charset=UTF-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type",
      ...extra
    }
  });
}

function text(data, status = 200) {
  return new Response(String(data), {
    status,
    headers: {
      "content-type": "text/plain;charset=UTF-8"
    }
  });
}

function page(data, status = 200) {
  return new Response(data, {
    status,
    headers: {
      "content-type": "text/html;charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}

function cookies(req) {
  const raw = req.headers.get("Cookie") || "";
  const out = {};

  for (const part of raw.split(";")) {
    const i = part.indexOf("=");

    if (i < 0) continue;

    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1));
  }

  return out;
}

function setSession(token) {
  return (
    "vpn-ui=" +
    encodeURIComponent(token) +
    "; Path=/; Max-Age=" +
    Math.floor(SESSION_TTL / 1000) +
    "; HttpOnly; Secure; SameSite=Lax"
  );
}

function clearSession() {
  return "vpn-ui=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax";
}

async function sha256(value) {
  const data = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function safeJSON(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function hostOnly(value) {
  return String(value || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "");
}

function supportedPort(port) {
  return CF_PORTS.includes(Number(port));
}

function isTLSPort(port) {
  return TLS_PORTS.includes(Number(port));
}

function bytes(n) {
  let x = Number(n || 0);
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;

  while (x >= 1024 && i < u.length - 1) {
    x /= 1024;
    i++;
  }

  return x.toFixed(i ? 2 : 0) + " " + u[i];
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new TextEncoder().encode(String(value));
}

function joinBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function textBytes(value) {
  return new TextDecoder().decode(value);
}

function sameBytes(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;

  let n = 0;
  for (let i = 0; i < a.length; i++) {
    n |= a[i] ^ b[i];
  }

  return n === 0;
}

function uuidBytes(value) {
  const s = String(value || "").replaceAll("-", "").toLowerCase();

  if (s.length !== 32) {
    return null;
  }

  const out = new Uint8Array(16);

  for (let i = 0; i < 16; i++) {
    const n = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(n)) return null;
    out[i] = n;
  }

  return out;
}

function validIP(value) {
  const s = String(value || "").trim();

  const v4 = s.match(/^(\d{1,3}\.){3}\d{1,3}$/);

  if (v4) {
    return s.split(".").every((x) => Number(x) >= 0 && Number(x) <= 255);
  }

  return s.includes(":") && /^[0-9a-fA-F:]+$/.test(s);
}

function privateTarget(host) {
  const h = String(host || "").trim().toLowerCase();

  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h === "127.0.0.1" ||
    h === "0.0.0.0" ||
    h === "::1"
  ) {
    return true;
  }

  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);

  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);

    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
  }

  return h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:");
}

async function addColumn(db, table, column, definition) {
  const info = await db.prepare("PRAGMA table_info(" + table + ")").all();
  const names = (info.results || []).map((x) => x.name);

  if (!names.includes(column)) {
    await db.prepare("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition).run();
  }
}

let INIT = null;

async function initDB(env) {
  if (INIT) return INIT;

  INIT = (async () => {
    const db = DB(env);

    if (!db) {
      throw new Error("D1 binding IOT_DB is missing");
    }

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS admins(" +
        "username TEXT PRIMARY KEY," +
        "password_hash TEXT NOT NULL," +
        "display_name TEXT DEFAULT ''," +
        "role TEXT DEFAULT 'admin'," +
        "permissions_json TEXT DEFAULT '{}'," +
        "enabled INTEGER DEFAULT 1," +
        "created INTEGER DEFAULT 0" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS sessions(" +
        "token TEXT PRIMARY KEY," +
        "username TEXT NOT NULL," +
        "expires INTEGER NOT NULL" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS outbounds(" +
        "id TEXT PRIMARY KEY," +
        "name TEXT NOT NULL," +
        "type TEXT NOT NULL" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS inbounds(" +
        "id TEXT PRIMARY KEY," +
        "name TEXT NOT NULL," +
        "protocol TEXT NOT NULL," +
        "port INTEGER NOT NULL," +
        "path TEXT NOT NULL UNIQUE" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS clients(" +
        "id TEXT PRIMARY KEY," +
        "inbound_id TEXT NOT NULL," +
        "name TEXT NOT NULL," +
        "uuid TEXT NOT NULL UNIQUE," +
        "password TEXT NOT NULL" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS clean_ips(" +
        "id TEXT PRIMARY KEY," +
        "ip TEXT NOT NULL UNIQUE," +
        "label TEXT DEFAULT ''," +
        "enabled INTEGER DEFAULT 1," +
        "created INTEGER DEFAULT 0" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS client_ips(" +
        "client_id TEXT NOT NULL," +
        "ip TEXT NOT NULL," +
        "last_seen INTEGER NOT NULL," +
        "PRIMARY KEY(client_id,ip)" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS logs(" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
        "t INTEGER NOT NULL," +
        "event TEXT NOT NULL," +
        "ip TEXT," +
        "info TEXT" +
        ")"
    ).run();

    await db.prepare(
      "CREATE TABLE IF NOT EXISTS app_settings(" +
        "key TEXT PRIMARY KEY," +
        "value TEXT" +
        ")"
    ).run();

    const columns = [
      ["outbounds", "host", "TEXT DEFAULT ''"],
      ["outbounds", "port", "INTEGER DEFAULT 0"],
      ["outbounds", "username", "TEXT DEFAULT ''"],
      ["outbounds", "password", "TEXT DEFAULT ''"],
      ["outbounds", "enabled", "INTEGER DEFAULT 1"],
      ["outbounds", "created", "INTEGER DEFAULT 0"],
      ["outbounds", "remark", "TEXT DEFAULT ''"],

      ["inbounds", "outbound_id", "TEXT DEFAULT ''"],
      ["inbounds", "enabled", "INTEGER DEFAULT 1"],
      ["inbounds", "created", "INTEGER DEFAULT 0"],
      ["inbounds", "ports_json", "TEXT DEFAULT '[]'"],
      ["inbounds", "tls_ports_json", "TEXT DEFAULT '[]'"],
      ["inbounds", "plain_ports_json", "TEXT DEFAULT '[]'"],
      ["inbounds", "traffic_limit", "INTEGER DEFAULT 0"],
      ["inbounds", "max_clients", "INTEGER DEFAULT 0"],
      ["inbounds", "xray_path", "TEXT DEFAULT ''"],

      ["clients", "outbound_id", "TEXT DEFAULT ''"],
      ["clients", "enabled", "INTEGER DEFAULT 1"],
      ["clients", "up", "INTEGER DEFAULT 0"],
      ["clients", "down", "INTEGER DEFAULT 0"],
      ["clients", "created", "INTEGER DEFAULT 0"],
      ["clients", "quota", "INTEGER DEFAULT 0"],
      ["clients", "expiry", "INTEGER DEFAULT 0"],
      ["clients", "limit_ip", "INTEGER DEFAULT 0"],
      ["clients", "sub_token", "TEXT DEFAULT ''"],
      ["clients", "email", "TEXT DEFAULT ''"],
      ["clients", "comment", "TEXT DEFAULT ''"],

      ["admins", "display_name", "TEXT DEFAULT ''"],
      ["admins", "role", "TEXT DEFAULT 'admin'"],
      ["admins", "permissions_json", "TEXT DEFAULT '{}'"],
      ["admins", "enabled", "INTEGER DEFAULT 1"],
      ["admins", "created", "INTEGER DEFAULT 0"]
    ];

    for (const item of columns) {
      await addColumn(db, item[0], item[1], item[2]);
    }

    const settings = [
      ["panel_name", PANEL_DEFAULT],
      ["public_host", ""],
      ["xray_origin", ""]
    ];

    for (const [key, value] of settings) {
      const existing = await db.prepare("SELECT key FROM app_settings WHERE key=?").bind(key).first();
      if (!existing) {
        await db.prepare("INSERT INTO app_settings(key,value) VALUES(?,?)").bind(key, value).run();
      }
    }

    const owner = await db.prepare("SELECT * FROM admins ORDER BY created ASC LIMIT 1").first();

    if (!owner) {
      await db.prepare(
        "INSERT INTO admins(" +
          "username,password_hash,display_name,role,permissions_json,enabled,created" +
          ") VALUES(?,?,?,?,?,?,?)"
      ).bind(
        "dollax26",
        await sha256("hesan356xbox123"),
        "Dollax26",
        "owner",
        JSON.stringify({
          view: true,
          createClient: true,
          editClient: true,
          deleteClient: true,
          createInbound: true,
          editInbound: true,
          deleteInbound: true,
          manageOutbounds: true,
          manageCleanIPs: true,
          manageAdmins: true,
          manageSettings: true,
          viewLogs: true
        }),
        1,
        now()
      ).run();
    } else {
      const adminRow = await db.prepare("SELECT username FROM admins WHERE username=?").bind("dollax26").first();
      if (!adminRow) {
        await db.prepare(
          "INSERT INTO admins(username,password_hash,display_name,role,permissions_json,enabled,created) VALUES(?,?,?,?,?,?,?)"
        ).bind(
          "dollax26",
          await sha256("hesan356xbox123"),
          "Dollax26",
          "owner",
          JSON.stringify({
            view: true,
            createClient: true,
            editClient: true,
            deleteClient: true,
            createInbound: true,
            editInbound: true,
            deleteInbound: true,
            manageOutbounds: true,
            manageCleanIPs: true,
            manageAdmins: true,
            manageSettings: true,
            viewLogs: true
          }),
          1,
          now()
        ).run();
      }
    }

    const outCount = await db.prepare("SELECT COUNT(*) n FROM outbounds").first();

    if (Number(outCount.n || 0) === 0) {
      const germany = id();
      const direct = id();
      const block = id();

      await db.prepare(
        "INSERT INTO outbounds(id,name,type,host,port,username,password,enabled,created,remark) VALUES(?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        germany,
        "GERMANY SOCKS5",
        "socks5",
        String(env.GERMANY_SOCKS_HOST || ""),
        Number(env.GERMANY_SOCKS_PORT || 1080),
        String(env.GERMANY_SOCKS_USERNAME || ""),
        String(env.GERMANY_SOCKS_PASSWORD || ""),
        1,
        now(),
        "Germany exit"
      ).run();

      await db.prepare(
        "INSERT INTO outbounds(id,name,type,host,port,username,password,enabled,created,remark) VALUES(?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        direct,
        "DIRECT",
        "direct",
        "",
        0,
        "",
        "",
        1,
        now(),
        "Worker edge"
      ).run();

      await db.prepare(
        "INSERT INTO outbounds(id,name,type,host,port,username,password,enabled,created,remark) VALUES(?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        block,
        "BLOCK",
        "block",
        "",
        0,
        "",
        "",
        1,
        now(),
        "Blocked route"
      ).run();
    }

    const inboundCount = await db.prepare("SELECT COUNT(*) n FROM inbounds").first();
    const outbound = await db.prepare(
      "SELECT id FROM outbounds WHERE enabled=1 ORDER BY created ASC LIMIT 1"
    ).first();

    if (Number(inboundCount.n || 0) === 0 && outbound) {
      for (const preset of DEFAULT_INBOUNDS) {
        const path = "/ws/" + preset.protocol + "-" + Math.random().toString(36).slice(2, 10);

        await db.prepare(
          "INSERT INTO inbounds(id,name,protocol,port,path,enabled,outbound_id,created,ports_json,tls_ports_json,plain_ports_json,traffic_limit,max_clients,xray_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(
          id(),
          preset.name,
          preset.protocol,
          preset.ports[0],
          path,
          1,
          outbound.id,
          now(),
          JSON.stringify(preset.ports),
          JSON.stringify(preset.tls),
          JSON.stringify(preset.plain),
          0,
          0,
          path
        ).run();
      }
    }

    const oldInbounds = await db.prepare("SELECT * FROM inbounds").all();
    for (const ib of (oldInbounds.results || [])) {
      let ports = safeJSON(ib.ports_json, []);
      if (!Array.isArray(ports) || !ports.length) {
        ports = [Number(ib.port)].filter(supportedPort);
      }

      let tls = safeJSON(ib.tls_ports_json, []);
      let plain = safeJSON(ib.plain_ports_json, []);

      if (!tls.length && !plain.length) {
        tls = ports.filter(isTLSPort);
        plain = ports.filter((x) => !isTLSPort(x));
      }

      await db.prepare(
        "UPDATE inbounds SET ports_json=?,tls_ports_json=?,plain_ports_json=?,xray_path=?,enabled=COALESCE(enabled,1),created=COALESCE(created,?) WHERE id=?"
      ).bind(
        JSON.stringify([...new Set(ports)]),
        JSON.stringify([...new Set(tls)]),
        JSON.stringify([...new Set(plain)]),
        ib.xray_path || ib.path,
        ib.created || now(),
        ib.id
      ).run();
    }

    const oldClients = await db.prepare("SELECT id,sub_token FROM clients").all();
    for (const c of (oldClients.results || [])) {
      if (!c.sub_token) {
        await db.prepare("UPDATE clients SET sub_token=? WHERE id=?").bind(id() + "-" + id(), c.id).run();
      }
    }
  })();

  return INIT;
}

async function getSetting(env, key, fallback = "") {
  const row = await DB(env)
    .prepare("SELECT value FROM app_settings WHERE key=?")
    .bind(key)
    .first();

  return row ? String(row.value || "") : fallback;
}

async function setSetting(env, key, value) {
  await DB(env)
    .prepare(
      "INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    )
    .bind(key, String(value == null ? "" : value))
    .run();
}

async function currentUser(env, req) {
  const token = cookies(req)["vpn-ui"];

  if (!token) return null;

  return DB(env)
    .prepare(
      "SELECT s.*,a.display_name,a.role,a.permissions_json,a.enabled " +
        "FROM sessions s " +
        "JOIN admins a ON a.username=s.username " +
        "WHERE s.token=? AND s.expires>? AND a.enabled=1 LIMIT 1"
    )
    .bind(token, now())
    .first();
}

function allowed(user, permission) {
  if (!user) return false;
  if (user.role === "owner") return true;

  const p = safeJSON(user.permissions_json, {});
  return p[permission] === true;
}

async function log(env, event, req, info = "") {
  try {
    await DB(env)
      .prepare("INSERT INTO logs(t,event,ip,info) VALUES(?,?,?,?)")
      .bind(now(), event, req.headers.get("CF-Connecting-IP") || "", info)
      .run();
  } catch {}
}

async function exactRead(reader, length) {
  const out = new Uint8Array(length);
  let pos = 0;

  while (pos < length) {
    const r = await reader.read();

    if (r.done) throw new Error("Socket closed");

    const chunk = toBytes(r.value);

    if (pos + chunk.length > length) {
      throw new Error("Invalid socket response");
    }

    out.set(chunk, pos);
    pos += chunk.length;
  }

  return out;
}

async function socks5(outbound, host, port) {
  const socket = connect({
    hostname: hostOnly(outbound.host),
    port: Number(outbound.port),
    secureTransport: "off"
  });

  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();

  const username = String(outbound.username || "");
  const password = String(outbound.password || "");

  if (username) {
    await writer.write(new Uint8Array([5, 2, 0, 2]));
  } else {
    await writer.write(new Uint8Array([5, 1, 0]));
  }

  const method = await exactRead(reader, 2);

  if (method[0] !== 5) throw new Error("Bad SOCKS5 server");

  if (username && method[1] === 2) {
    const u = new TextEncoder().encode(username);
    const p = new TextEncoder().encode(password);
    const auth = new Uint8Array(3 + u.length + p.length);

    auth[0] = 1;
    auth[1] = u.length;
    auth.set(u, 2);
    auth[2 + u.length] = p.length;
    auth.set(p, 3 + u.length);

    await writer.write(auth);

    const ar = await exactRead(reader, 2);
    if (ar[1] !== 0) throw new Error("SOCKS5 authentication failed");
  } else if (method[1] !== 0) {
    throw new Error("SOCKS5 authentication unavailable");
  }

  let atype = 3;
  let address;

  const v4 = hostOnly(host).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);

  if (v4) {
    atype = 1;
    address = new Uint8Array([
      Number(v4[1]), Number(v4[2]), Number(v4[3]), Number(v4[4])
    ]);
  } else {
    const h = new TextEncoder().encode(hostOnly(host));

    if (h.length > 255) {
      throw new Error("Hostname too long");
    }

    address = new Uint8Array(1 + h.length);
    address[0] = h.length;
    address.set(h, 1);
  }

  const request = new Uint8Array(4 + address.length + 2);
  request[0] = 5;
  request[1] = 1;
  request[2] = 0;
  request[3] = atype;

  request.set(address, 4);
  request[4 + address.length] = (Number(port) >> 8) & 255;
  request[5 + address.length] = Number(port) & 255;

  await writer.write(request);

  const h = await exactRead(reader, 4);

  if (h[0] !== 5 || h[1] !== 0) {
    throw new Error("SOCKS5 CONNECT failed");
  }

  if (h[3] === 1) {
    await exactRead(reader, 6);
  } else if (h[3] === 3) {
    const n = await exactRead(reader, 1);
    await exactRead(reader, n[0] + 2);
  } else if (h[3] === 4) {
    await exactRead(reader, 18);
  }

  return { socket, reader, writer };
}

function parseAddress(data, index, type) {
  if (type === 1) {
    if (data.length < index + 4) return null;
    return {
      host: [data[index], data[index + 1], data[index + 2], data[index + 3]].join("."),
      index: index + 4
    };
  }

  if (type === 2) {
    if (data.length < index + 1) return null;

    const length = data[index];
    index++;

    if (data.length < index + length) return null;

    return {
      host: textBytes(data.slice(index, index + length)),
      index: index + length
    };
  }

  if (type === 3) {
    if (data.length < index + 16) return null;

    const p = [];
    for (let i = 0; i < 16; i += 2) {
      p.push(((data[index + i] << 8) | data[index + i + 1]).toString(16));
    }

    return {
      host: p.join(":"),
      index: index + 16
    };
  }

  return null;
}

function parseVLESS(data) {
  if (data.length < 22) return null;

  const version = data[0];
  const uuid = data.slice(1, 17);
  const addonLength = data[17];
  let i = 18 + addonLength;

  if (data.length < i + 4) return null;

  const command = data[i];
  const port = (data[i + 1] << 8) | data[i + 2];
  const addressType = data[i + 3];
  i += 4;

  if (command !== 1) {
    throw new Error("Only TCP VLESS is supported");
  }

  const address = parseAddress(data, i, addressType);

  if (!address) {
    return null;
  }

  return {
    version,
    uuid,
    host: address.host,
    port,
    offset: address.index
  };
}

function sha224(message) {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4d2a0df8,0x53380d13,0x650a7354,
    0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,
    0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,
    0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,
    0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,
    0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];

  const H = [
    0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,
    0x64f98fa7,0xbefa4fa4
  ];

  const input = message instanceof Uint8Array
    ? message
    : new TextEncoder().encode(String(message));

  const bitLength = input.length * 8;
  const length = Math.ceil((input.length + 9) / 64) * 64;
  const data = new Uint8Array(length);

  data.set(input);
  data[input.length] = 128;

  const view = new DataView(data.buffer);
  view.setUint32(length - 8, Math.floor(bitLength / 0x100000000), false);
  view.setUint32(length - 4, bitLength >>> 0, false);

  function rotr(x, n) {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
  }

  function add() {
    let x = 0;
    for (let i = 0; i < arguments.length; i++) {
      x = (x + arguments[i]) >>> 0;
    }
    return x;
  }

  const W = new Uint32Array(64);

  for (let off = 0; off < length; off += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(off + i * 4, false);
    }

    for (let i = 16; i < 64; i++) {
      const s0 = (
        rotr(W[i - 15], 7) ^
        rotr(W[i - 15], 18) ^
        (W[i - 15] >>> 3)
      ) >>> 0;

      const s1 = (
        rotr(W[i - 2], 17) ^
        rotr(W[i - 2], 19) ^
        (W[i - 2] >>> 10)
      ) >>> 0;

      W[i] = add(W[i - 16], s0, W[i - 7], s1);
    }

    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];
    let f = H[5];
    let g = H[6];
    let h = H[7];

    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ ((~e) & g)) >>> 0;
      const t1 = add(h, S1, ch, K[i], W[i]);
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = add(S0, maj);

      h = g;
      g = f;
      f = e;
      e = add(d, t1);
      d = c;
      c = b;
      b = a;
      a = add(t1, t2);
    }

    H[0] = add(H[0], a);
    H[1] = add(H[1], b);
    H[2] = add(H[2], c);
    H[3] = add(H[3], d);
    H[4] = add(H[4], e);
    H[5] = add(H[5], f);
    H[6] = add(H[6], g);
    H[7] = add(H[7], h);
  }

  return H.slice(0, 7)
    .map((x) => x.toString(16).padStart(8, "0"))
    .join("");
}

function parseTrojan(data) {
  if (data.length < 62) return null;

  const passwordHash = textBytes(data.slice(0, 56));

  if (data[56] !== 13 || data[57] !== 10) {
    throw new Error("Invalid Trojan header");
  }

  let i = 58;

  if (data.length < i + 4) return null;

  const version = data[i];
  const command = data[i + 1];
  const reserved = data[i + 2];
  const type = data[i + 3];

  if (version !== 5 || reserved !== 0 || command !== 1) {
    throw new Error("Invalid Trojan request");
  }

  i += 4;

  const address = parseAddress(data, i, type);

  if (!address) {
    return null;
  }

  i = address.index;

  if (data.length < i + 2) return null;

  const port = (data[i] << 8) | data[i + 1];
  i += 2;

  return {
    passwordHash,
    host: address.host,
    port,
    offset: i
  };
}

function base64UTF8(value) {
  const bytes = new TextEncoder().encode(String(value));
  let s = "";

  for (let i = 0; i < bytes.length; i += 8192) {
    s += String.fromCharCode.apply(null, bytes.slice(i, i + 8192));
  }

  return btoa(s);
}

function endpointList(env, req) {
  return DB(env)
    .prepare("SELECT ip,label FROM clean_ips WHERE enabled=1 ORDER BY created ASC")
    .all()
    .then((r) => {
      const arr = (r.results || []).map((x) => ({
        address: x.ip,
        label: x.label
      }));

      if (!arr.length) {
        arr.push({
          address: hostOnly(getSettingSyncFallback(req)),
          label: "Worker"
        });
      }

      return arr;
    });
}

async function endpoints(env, req) {
  const publicHost =
    hostOnly(await getSetting(env, "public_host")) || new URL(req.url).hostname;

  const r = await DB(env)
    .prepare("SELECT ip,label FROM clean_ips WHERE enabled=1 ORDER BY created ASC")
    .all();

  let items = (r.results || []).map((x) => ({
    address: x.ip,
    label: x.label || ""
  }));

  if (!items.length) {
    items = [{ address: publicHost, label: "Worker" }];
  }

  return { publicHost, items };
}

function getSettingSyncFallback(req) {
  return new URL(req.url).hostname;
}

function buildLink(req, client, inbound, address, tls) {
  const host = hostOnly(address);
  const sni = hostOnly(client.public_host || new URL(req.url).hostname);
  const protocol = inbound.protocol;

  const p = new URLSearchParams();
  p.set("type", "ws");
  p.set("path", inbound.path);
  p.set("host", sni);

  if (tls) {
    p.set("security", "tls");
    p.set("sni", sni);
  } else {
    p.set("security", "none");
  }

  if (protocol === "vless") {
    p.set("encryption", "none");

    return (
      "vless://" +
      encodeURIComponent(client.uuid) +
      "@" +
      host +
      ":" +
      inbound.port +
      "?" +
      p.toString() +
      "#" +
      encodeURIComponent(client.name + " " + inbound.name)
    );
  }

  if (protocol === "trojan") {
    return (
      "trojan://" +
      encodeURIComponent(client.password) +
      "@" +
      host +
      ":" +
      inbound.port +
      "?" +
      p.toString() +
      "#" +
      encodeURIComponent(client.name + " " + inbound.name)
    );
  }

  if (protocol === "vmess") {
    const obj = {
      v: "2",
      ps: client.name + " " + inbound.name,
      add: host,
      port: String(inbound.port),
      id: client.uuid,
      aid: "0",
      scy: "auto",
      net: "ws",
      type: "none",
      host: sni,
      path: inbound.path,
      tls: tls ? "tls" : "",
      sni: tls ? sni : ""
    };

    return "vmess://" + base64UTF8(JSON.stringify(obj));
  }

  if (protocol === "shadowsocks") {
    const auth = base64UTF8("aes-128-gcm:" + client.password).replace(/=+$/, "");
    const plugin =
      "v2ray-plugin;mode=websocket;host=" +
      sni +
      ";path=" +
      inbound.path +
      (tls ? ";tls" : "");

    return (
      "ss://" +
      auth +
      "@" +
      host +
      ":" +
      inbound.port +
      "?plugin=" +
      encodeURIComponent(plugin) +
      "#" +
      encodeURIComponent(client.name + " " + inbound.name)
    );
  }

  return "";
}

async function nodesForClient(env, req, client) {
  const inbound = await DB(env)
    .prepare("SELECT * FROM inbounds WHERE id=?")
    .bind(client.inbound_id)
    .first();

  if (!inbound) {
    return [];
  }

  const ep = await endpoints(env, req);

  let ports = safeJSON(inbound.ports_json, [inbound.port]);
  ports = Array.from(new Set(ports.map(Number).filter(supportedPort))).slice(0, 4);

  const tls = safeJSON(inbound.tls_ports_json, []);

  const out = [];

  for (const item of ep.items) {
    for (const port of ports) {
      const copy = { ...inbound, port };
      const link = buildLink(req, client, copy, item.address, tls.includes(port));
      out.push({
        address: item.address,
        label: item.label,
        port,
        tls: tls.includes(port),
        link,
        protocol: inbound.protocol
      });
    }
  }

  return out;
}

function expired(client) {
  return Number(client.expiry || 0) > 0 && Number(client.expiry) <= now();
}

function quotaReached(client) {
  const q = Number(client.quota || 0);

  if (q <= 0) return false;

  return (Number(client.up || 0) + Number(client.down || 0)) >= q;
}

async function ipLimit(env, req, client) {
  const max = Number(client.limit_ip || 0);

  if (max <= 0) return true;

  const remote = req.headers.get("CF-Connecting-IP") || "";
  if (!remote) return true;

  const cutoff = now() - 10 * 60 * 1000;

  await DB(env)
    .prepare("DELETE FROM client_ips WHERE last_seen<?")
    .bind(cutoff)
    .run();

  const existing = await DB(env)
    .prepare("SELECT * FROM client_ips WHERE client_id=? AND ip=? LIMIT 1")
    .bind(client.id, remote)
    .first();

  if (!existing) {
    const count = await DB(env)
      .prepare("SELECT COUNT(*) n FROM client_ips WHERE client_id=? AND last_seen>=?")
      .bind(client.id, cutoff)
      .first();

    if (Number(count.n || 0) >= max) {
      return false;
    }
  }

  await DB(env)
    .prepare(
      "INSERT INTO client_ips(client_id,ip,last_seen) VALUES(?,?,?) ON CONFLICT(client_id,ip) DO UPDATE SET last_seen=excluded.last_seen"
    )
    .bind(client.id, remote, now())
    .run();

  return true;
}

async function outboundSocket(outbound, host, port) {
  if (privateTarget(host)) {
    throw new Error("Private destination blocked");
  }

  if (outbound.type === "block") {
    throw new Error("Blocked route");
  }

  if (outbound.type === "socks5") {
    return socks5(outbound, host, port);
  }

  if (outbound.type === "direct") {
    const socket = connect({
      hostname: hostOnly(host),
      port: Number(port),
      secureTransport: "off"
    });

    return {
      socket,
      reader: socket.readable.getReader(),
      writer: socket.writable.getWriter()
    };
  }

  throw new Error("Unsupported outbound");
}

async function relay(req, env, ctx, protocol) {
  if (req.headers.get("Upgrade") !== "websocket") {
    return text("WebSocket required", 426);
  }

  const path = new URL(req.url).pathname;

  const inbound = await DB(env)
    .prepare(
      "SELECT * FROM inbounds WHERE path=? AND protocol=? AND enabled=1 LIMIT 1"
    )
    .bind(path, protocol)
    .first();

  if (!inbound) {
    return text("Inbound not found", 404);
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  let buffer = new Uint8Array(0);
  let socket = null;
  let reader = null;
  let writer = null;

  let clientId = null;

  let up = 0;
  let down = 0;

  let savedUp = 0;
  let savedDown = 0;

  let connected = false;
  let closed = false;

  async function closeAll() {
    if (closed) return;

    closed = true;

    try { if (reader) await reader.cancel(); } catch {}
    try { if (writer) await writer.abort(); } catch {}
    try { if (socket) socket.close(); } catch {}

    if (clientId) {
      const du = up - savedUp;
      const dd = down - savedDown;

      if (du || dd) {
        ctx.waitUntil(
          DB(env)
            .prepare("UPDATE clients SET up=up+?,down=down+? WHERE id=?")
            .bind(Math.max(0, du), Math.max(0, dd), clientId)
            .run()
        );
      }
    }

    try {
      if (server.readyState === 1) server.close();
    } catch {}
  }

  async function storeTraffic() {
    if (!clientId) return;

    const du = up - savedUp;
    const dd = down - savedDown;

    if (!du && !dd) return;

    savedUp = up;
    savedDown = down;

    ctx.waitUntil(
      DB(env)
        .prepare("UPDATE clients SET up=up+?,down=down+? WHERE id=?")
        .bind(Math.max(0, du), Math.max(0, dd), clientId)
        .run()
    );
  }

  async function getClient(parsed) {
    const rows = await DB(env)
      .prepare("SELECT * FROM clients WHERE inbound_id=? AND enabled=1")
      .bind(inbound.id)
      .all();

    for (const c of (rows.results || [])) {
      if (protocol === "vless") {
        if (sameBytes(uuidBytes(c.uuid), parsed.uuid)) {
          return c;
        }
      } else if (protocol === "trojan") {
        if (sha224(c.password).toLowerCase() === String(parsed.passwordHash).toLowerCase()) {
          return c;
        }
      }
    }

    return null;
  }

  async function start(parsed, complete) {
    const c = await getClient(parsed);

    if (!c) throw new Error("Invalid client");
    if (c.enabled !== 1) throw new Error("Client disabled");
    if (expired(c)) throw new Error("Client expired");
    if (quotaReached(c)) throw new Error("Traffic quota reached");
    if (!(await ipLimit(env, req, c))) throw new Error("IP limit reached");

    clientId = c.id;

    const outbound = await DB(env)
      .prepare("SELECT * FROM outbounds WHERE id=? AND enabled=1 LIMIT 1")
      .bind(c.outbound_id || inbound.outbound_id)
      .first();

    if (!outbound) throw new Error("Outbound unavailable");

    const opened = await outboundSocket(outbound, parsed.host, parsed.port);
    socket = opened.socket;
    reader = opened.reader;
    writer = opened.writer;
    connected = true;

    const remaining = complete.slice(parsed.offset);

    if (remaining.length) {
      await writer.write(remaining);
      up += remaining.length;
    }

    if (protocol === "vless") {
      server.send(new Uint8Array([parsed.version, 0]));
    }

    ctx.waitUntil((async () => {
      try {
        while (!closed) {
          if (expired(c) || quotaReached(c)) break;

          const r = await reader.read();
          if (r.done) break;

          const data = toBytes(r.value);
          down += data.length;

          if (server.readyState === 1) {
            server.send(data);
          }

          if (up - savedUp + down - savedDown > 1024 * 1024) {
            await storeTraffic();
          }
        }
      } catch {}

      await closeAll();
    })());
  }

  server.addEventListener("message", (event) => {
    ctx.waitUntil((async () => {
      try {
        const data = toBytes(event.data);

        if (!connected) {
          buffer = joinBytes(buffer, data);

          if (buffer.length > 128 * 1024) {
            throw new Error("Handshake too large");
          }

          const parsed =
            protocol === "vless" ? parseVLESS(buffer) : parseTrojan(buffer);

          if (!parsed) return;

          await start(parsed, buffer);
          buffer = new Uint8Array(0);
        } else {
          up += data.length;
          await writer.write(data);

          if (up - savedUp + down - savedDown > 1024 * 1024) {
            await storeTraffic();
          }
        }
      } catch {
        await closeAll();
      }
    })());
  });

  server.addEventListener("close", () => ctx.waitUntil(closeAll()));
  server.addEventListener("error", () => ctx.waitUntil(closeAll()));

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

async function xrayBridge(req, env, inbound) {
  const origin = String(await getSetting(env, "xray_origin")).trim();

  if (!origin) {
    return text("Xray WebSocket bridge is not configured", 503);
  }

  let base;
  try {
    base = new URL(origin);
  } catch {
    return text("Invalid Xray bridge URL", 500);
  }

  base.pathname = inbound.xray_path || inbound.path;
  base.search = new URL(req.url).search;

  const headers = new Headers(req.headers);
  headers.set("X-Forwarded-Host", new URL(req.url).host);
  headers.set("X-Forwarded-Proto", "https");
  headers.delete("content-length");

  try {
    return await fetch(
      new Request(base.toString(), {
        method: req.method,
        headers,
        body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body
      })
    );
  } catch {
    return text("Xray bridge connection failed", 502);
  }
}

const DASHBOARD = String.raw`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dollax26</title>
<style>
:root{
  --bg:#0b1020;
  --bg-soft:#101827;
  --panel:#121d2d;
  --panel-2:#172334;
  --panel-3:#0f1726;
  --line:#243247;
  --text:#edf5ff;
  --muted:#90a3be;
  --accent:#26d0a8;
  --accent-2:#5ee6bf;
  --blue:#65a9ff;
  --red:#ff7d8f;
  --gold:#f6c86c;
  --shadow:0 24px 80px rgba(0,0,0,.36);
  --success:#1ecb9b;
  --warning:#f5c768;
  --danger:#ff6a7a;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;width:100%;height:100%;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;background:radial-gradient(circle at 20% 0%, rgba(24,111,118,.32), transparent 30%), linear-gradient(180deg,#0a0f18,#0b1220 32%, #0d1424);color:var(--text)}
body{overflow:hidden}
button,input,select,textarea{font:inherit}
button{cursor:pointer}
a{color:inherit;text-decoration:none}
.app{display:flex;width:100%;height:100vh}
.sidebar{width:240px;flex:0 0 240px;background:rgba(11,17,29,.74);backdrop-filter:blur(18px);border-right:1px solid var(--line);display:flex;flex-direction:column;position:relative;overflow:hidden}
.sidebar::before{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(38,208,168,.06),transparent 34%);pointer-events:none}
.brand{display:flex;align-items:center;gap:12px;padding:18px 18px 16px;border-bottom:1px solid var(--line);position:relative;z-index:1}
.brand-mark{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#1ce0b7,#0d8772);box-shadow:0 18px 36px rgba(38,208,168,.25);font-weight:900;font-size:20px}
.brand-text{line-height:1.1}
.brand-name{font-weight:900;letter-spacing:.3px;font-size:15px}
.brand-sub{font-size:8px;color:var(--muted);letter-spacing:2px;margin-top:3px;font-weight:700}
.nav{padding:14px 10px 8px;position:relative;z-index:1}
.nav button{display:flex;align-items:center;gap:10px;width:100%;height:42px;padding:0 13px;border:0;border-radius:10px;background:transparent;color:#b4c0cf;text-align:left;font-size:11px;letter-spacing:.1px;transition:.2s ease;position:relative}
.nav button:hover{background:rgba(255,255,255,.04);color:#eef7ff;transform:translateX(2px)}
.nav button.active{background:linear-gradient(90deg, rgba(38,208,168,.19), rgba(38,208,168,.04));color:var(--accent);box-shadow:inset 0 0 0 1px rgba(38,208,168,.14)}
.nav-icon{width:18px;display:inline-flex;justify-content:center;font-size:14px}
.side-foot{margin-top:auto;padding:14px 12px 16px;border-top:1px solid var(--line);position:relative;z-index:1}
.logout{width:100%;height:38px;border:1px solid var(--line);background:rgba(255,255,255,.02);border-radius:9px;color:#d5deeb;font-size:11px;padding:0 12px}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{height:72px;display:flex;align-items:center;justify-content:space-between;padding:0 22px;background:rgba(16,24,36,.5);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.top-title{font-weight:900;font-size:18px;letter-spacing:.2px}
.top-right{display:flex;align-items:center;gap:8px}
.pill{padding:6px 10px;border-radius:999px;border:1px solid var(--line);font-size:8px;letter-spacing:1px;text-transform:uppercase;color:#b1bed0;background:rgba(255,255,255,.02)}
.pill.ok{border-color:rgba(38,208,168,.4);background:rgba(22,94,79,.24);color:var(--accent)}
.content{flex:1;overflow:auto;padding:20px 20px 26px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.card{background:linear-gradient(180deg,rgba(18,29,45,.96),rgba(12,17,26,.96));border:1px solid var(--line);border-radius:12px;padding:16px;min-height:96px;box-shadow:0 12px 32px rgba(0,0,0,.18);transition:.2s ease;position:relative;overflow:hidden}
.card::before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.02),transparent 60%);pointer-events:none}
.card:hover{transform:translateY(-2px);border-color:#324662;box-shadow:var(--shadow)}
.card-label{font-size:8px;letter-spacing:1.4px;text-transform:uppercase;color:var(--muted)}
.card-value{font-size:28px;font-weight:900;margin-top:9px;letter-spacing:-.7px}
.card-sub{font-size:9px;color:var(--muted);margin-top:6px}
.grid2{display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-top:12px}
.panel{background:linear-gradient(180deg,rgba(18,29,45,.96),rgba(10,16,25,.96));border:1px solid var(--line);border-radius:12px;overflow:hidden;box-shadow:0 16px 36px rgba(0,0,0,.18)}
.panel-head{height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 14px;border-bottom:1px solid var(--line);background:rgba(255,255,255,.01)}
.panel-title{font-size:11px;font-weight:800;letter-spacing:.7px;text-transform:uppercase;color:#dce8f7}
.panel-body{padding:14px}
.info-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.info{background:rgba(9,14,23,.58);border:1px solid #243247;border-radius:10px;padding:12px}
.info-label{font-size:7px;text-transform:uppercase;color:#8aa0bc;letter-spacing:1.2px}
.info-value{font-size:10px;margin-top:6px;word-break:break-all;color:#eaf3ff}
.notice{background:rgba(10,17,28,.76);border:1px solid #283a52;border-radius:9px;padding:11px;color:#a4b5ca;font-size:8px;line-height:1.7}
.btn{height:33px;padding:0 12px;border:none;border-radius:8px;background:#1c2636;color:#edf4ff;border:1px solid #303f52;font-size:9px;transition:.18s ease}
.btn:hover{background:#243248;transform:translateY(-1px)}
.btn.primary{background:linear-gradient(135deg,#1ed0a7,#138b72);border-color:rgba(24,176,142,.6);color:#07140f;font-weight:800}
.btn.primary:hover{background:linear-gradient(135deg,#2fe2b8,#12a67d)}
.btn.danger{background:rgba(96,40,51,.35);border-color:rgba(255,116,135,.35);color:#ff9aa8}
.btn.small{height:29px;padding:0 9px;font-size:8px;border-radius:6px}
.action-row{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.table-wrap{overflow:auto}
table{width:100%;min-width:940px;border-collapse:collapse}
th,td{padding:11px 12px;border-bottom:1px solid #232f3d;text-align:left;font-size:9px}
th{background:#0f1724;color:#8496af;text-transform:uppercase;letter-spacing:1px;font-size:7px}
.badge{display:inline-flex;align-items:center;justify-content:center;padding:3px 7px;border-radius:999px;border:1px solid #303f52;font-size:7px}
.badge.ok{background:rgba(22,94,79,.25);border-color:rgba(38,208,168,.34);color:var(--accent)}
.badge.off{background:rgba(84,28,38,.36);border-color:rgba(255,116,135,.32);color:var(--danger)}
.badge.blue{background:rgba(25,66,118,.34);border-color:rgba(101,169,255,.32);color:var(--blue)}
.progress{height:7px;background:#232f3d;border-radius:999px;overflow:hidden;margin-top:7px}
.progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent-2))}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}
.field label{display:block;margin-bottom:6px;font-size:7px;text-transform:uppercase;color:#8ea4bf;letter-spacing:1.1px}
.field input,.field select,.field textarea{width:100%;height:38px;border-radius:8px;background:#0b131d;border:1px solid #2a3b4e;color:var(--text);padding:9px 10px;outline:none;transition:.18s ease}
.field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(38,208,168,.7);box-shadow:0 0 0 3px rgba(38,208,168,.1)}
.field textarea{min-height:120px;resize:vertical;height:auto}
.port-grid{display:grid;grid-template-columns:1fr 1fr;gap:11px}
.port-box{background:rgba(8,14,23,.64);border:1px solid #243247;border-radius:10px;padding:11px}
.port-title{font-size:8px;text-transform:uppercase;letter-spacing:1.1px;color:#8ba2bf;margin-bottom:9px}
.port-list{display:flex;flex-wrap:wrap;gap:5px}
.port{position:relative;display:inline-block}
.port input{position:absolute;opacity:0}
.port span{display:flex;align-items:center;justify-content:center;min-width:62px;height:28px;border:1px solid #2b3a4d;border-radius:7px;background:#161f2d;color:#a0b4cb;font-size:8px;transition:.15s ease}
.port input:checked + span{background:rgba(24,92,80,.32);border-color:rgba(38,208,168,.5);color:var(--accent)}
.permission-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
.perm{display:flex;align-items:center;gap:7px;background:rgba(8,14,23,.54);border:1px solid #243247;border-radius:8px;padding:8px;font-size:8px;color:#b0bfd1}
.modal{position:fixed;inset:0;display:none;place-items:center;padding:15px;background:rgba(5,8,14,.64);backdrop-filter:blur(8px);z-index:100}
.modal.open{display:grid}
.modal-box{width:min(760px,96vw);max-height:92vh;overflow:auto;background:linear-gradient(180deg,#171f2c,#111a26);border:1px solid #2c3c4f;border-radius:12px;box-shadow:var(--shadow);padding:18px;animation:modalIn .18s ease}
@keyframes modalIn{from{opacity:0;transform:translateY(10px) scale(.985)}to{opacity:1;transform:none}}
.modal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.modal-title{font-size:12px;font-weight:900}
.close{width:30px;height:30px;border:0;background:transparent;color:#95a4b5;font-size:20px}
.empty{padding:28px;text-align:center;color:#7f92ac;font-size:9px}
.toast{position:fixed;right:18px;bottom:18px;z-index:200;background:#141d2a;border:1px solid #2f3d50;border-radius:8px;padding:9px 12px;font-size:8px;box-shadow:var(--shadow)}
.login{height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 30% 10%, rgba(38,208,168,.18), transparent 28%), #0a0f18}
.login-box{width:min(430px,92vw);background:linear-gradient(180deg,#121b29,#0d1621);border:1px solid #2b394d;border-radius:14px;padding:24px;box-shadow:var(--shadow)}
.login-logo{width:48px;height:48px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#1ce0b7,#0d8772);font-weight:900;box-shadow:0 20px 40px rgba(38,208,168,.2)}
.login-name{font-size:22px;font-weight:900;margin-top:16px}
.login-sub{font-size:9px;color:var(--muted);margin-top:5px;letter-spacing:.8px}
.err{display:none;background:rgba(110,34,43,.35);border:1px solid rgba(255,116,135,.35);color:#ff9aa8;border-radius:8px;padding:9px 10px;font-size:8px;margin:12px 0 10px}
.donut{width:168px;height:168px;border-radius:50%;display:grid;place-items:center;position:relative;margin:auto;background:conic-gradient(var(--accent) 0deg, #2a374a 0deg)}
.donut::after{content:"";position:absolute;inset:14px;border-radius:50%;background:#101928}
.donut-center{position:relative;z-index:1;text-align:center}
.donut-pct{font-size:28px;font-weight:900}
.donut-txt{font-size:7px;color:#7f96b2;text-transform:uppercase;letter-spacing:1px}
.sub-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.stat{background:rgba(8,14,23,.6);border:1px solid #243247;border-radius:9px;padding:10px}
.stat b{display:block;font-size:13px}
.stat span{display:block;font-size:7px;color:#7c8da6;margin-top:4px;text-transform:uppercase;letter-spacing:1px}
.link-box{word-break:break-all;background:#0c1521;border:1px solid #243247;border-radius:8px;padding:10px;font-size:8px;line-height:1.7}
.node{margin-top:8px;background:#0d1724;border:1px solid #243247;border-radius:9px;padding:10px}
.node-top{display:flex;justify-content:space-between;gap:12px;font-size:8px}
.node-meta{font-size:8px;color:#93a7c2;margin-top:4px}
@media(max-width:1000px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}}
@media(max-width:700px){.sidebar{width:72px;flex-basis:72px}.brand-text,.nav-text,.logout-text{display:none}.brand{justify-content:center;padding:16px 0}.nav button{justify-content:center;padding:0}.nav-icon{margin:0}.content{padding:12px}.form-grid,.port-grid{grid-template-columns:1fr}}
</style>
<style>
.navIcon,
.nav-icon {
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:30px;
  min-width:30px;
  height:24px;
  margin-right:7px;
  border:1px solid #34445a;
  border-radius:6px;
  color:#8fa5bf;
  font-size:8px;
  font-weight:800;
  letter-spacing:.3px;
}

.nav button.active .navIcon,
.nav button.active .nav-icon {
  border-color:#1d8269;
  color:#3bd6ab;
  background:#103a31;
}
</style>
</head>

<body>
<div id="root"></div>
<div class="modal" id="modal">
  <div class="modal-box">
    <div class="modal-head">
      <div class="modal-title" id="modalTitle">Dialog</div>
      <button class="close" id="modalClose">Ã—</button>
    </div>
    <div id="modalBody"></div>
  </div>
</div>

<script>
var S = {
  inbounds: [],
  outbounds: [],
  clients: [],
  ips: [],
  admins: [],
  settings: {},
  page: "overview"
};

var root = document.getElementById("root");

function esc(v) {
  return String(v == null ? "" : v)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function bytes(n) {
  n = Number(n || 0);
  var u = ["B", "KB", "MB", "GB", "TB"];
  var i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return n.toFixed(i ? 2 : 0) + " " + u[i];
}

function toast(msg) {
  var x = document.createElement("div");
  x.className = "toast";
  x.textContent = msg;
  document.body.appendChild(x);
  setTimeout(function () {
    x.remove();
  }, 2200);
}

async function api(url, opt) {
  var r = await fetch(url, opt || {});
  var t = await r.text();
  var d = {};
  try { d = JSON.parse(t); } catch { d = { error: t }; }
  if (r.status === 401) { showLogin(); throw new Error("Unauthorized"); }
  if (!r.ok) { throw new Error(d.error || "Request failed"); }
  return d;
}

function openModal(title, html) {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalBody").innerHTML = html;
  document.getElementById("modal").classList.add("open");
}

function closeModal() {
  document.getElementById("modal").classList.remove("open");
}
document.getElementById("modalClose").onclick = closeModal;

function showLogin() {
  location.hash = "#/login";
  root.innerHTML =
    '<div class="login">' +
    '<div class="login-box">' +
    '<div class="login-logo">D</div>' +
    '<div class="login-name">' + esc(S.settings.panelName || "dollax26") + '</div>' +
    '<div class="login-sub">Secure VPN management</div>' +
    '<div class="field" style="margin-bottom:12px"><label>Username</label><input id="lu" value="dollax26"></div>' +
    '<div class="field" style="margin-bottom:12px"><label>Password</label><input id="lp" type="password" value="hesan356xbox123"></div>' +
    '<div id="le" class="err"></div>' +
    '<button class="btn primary" id="lb" style="width:100%;height:40px">Sign in</button>' +
    '</div>' +
    '</div>';

  document.getElementById("lb").onclick = login;
  document.getElementById("lp").onkeydown = function (e) {
    if (e.key === "Enter") login();
  };
}

async function login() {
  var e = document.getElementById("le");
  var b = document.getElementById("lb");
  e.style.display = "none";
  b.disabled = true;
  b.textContent = "Signing in...";

  try {
    await api("/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("lu").value,
        password: document.getElementById("lp").value
      })
    });

    location.hash = "#/overview";
    await boot();
  } catch (x) {
    e.textContent = x.message;
    e.style.display = "block";
  } finally {
    b.disabled = false;
    b.textContent = "Sign in";
  }
}

function shell() {
  root.innerHTML =
    '<div class="app">' +
    '<aside class="sidebar">' +
    '<div class="brand">' +
    '<div class="brand-mark">D</div>' +
    '<div class="brand-text">' +
    '<div class="brand-name" id="brandName">dollax26</div>' +
    '<div class="brand-sub">VPN MANAGEMENT</div>' +
    '</div>' +
    '</div>' +
    '<nav class="nav">' +
    '<button data-p="overview" class="active"><span class="nav-icon">â—‰</span><span class="nav-text">Overview</span></button>' +
    '<button data-p="inbounds"><span class="nav-icon">â‡„</span><span class="nav-text">Inbounds</span></button>' +
    '<button data-p="outbounds"><span class="nav-icon">â†’</span><span class="nav-text">Outbounds</span></button>' +
    '<button data-p="clients"><span class="nav-icon">â™™</span><span class="nav-text">Clients</span></button>' +
    '<button data-p="admins"><span class="nav-icon">âš‘</span><span class="nav-text">Admins</span></button>' +
    '<button data-p="cleanips"><span class="nav-icon">âœ¦</span><span class="nav-text">Clean IPs</span></button>' +
    '<button data-p="settings"><span class="nav-icon">âš™</span><span class="nav-text">Settings</span></button>' +
    '<button data-p="logs"><span class="nav-icon">â‰¡</span><span class="nav-text">Logs</span></button>' +
    '</nav>' +
    '<div class="side-foot">' +
    '<button class="logout" id="logout"><span class="logout-text">Logout</span></button>' +
    '</div>' +
    '</aside>' +
    '<main class="main">' +
    '<header class="topbar">' +
    '<div class="top-title" id="title">Overview</div>' +
    '<div class="top-right">' +
    '<span class="pill" id="colo">EDGE</span>' +
    '<span class="pill ok">â— Running</span>' +
    '</div>' +
    '</header>' +
    '<div class="content">' +
    '<div id="page"></div>' +
    '</div>' +
    '</main>' +
    '</div>';

  document.querySelectorAll(".nav button").forEach(function (b) {
    b.onclick = function () {
      location.hash = "#/" + b.dataset.p;
    };
  });

  document.getElementById("logout").onclick = async function () {
    await fetch("/api/logout", { method: "POST" });
    showLogin();
  };

  document.getElementById("brandName").textContent = S.settings.panelName || "dollax26";
}

async function refreshAll() {
  var a = await Promise.all([
    api("/api/inbounds"),
    api("/api/outbounds"),
    api("/api/clients"),
    api("/api/clean-ips"),
    api("/api/settings")
  ]);

  S.inbounds = a[0].items || [];
  S.outbounds = a[1].items || [];
  S.clients = a[2].items || [];
  S.ips = a[3].items || [];
  S.settings = a[4] || {};

  if (S.settings.panelName) {
    document.title = S.settings.panelName;
  }
}

async function route() {
  var h = location.hash || "#/overview";
  var p = h.indexOf("#/") === 0 ? h.slice(2) : "overview";

  if (p === "login") {
    showLogin();
    return;
  }

  if (["overview", "inbounds", "outbounds", "clients", "admins", "cleanips", "settings", "logs"].indexOf(p) < 0) {
    p = "overview";
  }

  S.page = p;

  document.querySelectorAll(".nav button").forEach(function (x) {
    x.classList.toggle("active", x.dataset.p === p);
  });

  document.getElementById("title").textContent = p.charAt(0).toUpperCase() + p.slice(1);

  if (p === "overview") renderOverview();
  if (p === "inbounds") renderInbounds();
  if (p === "outbounds") renderOutbounds();
  if (p === "clients") renderClients();
  if (p === "admins") renderAdmins();
  if (p === "cleanips") renderCleanIps();
  if (p === "settings") renderSettings();
  if (p === "logs") renderLogs();
}

function renderOverview() {
  var traffic = S.clients.reduce(function (a, x) {
    a.up += Number(x.up || 0);
    a.down += Number(x.down || 0);
    return a;
  }, { up: 0, down: 0 });

  var recent = S.clients.slice(0, 6);

  document.getElementById("page").innerHTML =
    '<div class="cards">' +
    '<div class="card"><div class="card-label">Clients</div><div class="card-value">' + S.clients.length + '</div><div class="card-sub">' + S.clients.filter(x => x.enabled).length + ' enabled</div></div>' +
    '<div class="card"><div class="card-label">Inbounds</div><div class="card-value">' + S.inbounds.length + '</div><div class="card-sub">' + S.inbounds.filter(x => x.enabled).length + ' active</div></div>' +
    '<div class="card"><div class="card-label">Outbounds</div><div class="card-value">' + S.outbounds.length + '</div><div class="card-sub">' + S.outbounds.filter(x => x.enabled).length + ' active</div></div>' +
    '<div class="card"><div class="card-label">Traffic</div><div class="card-value">' + bytes(traffic.up + traffic.down) + '</div><div class="card-sub">Upload ' + bytes(traffic.up) + ' Â· Download ' + bytes(traffic.down) + '</div></div>' +
    '</div>' +
    '<div class="grid2">' +
    '<div class="panel"><div class="panel-head"><div class="panel-title">Gateway</div><button class="btn" id="refresh">Refresh</button></div><div class="panel-body"><div class="info-grid"><div class="info"><div class="info-label">Panel</div><div class="info-value">' + esc(S.settings.panelName) + '</div></div><div class="info"><div class="info-label">Public Host</div><div class="info-value">' + esc(S.settings.publicHost || location.host) + '</div></div><div class="info"><div class="info-label">Clean IPs</div><div class="info-value">' + S.ips.filter(x => x.enabled).length + ' active</div></div><div class="info"><div class="info-label">Xray Bridge</div><div class="info-value">' + (S.settings.xrayOrigin ? "Configured" : "Not configured") + '</div></div></div><div style="height:12px"></div><div class="notice">Client traffic can be routed through DIRECT or the configured SOCKS5 Germany outbound. VMess and Shadowsocks use the configured Xray WebSocket bridge.</div></div></div>' +
    '<div class="panel"><div class="panel-head"><div class="panel-title">Latency</div><button class="btn" id="ping">Test</button></div><div class="panel-body"><div class="card-value" id="lat" style="font-size:26px">â€”</div><div class="card-sub">Worker response</div></div></div>' +
    '</div>' +
    '<div style="height:12px"></div>' +
    '<div class="panel"><div class="panel-head"><div class="panel-title">Recent Clients</div><button class="btn" id="clients">Open</button></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Protocol</th><th>Inbound</th><th>Outbound</th><th>Traffic</th><th>Status</th></tr></thead><tbody>' +
    (recent.length ? recent.map(function (x) {
      return '<tr><td>' + esc(x.name) + '</td><td><span class="badge blue">' + esc(x.protocol) + '</span></td><td>' + esc(x.inbound || "-") + '</td><td>' + esc(x.outbound || "-") + '</td><td>' + bytes(Number(x.up || 0) + Number(x.down || 0)) + '</td><td><span class="badge ' + (x.enabled ? "ok" : "off") + '">' + (x.enabled ? "Enabled" : "Disabled") + '</span></td></tr>';
    }).join("") : '<tr><td colspan="6" class="empty">No clients</td></tr>') +
    '</tbody></table></div></div>';

  document.getElementById("refresh").onclick = async function () {
    await refreshAll();
    route();
  };

  document.getElementById("clients").onclick = function () {
    location.hash = "#/clients";
  };

  document.getElementById("ping").onclick = async function () {
    var t = performance.now();
    await fetch("/api/ping?x=" + Date.now(), { cache: "no-store" });
    document.getElementById("lat").textContent = Math.round(performance.now() - t) + " ms";
  };

  document.getElementById("colo").textContent = (S.settings.colo || "EDGE") + (S.settings.country ? " Â· " + S.settings.country : "");
}

function portChecks(selected, tls) {
  var list = tls ? [443, 2053, 2083, 2087, 2096, 8443] : [80, 8080, 8880, 2052, 2082, 2086, 2095];
  return list.map(function (p) {
    return '<label class="port"><input type="checkbox" data-port="' + p + '" data-tls="' + (tls ? 1 : 0) + '" ' + (selected.indexOf(p) >= 0 ? "checked" : "") + '><span>' + p + '</span></label>';
  }).join("");
}

function safe(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

async function renderInbounds() {
  var rows = S.inbounds.length ? S.inbounds.map(function (x) {
    var ports = safe(x.ports_json, []);
    var tls = safe(x.tls_ports_json, []);

    return '<tr>' +
      '<td>' + esc(x.name) + '</td>' +
      '<td><span class="badge blue">' + esc(x.protocol) + '</span></td>' +
      '<td>' + ports.map(function (p) { return p + (tls.indexOf(p) >= 0 ? " TLS" : ""); }).join(", ") + '</td>' +
      '<td>' + esc(x.path) + '</td>' +
      '<td>' + esc(x.outbound_name || "-") + '</td>' +
      '<td>' + (Number(x.max_clients || 0) ? x.max_clients : "âˆž") + '</td>' +
      '<td>' + (Number(x.traffic_limit || 0) ? bytes(x.traffic_limit) : "âˆž") + '</td>' +
      '<td><span class="badge ' + (x.enabled ? "ok" : "off") + '">' + (x.enabled ? "Enabled" : "Disabled") + '</span></td>' +
      '<td>' +
      '<div class="action-row">' +
      '<button class="btn small" data-edit="' + x.id + '">Edit</button>' +
      '<button class="btn small" data-toggle="' + x.id + '">' + (x.enabled ? "Disable" : "Enable") + '</button>' +
      '<button class="btn danger small" data-delete="' + x.id + '">Delete</button>' +
      '</div>' +
      '</td>' +
      '</tr>';
  }).join("") : '<tr><td colspan="9" class="empty">No inbounds</td></tr>';

  document.getElementById("page").innerHTML =
    '<div class="panel">' +
    '<div class="panel-head"><div class="panel-title">Inbounds</div><button class="btn primary" id="add">+ Add inbound</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Protocol</th><th>Ports</th><th>Path</th><th>Outbound</th><th>Max</th><th>Traffic</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
    '</div>';

  document.getElementById("add").onclick = function () {
    inboundModal();
  };

  document.querySelectorAll("[data-edit]").forEach(function (b) {
    b.onclick = function () {
      inboundModal(S.inbounds.find(x => x.id === b.dataset.edit));
    };
  });

  document.querySelectorAll("[data-toggle]").forEach(function (b) {
    b.onclick = async function () {
      await api("/api/inbounds/" + encodeURIComponent(b.dataset.toggle) + "/toggle", { method: "POST" });
      await refreshAll();
      renderInbounds();
    };
  });

  document.querySelectorAll("[data-delete]").forEach(function (b) {
    b.onclick = async function () {
      if (!confirm("Delete inbound?")) return;
      await api("/api/inbounds/" + encodeURIComponent(b.dataset.delete), { method: "DELETE" });
      await refreshAll();
      renderInbounds();
    };
  });
}

async function inboundModal(item) {
  var edit = !!item;
  var out = await api("/api/outbounds");
  var tls = edit ? safe(item.tls_ports_json, []) : [443];
  var plain = edit ? safe(item.plain_ports_json, []) : [8080];

  openModal(edit ? "Edit inbound" : "Create inbound",
    '<div class="form-grid">' +
    '<div class="field"><label>Name</label><input id="inName" value="' + esc(edit ? item.name : "VLESS Edge") + '"></div>' +
    '<div class="field"><label>Protocol</label><select id="inProtocol"><option value="vless" ' + (edit && item.protocol === "vless" ? "selected" : "") + '>VLESS</option><option value="vmess" ' + (edit && item.protocol === "vmess" ? "selected" : "") + '>VMess</option><option value="trojan" ' + (edit && item.protocol === "trojan" ? "selected" : "") + '>Trojan</option><option value="shadowsocks" ' + (edit && item.protocol === "shadowsocks" ? "selected" : "") + '>Shadowsocks</option></select></div>' +
    '</div>' +
    '<div class="port-grid" style="margin-top:11px">' +
    '<div class="port-box"><div class="port-title">TLS ports</div><div class="port-list">' + portChecks(tls, true) + '</div></div>' +
    '<div class="port-box"><div class="port-title">No TLS ports</div><div class="port-list">' + portChecks(plain, false) + '</div></div>' +
    '</div>' +
    '<div class="form-grid" style="margin-top:11px">' +
    '<div class="field"><label>WebSocket path</label><input id="inPath" value="' + esc(edit ? item.path : "/ws/" + Math.random().toString(36).slice(2, 10)) + '"></div>' +
    '<div class="field"><label>Outbound</label><select id="inOutbound">' + (out.items || []).map(function (x) {
      return '<option value="' + x.id + '" ' + (edit && x.id === item.outbound_id ? "selected" : "") + '>' + esc(x.name) + " Â· " + esc(x.type) + '</option>';
    }).join("") + '</select></div>' +
    '<div class="field"><label>Inbound traffic limit GB</label><input id="inLimit" type="number" min="0" step="0.1" value="' + (edit ? (Number(item.traffic_limit || 0) / 1073741824).toFixed(2) : "0") + '"></div>' +
    '<div class="field"><label>Maximum clients</label><input id="inMax" type="number" min="0" value="' + (edit ? item.max_clients || 0 : 0) + '"></div>' +
    '</div>' +
    '<div class="notice" style="margin-top:11px">Select 2 to 4 total ports. TLS and non-TLS ports are configured separately. The same WebSocket path is used across all selected ports.</div>' +
    '<div class="action-row" style="justify-content:flex-end;margin-top:12px"><button class="btn primary" id="saveInbound">Save inbound</button></div>'
  );

  document.getElementById("saveInbound").onclick = async function () {
    var selected = [].slice.call(document.querySelectorAll("[data-port]:checked"));
    var ports = selected.map(x => Number(x.dataset.port));

    if (ports.length < 2 || ports.length > 4) {
      alert("Select 2 to 4 ports.");
      return;
    }

    var tlsPorts = selected.filter(x => x.dataset.tls === "1").map(x => Number(x.dataset.port));
    var plainPorts = selected.filter(x => x.dataset.tls === "0").map(x => Number(x.dataset.port));

    try {
      await api(edit ? "/api/inbounds/" + encodeURIComponent(item.id) : "/api/inbounds", {
        method: edit ? "PATCH" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: document.getElementById("inName").value,
          protocol: document.getElementById("inProtocol").value,
          ports,
          tlsPorts,
          plainPorts,
          path: document.getElementById("inPath").value,
          outboundId: document.getElementById("inOutbound").value,
          trafficLimitGB: Number(document.getElementById("inLimit").value || 0),
          maxClients: Number(document.getElementById("inMax").value || 0)
        })
      });

      closeModal();
      await refreshAll();
      renderInbounds();
      toast(edit ? "Inbound updated" : "Inbound created");
    } catch (e) {
      alert(e.message);
    }
  };
}

function renderOutbounds() {
  var rows = S.outbounds.length ? S.outbounds.map(function (x) {
    return '<tr><td>' + esc(x.name) + '</td><td><span class="badge blue">' + esc(x.type) + '</span></td><td>' + esc(x.host || "Worker edge") + '</td><td>' + esc(x.port || "-") + '</td><td>' + esc(x.clients || 0) + '</td><td><span class="badge ' + (x.enabled ? "ok" : "off") + '">' + (x.enabled ? "Enabled" : "Disabled") + '</span></td><td><div class="action-row"><button class="btn small" data-eout="' + x.id + '">Edit</button><button class="btn small" data-tout="' + x.id + '">' + (x.enabled ? "Disable" : "Enable") + '</button><button class="btn danger small" data-dout="' + x.id + '">Delete</button></div></td></tr>';
  }).join("") : '<tr><td colspan="7" class="empty">No outbounds</td></tr>';

  document.getElementById("page").innerHTML =
    '<div class="panel">' +
    '<div class="panel-head"><div class="panel-title">Outbounds</div><button class="btn primary" id="addOut">+ Add outbound</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Host</th><th>Port</th><th>Clients</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
    '</div>';

  document.getElementById("addOut").onclick = function () {
    outboundModal();
  };

  document.querySelectorAll("[data-eout]").forEach(function (b) {
    b.onclick = function () {
      outboundModal(S.outbounds.find(x => x.id === b.dataset.eout));
    };
  });

  document.querySelectorAll("[data-tout]").forEach(function (b) {
    b.onclick = async function () {
      await api("/api/outbounds/" + encodeURIComponent(b.dataset.tout) + "/toggle", { method: "POST" });
      await refreshAll();
      renderOutbounds();
    };
  });

  document.querySelectorAll("[data-dout]").forEach(function (b) {
    b.onclick = async function () {
      if (!confirm("Delete outbound?")) return;
      try {
        await api("/api/outbounds/" + encodeURIComponent(b.dataset.dout), { method: "DELETE" });
        await refreshAll();
        renderOutbounds();
      } catch (e) {
        alert(e.message);
      }
    };
  });
}

function outboundModal(item) {
  var edit = !!item;

  openModal(edit ? "Edit outbound" : "Create outbound",
    '<div class="form-grid">' +
    '<div class="field"><label>Name</label><input id="outName" value="' + esc(edit ? item.name : "GERMANY SOCKS5") + '"></div>' +
    '<div class="field"><label>Type</label><select id="outType"><option value="socks5">SOCKS5</option><option value="http">HTTP CONNECT</option><option value="direct">DIRECT</option><option value="block">BLOCK</option></select></div>' +
    '<div class="field"><label>Host</label><input id="outHost" value="' + esc(edit ? item.host : "") + '"></div>' +
    '<div class="field"><label>Port</label><input id="outPort" type="number" value="' + (edit ? item.port || 1080 : 1080) + '"></div>' +
    '<div class="field"><label>Username</label><input id="outUser" value="' + esc(edit ? item.username : "") + '"></div>' +
    '<div class="field"><label>Password</label><input id="outPass" type="password"></div>' +
    '</div>' +
    '<div class="notice" style="margin-top:11px">SOCKS5 is intended for the Germany exit. DIRECT uses the Worker edge. BLOCK refuses traffic.</div>' +
    '<div class="action-row" style="justify-content:flex-end;margin-top:12px"><button class="btn primary" id="saveOut">Save outbound</button></div>'
  );

  document.getElementById("outType").value = edit ? item.type : "socks5";

  document.getElementById("saveOut").onclick = async function () {
    try {
      await api(edit ? "/api/outbounds/" + encodeURIComponent(item.id) : "/api/outbounds", {
        method: edit ? "PATCH" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: document.getElementById("outName").value,
          type: document.getElementById("outType").value,
          host: document.getElementById("outHost").value,
          port: Number(document.getElementById("outPort").value || 0),
          username: document.getElementById("outUser").value,
          password: document.getElementById("outPass").value
        })
      });

      closeModal();
      await refreshAll();
      renderOutbounds();
      toast(edit ? "Outbound updated" : "Outbound created");
    } catch (e) {
      alert(e.message);
    }
  };
}

function clientPercent(x) {
  var q = Number(x.quota || 0);
  if (!q) return 0;
  return Math.min(100, (Number(x.up || 0) + Number(x.down || 0)) / q * 100);
}

function daysLeft(x) {
  var e = Number(x.expiry || 0);
  if (!e) return null;
  return Math.max(0, Math.ceil((e - Date.now()) / 86400000));
}

function renderClients() {
  var rows = S.clients.length ? S.clients.map(function (x) {
    var p = clientPercent(x);
    var d = daysLeft(x);

    return '<tr>' +
      '<td>' + esc(x.name) + '</td>' +
      '<td><span class="badge blue">' + esc(x.protocol) + '</span></td>' +
      '<td>' + esc(x.inbound || "-") + '</td>' +
      '<td>' + esc(x.outbound || "-") + '</td>' +
      '<td style="min-width:155px">' + bytes(Number(x.up || 0) + Number(x.down || 0)) + (Number(x.quota || 0) ? " / " + bytes(x.quota) : "") +
      '<div class="progress"><i style="width:' + p + '%"></i></div>' +
      '</td>' +
      '<td>' + (d === null ? "âˆž" : d + " days") + '</td>' +
      '<td><span class="badge ' + (x.enabled ? "ok" : "off") + '">' + (x.enabled ? "Enabled" : "Disabled") + '</span></td>' +
      '<td>' +
      '<div class="action-row">' +
      '<button class="btn small" data-config-c="' + x.id + '">Config</button>' +
      '<button class="btn small" data-edit-c="' + x.id + '">Edit</button>' +
      '<button class="btn small" data-toggle-c="' + x.id + '">' + (x.enabled ? "Disable" : "Enable") + '</button>' +
      '<button class="btn danger small" data-delete-c="' + x.id + '">Delete</button>' +
      '</div>' +
      '</td>' +
      '</tr>';
  }).join("") : '<tr><td colspan="8" class="empty">No clients</td></tr>';

  document.getElementById("page").innerHTML =
    '<div class="panel">' +
    '<div class="panel-head"><div class="panel-title">Clients</div><button class="btn primary" id="addClient">+ Add client</button></div>' +
    '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Protocol</th><th>Inbound</th><th>Outbound</th><th>Traffic</th><th>Time</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
    '</div>';

  document.getElementById("addClient").onclick = function () {
    clientModal();
  };

  document.querySelectorAll("[data-config-c]").forEach(function (b) {
    b.onclick = function () { clientConfig(b.dataset.configC); };
  });

  document.querySelectorAll("[data-edit-c]").forEach(function (b) {
    b.onclick = function () {
      clientModal(S.clients.find(x => x.id === b.dataset.editC));
    };
  });

  document.querySelectorAll("[data-toggle-c]").forEach(function (b) {
    b.onclick = async function () {
      await api("/api/clients/" + encodeURIComponent(b.dataset.toggleC) + "/toggle", { method: "POST" });
      await refreshAll();
      renderClients();
    };
  });

  document.querySelectorAll("[data-delete-c]").forEach(function (b) {
    b.onclick = async function () {
      if (!confirm("Delete client?")) return;
      await api("/api/clients/" + encodeURIComponent(b.dataset.deleteC), { method: "DELETE" });
      await refreshAll();
      renderClients();
    };
  });
}

function clientModal(item) {
  var edit = !!item;
  var io = S.inbounds.filter(x => x.enabled).map(function (x) {
    return '<option value="' + x.id + '" ' + (edit && item.inbound_id === x.id ? "selected" : "") + '>' + esc(x.name) + " Â· " + esc(x.protocol) + '</option>';
  }).join("");

  var oo = S.outbounds.filter(x => x.enabled).map(function (x) {
    return '<option value="' + x.id + '" ' + (edit && item.outbound_id === x.id ? "selected" : "") + '>' + esc(x.name) + " Â· " + esc(x.type) + '</option>';
  }).join("");

  var expiry = edit && Number(item.expiry || 0) ? new Date(Number(item.expiry)).toISOString().slice(0, 16) : "";

  openModal(edit ? "Edit client" : "Create client",
    '<div class="form-grid">' +
    '<div class="field"><label>Name</label><input id="clientName" value="' + esc(edit ? item.name : "Client") + '"></div>' +
    '<div class="field"><label>Inbound</label><select id="clientInbound">' + io + '</select></div>' +
    '<div class="field"><label>Outbound</label><select id="clientOutbound">' + oo + '</select></div>' +
    '<div class="field"><label>Traffic limit GB</label><input id="clientQuota" type="number" min="0" step="0.1" value="' + (edit ? (Number(item.quota || 0) / 1073741824).toFixed(2) : "0") + '"></div>' +
    '<div class="field"><label>Expiration</label><input id="clientExpiry" type="datetime-local" value="' + esc(expiry) + '"></div>' +
    '<div class="field"><label>Maximum IPs</label><input id="clientIPs" type="number" min="0" value="' + (edit ? item.limit_ip || 0 : 0) + '"></div>' +
    '</div>' +
    '<div class="notice" style="margin-top:11px">0 means unlimited. Client credentials stay unchanged when the client is edited.</div>' +
    '<div class="action-row" style="justify-content:flex-end;margin-top:12px"><button class="btn primary" id="saveClient">Save client</button></div>'
  );

  document.getElementById("saveClient").onclick = async function () {
    try {
      await api(edit ? "/api/clients/" + encodeURIComponent(item.id) : "/api/clients", {
        method: edit ? "PATCH" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: document.getElementById("clientName").value,
          inboundId: document.getElementById("clientInbound").value,
          outboundId: document.getElementById("clientOutbound").value,
          quotaGB: Number(document.getElementById("clientQuota").value || 0),
          expiry: document.getElementById("clientExpiry").value ? new Date(document.getElementById("clientExpiry").value).getTime() : 0,
          limitIp: Number(document.getElementById("clientIPs").value || 0)
        })
      });

      closeModal();
      await refreshAll();
      renderClients();
      toast(edit ? "Client updated" : "Client created");
    } catch (e) {
      alert(e.message);
    }
  };
}

async function clientConfig(id) {
  var d = await api("/api/clients/" + encodeURIComponent(id) + "/config");
  var p = d.quota ? Math.min(100, d.used / d.quota * 100) : 0;
  var remaining = d.quota ? Math.max(0, d.quota - d.used) : 0;
  var expiry = d.expiry ? new Date(d.expiry).toLocaleString() : "Never";

  openModal("Client configuration",
    '<div class="sub-stats">' +
    '<div class="stat"><b>' + bytes(d.used) + '</b><span>Used</span></div>' +
    '<div class="stat"><b>' + (d.quota ? bytes(remaining) : "âˆž") + '</b><span>Remaining</span></div>' +
    '<div class="stat"><b>' + (d.daysLeft === null ? "âˆž" : d.daysLeft) + '</b><span>Days left</span></div>' +
    '</div>' +
    '<div style="height:14px"></div>' +
    '<div style="display:grid;grid-template-columns:180px 1fr;gap:15px;align-items:center">' +
    '<div class="donut" id="clientDonut">' +
    '<div class="donut-center"><div class="donut-pct">' + Math.round(p) + '%</div><div class="donut-txt">Used</div></div>' +
    '</div>' +
    '<div>' +
    '<div class="notice">Expires: ' + esc(expiry) + '</div>' +
    '<div style="height:9px"></div>' +
    '<div class="info-label">Subscription</div>' +
    '<div class="link-box">' + esc(d.subUrl) + '</div>' +
    '<div class="action-row" style="margin-top:8px">' +
    '<button class="btn primary small" id="copySub">Copy subscription</button>' +
    '<button class="btn small" id="openSub">Open subscription</button>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div style="height:15px"></div>' +
    '<div class="info-label">Configuration nodes</div>' +
    (d.nodes && d.nodes.length ? d.nodes.map(function (n) {
      return '<div class="node"><div class="node-top"><strong>' + esc(n.protocol.toUpperCase()) + ' Â· ' + n.port + '</strong><span>' + (n.tls ? 'TLS' : 'NO TLS') + '</span></div><div class="node-meta">' + esc(n.addressLabel || n.address) + '</div><div class="link-box" style="margin-top:8px">' + esc(n.link) + '</div><div class="action-row" style="margin-top:8px"><button class="btn small copyNode" data-link="' + encodeURIComponent(n.link) + '">Copy</button></div></div>';
    }).join("") : '<div class="empty">No generated nodes</div>')
  );

  var deg = Math.round(p * 3.6);
  document.getElementById("clientDonut").style.background = "conic-gradient(var(--accent) " + deg + "deg,#28313a " + deg + "deg)";

  document.getElementById("copySub").onclick = function () {
    navigator.clipboard.writeText(d.subUrl);
    toast("Subscription copied");
  };

  document.getElementById("openSub").onclick = function () {
    window.open(d.subUrl, "_blank");
  };

  document.querySelectorAll(".copyNode").forEach(function (b) {
    b.onclick = function () {
      navigator.clipboard.writeText(decodeURIComponent(b.dataset.link));
      toast("Configuration copied");
    };
  });
}

function renderAdmins() {
  api("/api/admins").then(function (d) {
    S.admins = d.items || [];
    var rows = S.admins.map(function (x) {
      return '<tr>' +
        '<td>' + esc(x.username) + '</td>' +
        '<td>' + esc(x.display_name || "") + '</td>' +
        '<td>' + esc(x.role) + '</td>' +
        '<td><span class="badge ' + (x.enabled ? "ok" : "off") + '">' + (x.enabled ? "Enabled" : "Disabled") + '</span></td>' +
        '<td><div class="action-row"><button class="btn small" data-edit-a="' + x.username + '">Edit</button><button class="btn small" data-toggle-a="' + x.username + '">' + (x.enabled ? "Disable" : "Enable") + '</button><button class="btn danger small" data-delete-a="' + x.username + '">Delete</button></div></td>' +
        '</tr>';
    }).join("");

    document.getElementById("page").innerHTML =
      '<div class="panel">' +
      '<div class="panel-head"><div class="panel-title">Admins</div><button class="btn primary" id="addAdmin">+ Add admin</button></div>' +
      '<div class="table-wrap"><table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + (rows || '<tr><td colspan="5" class="empty">No admins</td></tr>') + '</tbody></table></div>' +
      '</div>';

    document.getElementById("addAdmin").onclick = function () {
      adminModal();
    };

    document.querySelectorAll("[data-edit-a]").forEach(function (b) {
      b.onclick = function () {
        adminModal(S.admins.find(x => x.username === b.dataset.editA));
      };
    });

    document.querySelectorAll("[data-toggle-a]").forEach(function (b) {
      b.onclick = async function () {
        await api("/api/admins/" + encodeURIComponent(b.dataset.toggleA) + "/toggle", { method: "POST" });
        renderAdmins();
      };
    });

    document.querySelectorAll("[data-delete-a]").forEach(function (b) {
      b.onclick = async function () {
        if (!confirm("Delete admin?")) return;
        try {
          await api("/api/admins/" + encodeURIComponent(b.dataset.deleteA), { method: "DELETE" });
          renderAdmins();
        } catch (e) {
          alert(e.message);
        }
      };
    });
  }).catch(function (e) {
    document.getElementById("page").innerHTML = '<div class="panel"><div class="empty">' + esc(e.message) + '</div></div>';
  });
}

var PERMISSIONS = [
  ["view", "View panel"],
  ["createClient", "Create clients"],
  ["editClient", "Edit clients"],
  ["deleteClient", "Delete clients"],
  ["createInbound", "Create inbounds"],
  ["editInbound", "Edit inbounds"],
  ["deleteInbound", "Delete inbounds"],
  ["manageOutbounds", "Manage outbounds"],
  ["manageCleanIPs", "Manage clean IPs"],
  ["manageAdmins", "Manage admins"],
  ["manageSettings", "Manage settings"],
  ["viewLogs", "View logs"]
];

function adminModal(item) {
  var edit = !!item;
  var current = safe(item && item.permissions_json, {});
  var checks = PERMISSIONS.map(function (p) {
    return '<label class="perm"><input type="checkbox" data-perm="' + p[0] + '" ' + (edit && item.role === "owner" ? "checked" : (current[p[0]] ? "checked" : "")) + '>' + esc(p[1]) + '</label>';
  }).join("");

  openModal(edit ? "Edit admin" : "Create admin",
    '<div class="form-grid">' +
    '<div class="field"><label>Username</label><input id="adminUser" value="' + esc(edit ? item.username : "friend") + '" ' + (edit ? "readonly" : "") + '></div>' +
    '<div class="field"><label>Display name</label><input id="adminName" value="' + esc(edit ? item.display_name : "Friend") + '"></div>' +
    '<div class="field"><label>Role</label><select id="adminRole"><option value="admin">Admin</option><option value="owner">Owner</option></select></div>' +
    '<div class="field"><label>Password</label><input id="adminPass" type="password"></div>' +
    '</div>' +
    '<div style="height:11px"></div>' +
    '<div class="field"><label>Permissions</label><div class="permission-grid">' + checks + '</div></div>' +
    '<div class="action-row" style="justify-content:flex-end;margin-top:12px"><button class="btn primary" id="saveAdmin">Save admin</button></div>'
  );

  document.getElementById("adminRole").value = edit ? item.role : "admin";

  document.getElementById("saveAdmin").onclick = async function () {
    var permissions = {};
    document.querySelectorAll("[data-perm]").forEach(function (c) {
      permissions[c.dataset.perm] = c.checked;
    });

    try {
      await api(edit ? "/api/admins/" + encodeURIComponent(item.username) : "/api/admins", {
        method: edit ? "PATCH" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          username: document.getElementById("adminUser").value,
          displayName: document.getElementById("adminName").value,
          role: document.getElementById("adminRole").value,
          password: document.getElementById("adminPass").value,
          permissions
        })
      });

      closeModal();
      renderAdmins();
      toast(edit ? "Admin updated" : "Admin created");
    } catch (e) {
      alert(e.message);
    }
  };
}

function renderCleanIps() {
  var rows = S.ips.map(function (x) {
    return '<tr><td>' + esc(x.ip) + '</td><td>' + esc(x.label || "") + '</td><td><span class="badge ' + (x.enabled ? "ok" : "off") + '">' + (x.enabled ? "Active" : "Disabled") + '</span></td><td><div class="action-row"><button class="btn small" data-tip="' + x.id + '">' + (x.enabled ? "Disable" : "Enable") + '</button><button class="btn danger small" data-dip="' + x.id + '">Delete</button></div></td></tr>';
  }).join("");

  document.getElementById("page").innerHTML =
    '<div class="panel">' +
    '<div class="panel-head"><div class="panel-title">Clean IPs</div><button class="btn primary" id="addIP">+ Add IPs</button></div>' +
    '<div class="panel-body"><div class="notice">Paste one IP per line. You may use IP#Name. Enabled clean IPs become connection addresses in generated configs.</div></div>' +
    '<div class="table-wrap"><table><thead><tr><th>IP</th><th>Name</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + (rows || '<tr><td colspan="4" class="empty">No clean IPs</td></tr>') + '</tbody></table></div>' +
    '</div>';

  document.getElementById("addIP").onclick = function () {
    openModal("Add clean IPs",
      '<div class="field"><label>IP#Name</label><textarea id="ipText" placeholder="1.2.3.4#Primary\\n5.6.7.8#Backup"></textarea></div><div class="action-row" style="justify-content:flex-end;margin-top:12px"><button class="btn primary" id="saveIPs">Add IPs</button></div>'
    );

    document.getElementById("saveIPs").onclick = async function () {
      try {
        await api("/api/clean-ips", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ text: document.getElementById("ipText").value })
        });
        closeModal();
        await refreshAll();
        renderCleanIps();
        toast("IPs added");
      } catch (e) {
        alert(e.message);
      }
    };
  };

  document.querySelectorAll("[data-tip]").forEach(function (b) {
    b.onclick = async function () {
      await api("/api/clean-ips/" + encodeURIComponent(b.dataset.tip) + "/toggle", { method: "POST" });
      await refreshAll();
      renderCleanIps();
    };
  });

  document.querySelectorAll("[data-dip]").forEach(function (b) {
    b.onclick = async function () {
      if (!confirm("Delete IP?")) return;
      await api("/api/clean-ips/" + encodeURIComponent(b.dataset.dip), { method: "DELETE" });
      await refreshAll();
      renderCleanIps();
    };
  });
}

function renderSettings() {
  var d = S.settings;

  document.getElementById("page").innerHTML =
    '<div class="grid2">' +
    '<div class="panel"><div class="panel-head"><div class="panel-title">Panel Settings</div></div><div class="panel-body"><div class="form-grid"><div class="field"><label>Panel name</label><input id="spName" value="' + esc(d.panelName || "dollax26") + '"></div><div class="field"><label>Public host</label><input id="spHost" value="' + esc(d.publicHost || "") + '"></div><div class="field"><label>Username</label><input id="spUser" value="' + esc(d.username || "dollax26") + '"></div><div class="field"><label>New password</label><input id="spPass" type="password"></div></div><div class="action-row" style="margin-top:12px"><button class="btn primary" id="saveSettings">Save settings</button></div></div></div>' +
    '<div class="panel"><div class="panel-head"><div class="panel-title">Xray bridge</div></div><div class="panel-body"><div class="field"><label>Xray WebSocket origin</label><input id="spXray" value="' + esc(d.xrayOrigin || "") + '" placeholder="https://xray.example.com"></div><div style="height:10px"></div><div class="notice">VMess and Shadowsocks use this bridge. The Xray server must have matching paths and client credentials.</div></div></div>' +
    '</div>' +
    '<div style="height:12px"></div>' +
    '<div class="panel"><div class="panel-head"><div class="panel-title">Cloudflare ports</div></div><div class="panel-body"><div class="notice">' + esc((d.cloudflarePorts || []).join(", ")) + '</div></div></div>';

  document.getElementById("saveSettings").onclick = async function () {
    try {
      await api("/api/settings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          panelName: document.getElementById("spName").value,
          publicHost: document.getElementById("spHost").value,
          username: document.getElementById("spUser").value,
          password: document.getElementById("spPass").value,
          xrayOrigin: document.getElementById("spXray").value
        })
      });

      await refreshAll();
      renderSettings();
      toast("Settings saved");
    } catch (e) {
      alert(e.message);
    }
  };
}

function renderLogs() {
  api("/api/logs").then(function (d) {
    var rows = (d.items || []).map(function (x) {
      return '<tr><td>' + new Date(x.t).toLocaleString() + '</td><td>' + esc(x.event) + '</td><td>' + esc(x.ip || "") + '</td><td>' + esc(x.info || "") + '</td></tr>';
    }).join("");

    document.getElementById("page").innerHTML =
      '<div class="panel">' +
      '<div class="panel-head"><div class="panel-title">Logs</div></div>' +
      '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>IP</th><th>Info</th></tr></thead><tbody>' + (rows || '<tr><td colspan="4" class="empty">No logs</td></tr>') + '</tbody></table></div>' +
      '</div>';
  }).catch(function (e) {
    document.getElementById("page").innerHTML = '<div class="panel"><div class="empty">' + esc(e.message) + '</div></div>';
  });
}

async function boot() {
  try {
    await api("/api/me");
    await refreshAll();
    shell();
    route();
  } catch {
    showLogin();
  }
}

window.addEventListener("hashchange", route);
boot();
</script>
</body>
</html>`;

async function apiHandler(req, env, ctx) {
  const u = new URL(req.url);
  const path = u.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
        "access-control-allow-headers": "content-type"
      }
    });
  }

  if (path === "/api/login" && req.method === "POST") {
    const body = await req.json();

    const admin = await DB(env)
      .prepare("SELECT * FROM admins WHERE username=? AND enabled=1 LIMIT 1")
      .bind(String(body.username || ""))
      .first();

    if (!admin || (await sha256(String(body.password || ""))) !== admin.password_hash) {
      await log(env, "login_failed", req, "invalid credentials");
      return json({ error: "Invalid username or password" }, 401);
    }

    const token = id();

    await DB(env)
      .prepare("INSERT INTO sessions(token,username,expires) VALUES(?,?,?)")
      .bind(token, admin.username, now() + SESSION_TTL)
      .run();

    await log(env, "login", req, admin.username);

    return json({ ok: true }, 200, {
      "Set-Cookie": setSession(token)
    });
  }

  if (path === "/api/logout") {
    const token = cookies(req)["vpn-ui"];

    if (token) {
      await DB(env)
        .prepare("DELETE FROM sessions WHERE token=?")
        .bind(token)
        .run();
    }

    return json({ ok: true }, 200, {
      "Set-Cookie": clearSession()
    });
  }

  const me = await currentUser(env, req);

  if (!me) {
    return json({ error: "Unauthorized" }, 401);
  }

  if (path === "/api/me") {
    return json({
      username: me.username,
      displayName: me.display_name || "",
      role: me.role || "admin"
    });
  }

  if (path === "/api/ping") {
    return json({ ok: true, t: now() });
  }

  if (path === "/api/summary") {
    const a = await DB(env).prepare("SELECT COUNT(*) n FROM inbounds").first();
    const b = await DB(env).prepare("SELECT COUNT(*) n FROM outbounds").first();
    const c = await DB(env).prepare(
      "SELECT COUNT(*) n,SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) enabled,SUM(up) up,SUM(down) down FROM clients"
    ).first();

    const recent = await DB(env).prepare(
      "SELECT c.name,c.enabled,c.up,c.down,i.protocol,o.name outbound,i.name inbound FROM clients c LEFT JOIN inbounds i ON i.id=c.inbound_id LEFT JOIN outbounds o ON o.id=c.outbound_id ORDER BY c.created DESC LIMIT 6"
    ).all();

    const cf = req.cf || {};
    return json({
      inbounds: Number(a.n || 0),
      outbounds: Number(b.n || 0),
      clients: Number(c.n || 0),
      enabled: Number(c.enabled || 0),
      up: Number(c.up || 0),
      down: Number(c.down || 0),
      recent: recent.results || [],
      country: cf.country || "",
      colo: cf.colo || "EDGE"
    });
  }

  if (path === "/api/inbounds" && req.method === "GET") {
    const r = await DB(env)
      .prepare(
        "SELECT i.*,o.name outbound_name FROM inbounds i LEFT JOIN outbounds o ON o.id=i.outbound_id ORDER BY i.created DESC"
      )
      .all();

    return json({ items: r.results || [] });
  }

  if (path === "/api/inbounds" && req.method === "POST") {
    if (!allowed(me, "createInbound")) return json({ error: "Permission denied" }, 403);

    const body = await req.json();

    const protocol = ["vless", "vmess", "trojan", "shadowsocks"].includes(body.protocol)
      ? body.protocol
      : "vless";

    const ports = Array.from(
      new Set((body.ports || []).map(Number).filter(supportedPort))
    ).slice(0, 4);

    if (ports.length < 2 || ports.length > 4) {
      return json({ error: "Choose 2 to 4 Cloudflare-supported ports" }, 400);
    }

    const tlsPorts = Array.from(
      new Set((body.tlsPorts || []).map(Number).filter((x) => ports.includes(x) && isTLSPort(x)))
    );

    const plainPorts = Array.from(
      new Set((body.plainPorts || []).map(Number).filter((x) => ports.includes(x) && !isTLSPort(x)))
    );

    const pathValue = String(body.path || "/ws/" + Math.random().toString(36).slice(2, 10)).trim();
    const existing = await DB(env)
      .prepare("SELECT id FROM inbounds WHERE path=?")
      .bind(pathValue)
      .first();

    if (existing) {
      return json({ error: "Path already exists" }, 409);
    }

    const outbound = await DB(env)
      .prepare("SELECT id FROM outbounds WHERE id=? AND enabled=1 LIMIT 1")
      .bind(String(body.outboundId || ""))
      .first();

    if (!outbound) {
      return json({ error: "Outbound not found" }, 400);
    }

    const limit = Math.max(0, Number(body.trafficLimitGB || 0)) * 1073741824;

    const idValue = id();

    await DB(env)
      .prepare(
        "INSERT INTO inbounds(" +
          "id,name,protocol,port,path,enabled,outbound_id,created," +
          "ports_json,tls_ports_json,plain_ports_json,traffic_limit,max_clients,xray_path" +
          ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      )
      .bind(
        idValue,
        String(body.name || "Inbound"),
        protocol,
        ports[0],
        pathValue,
        1,
        outbound.id,
        now(),
        JSON.stringify(ports),
        JSON.stringify(tlsPorts),
        JSON.stringify(plainPorts),
        limit,
        Math.max(0, Number(body.maxClients || 0)),
        pathValue
      )
      .run();

    await log(env, "inbound_create", req, idValue);

    return json({ ok: true, id: idValue });
  }

  if (path.match(/^\/api\/inbounds\/[^/]+\/toggle$/) && req.method === "POST") {
    if (!allowed(me, "editInbound")) return json({ error: "Permission denied" }, 403);

    const value = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("UPDATE inbounds SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?")
      .bind(value)
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/inbounds\/[^/]+$/) && req.method === "PATCH") {
    if (!allowed(me, "editInbound")) return json({ error: "Permission denied" }, 403);

    const iid = decodeURIComponent(path.split("/")[3]);
    const body = await req.json();

    const old = await DB(env)
      .prepare("SELECT * FROM inbounds WHERE id=?")
      .bind(iid)
      .first();

    if (!old) {
      return json({ error: "Inbound not found" }, 404);
    }

    const ports = Array.from(new Set((body.ports || []).map(Number).filter(supportedPort))).slice(0, 4);

    if (ports.length < 2 || ports.length > 4) {
      return json({ error: "Choose 2 to 4 ports" }, 400);
    }

    const tlsPorts = (body.tlsPorts || []).map(Number).filter((x) => ports.includes(x) && isTLSPort(x));
    const plainPorts = (body.plainPorts || []).map(Number).filter((x) => ports.includes(x) && !isTLSPort(x));
    const limit = Math.max(0, Number(body.trafficLimitGB || 0)) * 1073741824;

    await DB(env).prepare(
      "UPDATE inbounds SET name=?,protocol=?,port=?,path=?,outbound_id=?,ports_json=?,tls_ports_json=?,plain_ports_json=?,traffic_limit=?,max_clients=?,xray_path=? WHERE id=?"
    ).bind(
      String(body.name || old.name),
      ["vless", "vmess", "trojan", "shadowsocks"].includes(body.protocol) ? body.protocol : old.protocol,
      ports[0],
      String(body.path || old.path),
      String(body.outboundId || old.outbound_id),
      JSON.stringify(ports),
      JSON.stringify(tlsPorts),
      JSON.stringify(plainPorts),
      limit,
      Math.max(0, Number(body.maxClients || 0)),
      String(body.path || old.xray_path || old.path),
      iid
    ).run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/inbounds\/[^/]+$/) && req.method === "DELETE") {
    if (!allowed(me, "deleteInbound")) return json({ error: "Permission denied" }, 403);

    const iid = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("DELETE FROM clients WHERE inbound_id=?")
      .bind(iid)
      .run();

    await DB(env)
      .prepare("DELETE FROM inbounds WHERE id=?")
      .bind(iid)
      .run();

    return json({ ok: true });
  }

  if (path === "/api/outbounds" && req.method === "GET") {
    const r = await DB(env)
      .prepare(
        "SELECT o.*,COUNT(c.id) clients FROM outbounds o LEFT JOIN clients c ON c.outbound_id=o.id GROUP BY o.id ORDER BY o.created DESC"
      )
      .all();

    return json({ items: r.results || [] });
  }

  if (path === "/api/outbounds" && req.method === "POST") {
    if (!allowed(me, "manageOutbounds")) return json({ error: "Permission denied" }, 403);

    const body = await req.json();
    const oid = id();
    const type = ["socks5", "http", "direct", "block"].includes(body.type) ? body.type : "direct";

    await DB(env)
      .prepare(
        "INSERT INTO outbounds(id,name,type,host,port,username,password,enabled,created,remark) VALUES(?,?,?,?,?,?,?,?,?,?)"
      )
      .bind(
        oid,
        String(body.name || "Outbound"),
        type,
        String(body.host || ""),
        Number(body.port || 0),
        String(body.username || ""),
        String(body.password || ""),
        1,
        now(),
        String(body.remark || "")
      )
      .run();

    return json({ ok: true, id: oid });
  }

  if (path.match(/^\/api\/outbounds\/[^/]+\/toggle$/) && req.method === "POST") {
    if (!allowed(me, "manageOutbounds")) return json({ error: "Permission denied" }, 403);

    const oid = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("UPDATE outbounds SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?")
      .bind(oid)
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/outbounds\/[^/]+$/) && req.method === "PATCH") {
    if (!allowed(me, "manageOutbounds")) return json({ error: "Permission denied" }, 403);

    const oid = decodeURIComponent(path.split("/")[3]);
    const body = await req.json();

    await DB(env)
      .prepare(
        "UPDATE outbounds SET name=?,type=?,host=?,port=?,username=?,password=?,remark=? WHERE id=?"
      )
      .bind(
        String(body.name || "Outbound"),
        String(body.type || "direct"),
        String(body.host || ""),
        Number(body.port || 0),
        String(body.username || ""),
        body.password !== undefined ? String(body.password) : "",
        String(body.remark || ""),
        oid
      )
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/outbounds\/[^/]+$/) && req.method === "DELETE") {
    if (!allowed(me, "manageOutbounds")) return json({ error: "Permission denied" }, 403);

    const oid = decodeURIComponent(path.split("/")[3]);

    const inUse = await DB(env)
      .prepare(
        "SELECT id FROM clients WHERE outbound_id=? UNION SELECT id FROM inbounds WHERE outbound_id=? LIMIT 1"
      )
      .bind(oid, oid)
      .first();

    if (inUse) {
      return json({ error: "Outbound is still in use" }, 409);
    }

    await DB(env)
      .prepare("DELETE FROM outbounds WHERE id=?")
      .bind(oid)
      .run();

    return json({ ok: true });
  }

  if (path === "/api/clients" && req.method === "GET") {
    const r = await DB(env)
      .prepare(
        "SELECT c.*,i.name inbound,i.protocol,o.name outbound FROM clients c LEFT JOIN inbounds i ON i.id=c.inbound_id LEFT JOIN outbounds o ON o.id=c.outbound_id ORDER BY c.created DESC"
      )
      .all();

    return json({ items: r.results || [] });
  }

  if (path === "/api/clients" && req.method === "POST") {
    if (!allowed(me, "createClient")) return json({ error: "Permission denied" }, 403);

    const body = await req.json();

    const inbound = await DB(env)
      .prepare("SELECT * FROM inbounds WHERE id=? AND enabled=1")
      .bind(String(body.inboundId || ""))
      .first();

    if (!inbound) {
      return json({ error: "Inbound not found" }, 400);
    }

    const count = await DB(env)
      .prepare("SELECT COUNT(*) n FROM clients WHERE inbound_id=?")
      .bind(inbound.id)
      .first();

    if (Number(inbound.max_clients || 0) > 0 && Number(count.n || 0) >= Number(inbound.max_clients)) {
      return json({ error: "Inbound client limit reached" }, 409);
    }

    const outbound = await DB(env)
      .prepare("SELECT * FROM outbounds WHERE id=? AND enabled=1")
      .bind(String(body.outboundId || inbound.outbound_id))
      .first();

    if (!outbound) {
      return json({ error: "Outbound unavailable" }, 400);
    }

    const cid = id();
    const uuidValue = id();
    const pass = (id() + id() + id()).replaceAll("-", "").slice(0, 48);
    let expiry = Number(body.expiry || 0);

    if (!Number.isFinite(expiry)) expiry = 0;

    const quota = Math.max(0, Number(body.quotaGB || 0)) * 1073741824;
    const token = id() + "-" + id();

    await DB(env)
      .prepare(
        "INSERT INTO clients(" +
          "id,inbound_id,outbound_id,name,uuid,password,enabled,up,down,created," +
          "quota,expiry,limit_ip,sub_token,email,comment" +
          ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      )
      .bind(
        cid,
        inbound.id,
        outbound.id,
        String(body.name || "Client"),
        uuidValue,
        pass,
        1,
        0,
        0,
        now(),
        quota,
        expiry,
        Math.max(0, Number(body.limitIp || 0)),
        token,
        "",
        ""
      )
      .run();

    await log(env, "client_create", req, cid);

    return json({ ok: true, id: cid });
  }

  if (path.match(/^\/api\/clients\/[^/]+\/toggle$/) && req.method === "POST") {
    if (!allowed(me, "editClient")) return json({ error: "Permission denied" }, 403);

    const cid = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("UPDATE clients SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?")
      .bind(cid)
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/clients\/[^/]+\/config$/) && req.method === "GET") {
    const cid = decodeURIComponent(path.split("/")[3]);

    const c = await DB(env)
      .prepare(
        "SELECT c.*,i.protocol,i.port,i.path,i.name inbound FROM clients c LEFT JOIN inbounds i ON i.id=c.inbound_id WHERE c.id=? LIMIT 1"
      )
      .bind(cid)
      .first();

    if (!c) {
      return json({ error: "Client not found" }, 404);
    }

    const n = await nodesForClient(env, req, c);
    const publicHost = (await getSetting(env, "public_host")) || new URL(req.url).hostname;
    const sub = "https://" + hostOnly(publicHost) + "/sub/" + c.sub_token;

    return json({
      name: c.name,
      protocol: c.protocol,
      used: Number(c.up || 0) + Number(c.down || 0),
      quota: Number(c.quota || 0),
      expiry: Number(c.expiry || 0),
      daysLeft: c.expiry ? Math.max(0, Math.ceil((Number(c.expiry) - now()) / 86400000)) : null,
      subUrl: sub,
      nodes: n,
      link: n[0] ? n[0].link : ""
    });
  }

  if (path.match(/^\/api\/clients\/[^/]+$/) && req.method === "PATCH") {
    if (!allowed(me, "editClient")) return json({ error: "Permission denied" }, 403);

    const cid = decodeURIComponent(path.split("/")[3]);
    const body = await req.json();

    const old = await DB(env)
      .prepare("SELECT * FROM clients WHERE id=?")
      .bind(cid)
      .first();

    if (!old) {
      return json({ error: "Client not found" }, 404);
    }

    let expiry = Number(body.expiry || 0);

    if (!Number.isFinite(expiry)) {
      expiry = 0;
    }

    const quota = Math.max(0, Number(body.quotaGB || 0)) * 1073741824;
    const inbound = await DB(env)
      .prepare("SELECT * FROM inbounds WHERE id=?")
      .bind(String(body.inboundId || old.inbound_id))
      .first();

    const outbound = await DB(env)
      .prepare("SELECT * FROM outbounds WHERE id=?")
      .bind(String(body.outboundId || old.outbound_id))
      .first();

    if (!inbound || !outbound) {
      return json({ error: "Inbound or outbound not found" }, 400);
    }

    await DB(env)
      .prepare(
        "UPDATE clients SET name=?,inbound_id=?,outbound_id=?,quota=?,expiry=?,limit_ip=? WHERE id=?"
      )
      .bind(
        String(body.name || old.name),
        inbound.id,
        outbound.id,
        quota,
        expiry,
        Math.max(0, Number(body.limitIp || 0)),
        cid
      )
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/clients\/[^/]+$/) && req.method === "DELETE") {
    if (!allowed(me, "deleteClient")) return json({ error: "Permission denied" }, 403);

    const cid = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("DELETE FROM client_ips WHERE client_id=?")
      .bind(cid)
      .run();

    await DB(env)
      .prepare("DELETE FROM clients WHERE id=?")
      .bind(cid)
      .run();

    return json({ ok: true });
  }

  if (path === "/api/clean-ips" && req.method === "GET") {
    const r = await DB(env).prepare("SELECT * FROM clean_ips ORDER BY created ASC").all();
    return json({ items: r.results || [] });
  }

  if (path === "/api/clean-ips" && req.method === "POST") {
    if (!allowed(me, "manageCleanIPs")) return json({ error: "Permission denied" }, 403);

    const body = await req.json();
    const lines = String(body.text || "").split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

    let added = 0;

    for (const line of lines) {
      const parts = line.split("#");
      const ipValue = String(parts.shift() || "").trim();
      const label = parts.join("#").trim();

      if (!validIP(ipValue)) {
        continue;
      }

      try {
        await DB(env)
          .prepare("INSERT INTO clean_ips(id,ip,label,enabled,created) VALUES(?,?,?,?,?)")
          .bind(id(), ipValue, label, 1, now())
          .run();

        added++;
      } catch {}
    }

    return json({ ok: true, added });
  }

  if (path.match(/^\/api\/clean-ips\/[^/]+\/toggle$/) && req.method === "POST") {
    if (!allowed(me, "manageCleanIPs")) return json({ error: "Permission denied" }, 403);

    const iid = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("UPDATE clean_ips SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?")
      .bind(iid)
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/clean-ips\/[^/]+$/) && req.method === "DELETE") {
    if (!allowed(me, "manageCleanIPs")) return json({ error: "Permission denied" }, 403);

    const iid = decodeURIComponent(path.split("/")[3]);

    await DB(env)
      .prepare("DELETE FROM clean_ips WHERE id=?")
      .bind(iid)
      .run();

    return json({ ok: true });
  }

  if (path === "/api/admins" && req.method === "GET") {
    if (!allowed(me, "manageAdmins")) return json({ error: "Permission denied" }, 403);

    const r = await DB(env)
      .prepare("SELECT username,display_name,role,permissions_json,enabled,created FROM admins ORDER BY created ASC")
      .all();

    return json({ items: r.results || [] });
  }

  if (path === "/api/admins" && req.method === "POST") {
    if (!allowed(me, "manageAdmins")) return json({ error: "Permission denied" }, 403);

    const body = await req.json();
    const username = String(body.username || "").trim();

    if (!/^[A-Za-z0-9_.-]{2,32}$/.test(username)) {
      return json({ error: "Invalid username" }, 400);
    }

    const exists = await DB(env)
      .prepare("SELECT username FROM admins WHERE username=?")
      .bind(username)
      .first();

    if (exists) {
      return json({ error: "Username already exists" }, 409);
    }

    const role = body.role === "owner" ? "owner" : "admin";

    const permissions = role === "owner"
      ? {
          view: true,
          createClient: true,
          editClient: true,
          deleteClient: true,
          createInbound: true,
          editInbound: true,
          deleteInbound: true,
          manageOutbounds: true,
          manageCleanIPs: true,
          manageAdmins: true,
          manageSettings: true,
          viewLogs: true
        }
      : (body.permissions || { view: true });

    await DB(env)
      .prepare(
        "INSERT INTO admins(" +
          "username,password_hash,display_name,role,permissions_json,enabled,created" +
          ") VALUES(?,?,?,?,?,?,?)"
      )
      .bind(
        username,
        await sha256(String(body.password || "admin")),
        String(body.displayName || username),
        role,
        JSON.stringify(permissions),
        1,
        now()
      )
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/admins\/[^/]+$/) && req.method === "PATCH") {
    if (!allowed(me, "manageAdmins")) return json({ error: "Permission denied" }, 403);

    const username = decodeURIComponent(path.split("/")[3]);
    const body = await req.json();

    const old = await DB(env)
      .prepare("SELECT * FROM admins WHERE username=?")
      .bind(username)
      .first();

    if (!old) {
      return json({ error: "Admin not found" }, 404);
    }

    const role = body.role === "owner" ? "owner" : "admin";

    const permissions = role === "owner"
      ? {
          view: true,
          createClient: true,
          editClient: true,
          deleteClient: true,
          createInbound: true,
          editInbound: true,
          deleteInbound: true,
          manageOutbounds: true,
          manageCleanIPs: true,
          manageAdmins: true,
          manageSettings: true,
          viewLogs: true
        }
      : (body.permissions || safeJSON(old.permissions_json, {}));

    if (username === me.username && old.role === "owner" && role !== "owner") {
      return json({ error: "The owner cannot be demoted" }, 400);
    }

    const fields = ["display_name=?", "role=?", "permissions_json=?"];
    const values = [
      String(body.displayName || old.display_name || username),
      role,
      JSON.stringify(permissions)
    ];

    if (body.password) {
      fields.push("password_hash=?");
      values.push(await sha256(body.password));
    }

    values.push(username);

    await DB(env)
      .prepare("UPDATE admins SET " + fields.join(",") + " WHERE username=?")
      .bind(...values)
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/admins\/[^/]+\/toggle$/) && req.method === "POST") {
    if (!allowed(me, "manageAdmins")) return json({ error: "Permission denied" }, 403);

    const username = decodeURIComponent(path.split("/")[3]);

    if (username === me.username) {
      return json({ error: "You cannot disable yourself" }, 400);
    }

    await DB(env)
      .prepare("UPDATE admins SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE username=?")
      .bind(username)
      .run();

    return json({ ok: true });
  }

  if (path.match(/^\/api\/admins\/[^/]+$/) && req.method === "DELETE") {
    if (!allowed(me, "manageAdmins")) return json({ error: "Permission denied" }, 403);

    const username = decodeURIComponent(path.split("/")[3]);

    if (username === me.username) {
      return json({ error: "You cannot delete yourself" }, 400);
    }

    await DB(env)
      .prepare("DELETE FROM admins WHERE username=?")
      .bind(username)
      .run();

    return json({ ok: true });
  }

  if (path === "/api/settings" && req.method === "GET") {
    const admin = await DB(env)
      .prepare("SELECT username,display_name FROM admins ORDER BY created ASC LIMIT 1")
      .first();

    return json({
      panelName: await getSetting(env, "panel_name", PANEL_DEFAULT),
      publicHost: await getSetting(env, "public_host"),
      xrayOrigin: await getSetting(env, "xray_origin"),
      username: admin ? admin.username : "dollax26",
      displayName: admin ? admin.display_name : "Dollax26",
      cloudflarePorts: CF_PORTS,
      tlsPorts: TLS_PORTS,
      country: (req.cf || {}).country || "",
      colo: (req.cf || {}).colo || "EDGE"
    });
  }

  if (path === "/api/settings" && req.method === "POST") {
    if (!allowed(me, "manageSettings")) return json({ error: "Permission denied" }, 403);

    const body = await req.json();

    if (body.panelName != null) {
      await setSetting(env, "panel_name", String(body.panelName).trim() || PANEL_DEFAULT);
    }

    if (body.publicHost != null) {
      await setSetting(env, "public_host", hostOnly(body.publicHost));
    }

    if (body.xrayOrigin != null) {
      await setSetting(env, "xray_origin", String(body.xrayOrigin || "").trim());
    }

    const old = await DB(env)
      .prepare("SELECT * FROM admins WHERE username=?")
      .bind(me.username)
      .first();

    if (old) {
      const username = String(body.username || old.username);

      if (body.password) {
        await DB(env)
          .prepare(
            "UPDATE admins SET username=?,password_hash=?,display_name=? WHERE username=?"
          )
          .bind(
            username,
            await sha256(body.password),
            String(body.displayName || old.display_name || ""),
            old.username
          )
          .run();
      } else {
        await DB(env)
          .prepare(
            "UPDATE admins SET username=?,display_name=? WHERE username=?"
          )
          .bind(
            username,
            String(body.displayName || old.display_name || ""),
            old.username
          )
          .run();
      }
    }

    return json({ ok: true });
  }

  if (path === "/api/xray/export" && req.method === "GET") {
    const rows = await DB(env).prepare("SELECT * FROM inbounds WHERE enabled=1").all();
    const clients = await DB(env).prepare("SELECT * FROM clients WHERE enabled=1").all();

    const xrayInbounds = [];

    for (const ib of (rows.results || [])) {
      const users = (clients.results || []).filter((x) => x.inbound_id === ib.id);

      const stream = {
        network: "ws",
        security: "none",
        wsSettings: {
          path: ib.xray_path || ib.path
        }
      };

      const settings = {
        clients: users.map((x) => {
          if (ib.protocol === "vless") {
            return { id: x.uuid, email: x.email || x.name, enable: true };
          }

          if (ib.protocol === "vmess") {
            return { id: x.uuid, email: x.email || x.name, security: "auto", level: 0 };
          }

          if (ib.protocol === "trojan") {
            return { password: x.password, email: x.email || x.name };
          }

          return { password: x.password, email: x.email || x.name, method: "aes-128-gcm" };
        })
      };

      if (ib.protocol === "vless") {
        settings.decryption = "none";
      }

      if (ib.protocol === "shadowsocks") {
        settings.method = "aes-128-gcm";
        settings.password = users[0] ? users[0].password : "CHANGE_ME";
      }

      xrayInbounds.push({
        listen: "127.0.0.1",
        port: 10000 + xrayInbounds.length,
        protocol: ib.protocol,
        settings,
        streamSettings: stream
      });
    }

    return json({
      log: { loglevel: "warning" },
      inbounds: xrayInbounds,
      outbounds: [
        { protocol: "freedom", tag: "direct" },
        { protocol: "blackhole", tag: "block" }
      ]
    });
  }

  if (path === "/api/logs") {
    if (!allowed(me, "viewLogs")) return json({ error: "Permission denied" }, 403);

    const r = await DB(env)
      .prepare("SELECT t,event,ip,info FROM logs ORDER BY t DESC LIMIT 300")
      .all();

    return json({ items: r.results || [] });
  }

  return json({ error: "API endpoint not found" }, 404);
}

function subscriptionPage(data) {
  const safe = JSON.stringify(data).replace(/</g, "\\u003c");

  return String.raw`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${data.panelName}</title>
<style>
:root{
  --bg:#0a0f18;
  --panel:#111a29;
  --panel-2:#0f1727;
  --line:#263549;
  --text:#edf6ff;
  --muted:#8ea5c0;
  --accent:#22d4a5;
  --accent-2:#7de7cc;
  --danger:#ff7c88;
}
*{box-sizing:border-box}
html,body{margin:0;width:100%;min-height:100%;font-family:Inter,system-ui,sans-serif;background:radial-gradient(circle at 20% 0%, rgba(34,212,165,.12), transparent 30%), #080d16;color:var(--text)}
.wrap{width:min(900px,94vw);margin:auto;padding:28px 0 45px}
.head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.logo{display:flex;align-items:center;gap:10px}
.logo-mark{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#1ce0b7,#0d8772);font-weight:900;font-size:18px}
.name{font-size:16px;font-weight:900}
.mini{font-size:8px;color:var(--muted);letter-spacing:1px;margin-top:3px}
.status{border:1px solid rgba(34,212,165,.4);color:#4fe7bd;background:rgba(34,212,165,.08);border-radius:999px;padding:6px 10px;font-size:8px;text-transform:uppercase}
.hero{background:linear-gradient(180deg,#111d2d,#0d1723);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 24px 70px rgba(0,0,0,.2)}
.hero h1{margin:0;font-size:22px}
.hero p{margin:7px 0 0;color:var(--muted);font-size:9px}
.grid{display:grid;grid-template-columns:300px 1fr;gap:15px;margin-top:15px}
.panel{background:linear-gradient(180deg,#121d2d,#0d1620);border:1px solid var(--line);border-radius:12px;padding:15px}
.donut{width:210px;height:210px;margin:auto;border-radius:50%;position:relative;display:grid;place-items:center;background:conic-gradient(var(--accent) 0deg,#2d3b4f 0deg)}
.donut::after{content:"";position:absolute;inset:17px;border-radius:50%;background:#0d141d}
.center{position:relative;z-index:1;text-align:center}
.pct{font-size:38px;font-weight:900}
.small{font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.stat{background:#0d141d;border:1px solid #243348;border-radius:8px;padding:11px}
.stat b{display:block;font-size:14px}
.stat span{display:block;font-size:7px;color:#7a8ca6;margin-top:4px}
.progress{height:8px;background:#243348;border-radius:999px;overflow:hidden;margin-top:10px}
.progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent-2))}
.link{word-break:break-all;background:#0a111a;border:1px solid #243348;border-radius:7px;padding:10px;font-size:8px;line-height:1.6}
.node{margin-top:8px;background:#0d1520;border:1px solid #263549;border-radius:8px;padding:10px}
.node-top{display:flex;justify-content:space-between;gap:10px;font-size:8px}
.node-meta{font-size:8px;color:var(--muted);margin-top:4px}
button{height:33px;padding:0 11px;font-size:8px;border-radius:6px;border:1px solid #303f52;background:#1a2433;color:#eaf4ff;cursor:pointer}
button:hover{background:#243246}
.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:8px}
.footer{text-align:center;margin-top:14px;font-size:8px;color:#70819b}
@media(max-width:720px){.grid{grid-template-columns:1fr}.donut{width:180px;height:180px}.stats{grid-template-columns:repeat(3,1fr)}}
</style>
<style>
.navIcon,
.nav-icon {
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:30px;
  min-width:30px;
  height:24px;
  margin-right:7px;
  border:1px solid #34445a;
  border-radius:6px;
  color:#8fa5bf;
  font-size:8px;
  font-weight:800;
  letter-spacing:.3px;
}

.nav button.active .navIcon,
.nav button.active .nav-icon {
  border-color:#1d8269;
  color:#3bd6ab;
  background:#103a31;
}
</style>
</head>

<body>
<div class="wrap">
  <div class="head">
    <div class="logo">
      <div class="logo-mark">D</div>
      <div>
        <div class="name">${data.panelName}</div>
        <div class="mini">PERSONAL VPN SUBSCRIPTION</div>
      </div>
    </div>
    <div class="status">${data.expired ? "EXPIRED" : data.enabled ? "ACTIVE" : "DISABLED"}</div>
  </div>

  <div class="hero">
    <h1>${data.clientName}</h1>
    <p>${data.expired ? "This subscription has expired." : data.enabled ? "Your subscription is active." : "This account is disabled."}</p>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="small">Traffic usage</div>
      <div class="donut" id="donut">
        <div class="center">
          <div class="pct" id="pct">0%</div>
          <div class="small">Used</div>
        </div>
      </div>
      <div class="progress"><i id="bar"></i></div>
    </div>

    <div class="panel">
      <div class="stats">
        <div class="stat"><b>${bytes(data.used)}</b><span>Used</span></div>
        <div class="stat"><b>${data.quota ? bytes(Math.max(0, data.quota - data.used)) : "Unlimited"}</b><span>Remaining</span></div>
        <div class="stat"><b>${data.daysLeft === null ? "âˆž" : data.daysLeft}</b><span>Days left</span></div>
      </div>

      <div style="height:13px"></div>

      <div class="small">Expiration</div>
      <div class="link">${data.expiry ? new Date(data.expiry).toLocaleString() : "Never"}</div>

      <div style="height:12px"></div>

      <div class="small">Subscription URL</div>
      <div class="link">${data.subUrl}</div>

      <div class="actions">
        <button id="copySub">Copy subscription</button>
        <button id="rawSub">Open raw</button>
      </div>
    </div>
  </div>

  <div class="panel" style="margin-top:15px">
    <div class="small">Connection nodes</div>
    <div id="nodes"></div>
  </div>

  <div class="footer">Generated by ${data.panelName}</div>
</div>

<script>
const D=${safe};

const quota = Number(D.quota || 0);
const used = Number(D.used || 0);
const pct = quota ? Math.min(100, used / quota * 100) : 0;

document.getElementById("pct").textContent = Math.round(pct) + "%";
document.getElementById("bar").style.width = pct + "%";

const deg = Math.round(pct * 3.6);
document.getElementById("donut").style.background = "conic-gradient(#22d4a5 " + deg + "deg,#2d3b4f " + deg + "deg)";

document.getElementById("copySub").onclick = function () {
  navigator.clipboard.writeText(D.subUrl);
  this.textContent = "Copied";
  setTimeout(() => { this.textContent = "Copy subscription"; }, 1200);
};

document.getElementById("rawSub").onclick = function () {
  location.href = D.rawUrl;
};

const nodes = document.getElementById("nodes");
(D.nodes || []).forEach(function (n) {
  const div = document.createElement("div");
  div.className = "node";

  div.innerHTML =
    '<div class="node-top"><strong>' + n.protocol.toUpperCase() + ' Â· ' + n.port + '</strong><span>' + (n.tls ? 'TLS' : 'NO TLS') + '</span></div>' +
    '<div class="node-meta">' + (n.addressLabel || n.address) + '</div>' +
    '<div class="link">' + n.link + '</div>' +
    '<div class="actions"><button>Copy configuration</button></div>';

  div.querySelector("button").onclick = function () {
    navigator.clipboard.writeText(n.link);
    this.textContent = "Copied";
    setTimeout(() => { this.textContent = "Copy configuration"; }, 1200);
  };

  nodes.appendChild(div);
});
</script>
</body>
</html>`;
}

async function subscription(req, env, raw) {
  const parts = new URL(req.url).pathname.split("/").filter(Boolean);
  const token = parts[1];

  if (!token) {
    return text("Not found", 404);
  }

  const client = await DB(env)
    .prepare("SELECT * FROM clients WHERE sub_token=? LIMIT 1")
    .bind(token)
    .first();

  if (!client) {
    return text("Subscription not found", 404);
  }

  const nodes = await nodesForClient(env, req, client);
  const rawText = nodes.map((x) => x.link).join("\n");
  const publicHost = (await getSetting(env, "public_host")) || new URL(req.url).hostname;

  if (raw) {
    return new Response(base64UTF8(rawText) + "\n", {
      status: 200,
      headers: {
        "content-type": "text/plain;charset=UTF-8",
        "cache-control": "no-store"
      }
    });
  }

  const data = {
    panelName: await getSetting(env, "panel_name", PANEL_DEFAULT),
    clientName: client.name,
    enabled: Number(client.enabled) === 1,
    expired: expired(client),
    used: Number(client.up || 0) + Number(client.down || 0),
    quota: Number(client.quota || 0),
    expiry: Number(client.expiry || 0),
    daysLeft: client.expiry ? Math.max(0, Math.ceil((Number(client.expiry) - now()) / 86400000)) : null,
    subUrl: "https://" + hostOnly(publicHost) + "/sub/" + token,
    rawUrl: "https://" + hostOnly(publicHost) + "/sub/" + token + "/raw",
    nodes: nodes.map((x) => ({
      protocol: x.protocol,
      port: x.port,
      tls: x.tls,
      address: x.address,
      addressLabel: x.label,
      link: x.link
    }))
  };

  return page(subscriptionPage(data));
}

export default {
  async fetch(req, env, ctx) {
    try {
      await initDB(env);

      const url = new URL(req.url);
      const path = url.pathname;

      if (path === "/") {
        return Response.redirect(new URL("/dashboard", req.url).toString(), 302);
      }

      if (path === "/health") {
        return json({ ok: true, service: PANEL_DEFAULT, time: now() });
      }

      if (path.startsWith("/api/")) {
        return apiHandler(req, env, ctx);
      }

      if (path.startsWith("/sub/")) {
        return subscription(req, env, path.endsWith("/raw"));
      }

      const vless = await DB(env)
        .prepare("SELECT id FROM inbounds WHERE path=? AND protocol='vless' AND enabled=1 LIMIT 1")
        .bind(path)
        .first();

      if (vless) {
        return relay(req, env, ctx, "vless");
      }

      const trojan = await DB(env)
        .prepare("SELECT id FROM inbounds WHERE path=? AND protocol='trojan' AND enabled=1 LIMIT 1")
        .bind(path)
        .first();

      if (trojan) {
        return relay(req, env, ctx, "trojan");
      }

      const vmess = await DB(env)
        .prepare("SELECT * FROM inbounds WHERE path=? AND protocol='vmess' AND enabled=1 LIMIT 1")
        .bind(path)
        .first();

      if (vmess) {
        return xrayBridge(req, env, vmess);
      }

      const ss = await DB(env)
        .prepare("SELECT * FROM inbounds WHERE path=? AND protocol='shadowsocks' AND enabled=1 LIMIT 1")
        .bind(path)
        .first();

      if (ss) {
        return xrayBridge(req, env, ss);
      }

      if (path === "/dashboard" || path === "/dashboard/") {
        return page(DASHBOARD);
      }

      return text("Not Found", 404);
    } catch (e) {
      return text("Worker error\n\n" + String(e && e.stack ? e.stack : e), 500);
    }
  }
};



