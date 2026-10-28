/*
 * Servidor do painel da Jardy Beach Wear
 * ---------------------------------------
 * - POST /api/login  { user, password }  -> { token }   (sessão de 12 horas)
 * - PUT  /api/loja   { store }  (com o token)          -> grava loja.json no GitHub da loja
 * - GET  /           -> "ok" (para o Render saber que está no ar)
 *
 * O site (GitHub Pages) lê o loja.json direto do GitHub, então os clientes nunca dependem deste servidor.
 *
 * Variáveis de ambiente (Render -> Environment):
 *   ADMIN_USER       usuário do painel
 *   ADMIN_PASSWORD   senha do painel
 *   GITHUB_TOKEN     chave do GitHub da loja (Contents: Read and write no repositório JardyBeachWear)
 *   REPO             opcional, padrão "jardybeachwear/JardyBeachWear"
 *   BRANCH           opcional, padrão "main"
 *   ALLOWED_ORIGIN   opcional, padrão "https://jardybeachwear.github.io"
 */
"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const ADMIN_USER = (process.env.ADMIN_USER || "").trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const GITHUB_TOKEN = (process.env.GITHUB_TOKEN || "").trim();
const REPO = (process.env.REPO || "jardybeachwear/JardyBeachWear").trim();
const BRANCH = (process.env.BRANCH || "main").trim();
const FILE = "loja.json";
const ORIGINS = (process.env.ALLOWED_ORIGIN || "https://jardybeachwear.github.io").split(",").map(s => s.trim()).filter(Boolean);
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash("sha256").update("jardy|" + ADMIN_PASSWORD + "|" + GITHUB_TOKEN).digest("hex");
const MAX_BODY = 40 * 1024 * 1024;   // fotos e vídeos vão embutidos no catálogo
const SESSION_MS = 12 * 60 * 60 * 1000;

// ---------------------------------------------------------------- utilidades

function send(res, status, data, origin) {
  const body = typeof data === "string" ? data : JSON.stringify(data);
  const headers = {
    "Content-Type": typeof data === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  res.writeHead(status, headers);
  res.end(body);
}

function allowedOrigin(req) {
  const o = req.headers.origin;
  return o && ORIGINS.includes(o) ? o : null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error("Arquivo grande demais (máximo 40 MB)."), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); }
      catch { reject(Object.assign(new Error("Dados inválidos."), { status: 400 })); }
    });
    req.on("error", reject);
  });
}

function safeEqual(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", SECRET).update(data).digest("base64url");
  return data + "." + mac;
}

function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [data, mac] = token.split(".");
  const good = crypto.createHmac("sha256", SECRET).update(data).digest("base64url");
  if (mac.length !== good.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
  try {
    const p = JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

// tentativas de login por IP (bloqueia 15 min depois de 8 erros)
const attempts = new Map();
function ipOf(req) { return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim(); }
function blocked(ip) {
  const a = attempts.get(ip);
  return a && a.count >= 8 && Date.now() - a.first < 15 * 60 * 1000;
}
function failed(ip) {
  const a = attempts.get(ip);
  if (!a || Date.now() - a.first > 15 * 60 * 1000) attempts.set(ip, { count: 1, first: Date.now() });
  else a.count++;
}

// ---------------------------------------------------------------- GitHub

async function github(path, options = {}) {
  const res = await fetch(`https://api.github.com/repos/${REPO}${path}`, {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "User-Agent": "jardy-painel",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {})
    }
  });
  return res;
}

async function currentSha() {
  const res = await github(`/contents/${FILE}?ref=${encodeURIComponent(BRANCH)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw Object.assign(new Error(`GitHub respondeu ${res.status} ao ler o catálogo.`), { status: 502 });
  return (await res.json()).sha || null;
}

let queue = Promise.resolve();   // uma publicação de cada vez

function publish(store) {
  const job = queue.then(async () => {
    const updatedAt = Date.now();
    const content = Buffer.from(JSON.stringify({ app: "jardy", version: 4, updatedAt, store })).toString("base64");
    for (let attempt = 0; attempt < 3; attempt++) {
      const sha = await currentSha();
      const res = await github(`/contents/${FILE}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: `Atualiza a loja pelo painel (${new Date(updatedAt).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })})`,
          content, branch: BRANCH, ...(sha ? { sha } : {})
        })
      });
      if (res.ok) return updatedAt;
      if (res.status === 409 || res.status === 422) continue;
      const msg = res.status === 401 || res.status === 403
        ? "A chave do GitHub (GITHUB_TOKEN) não tem permissão para salvar no site."
        : `GitHub respondeu ${res.status}.`;
      throw Object.assign(new Error(msg), { status: 502 });
    }
    throw Object.assign(new Error("Não foi possível publicar agora. Tente de novo."), { status: 503 });
  });
  queue = job.catch(() => {});
  return job;
}

function validStore(store) {
  return store && typeof store === "object" && Array.isArray(store.products) &&
    store.products.every(p => p && typeof p === "object" && p.id && p.name !== undefined);
}

// ---------------------------------------------------------------- rotas

const server = http.createServer(async (req, res) => {
  const origin = allowedOrigin(req);
  const url = new URL(req.url, "http://x");

  if (req.method === "OPTIONS") {
    if (!origin) { res.writeHead(403); res.end(); return; }
    res.writeHead(204, {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    });
    res.end();
    return;
  }

  try {
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/api/status")) {
      send(res, 200, { ok: true, configurado: Boolean(ADMIN_USER && ADMIN_PASSWORD && GITHUB_TOKEN) }, origin);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/login") {
      if (!origin) { send(res, 403, { erro: "Origem não permitida." }); return; }
      if (!ADMIN_USER || !ADMIN_PASSWORD) { send(res, 503, { erro: "Painel ainda não configurado no servidor." }, origin); return; }
      const ip = ipOf(req);
      if (blocked(ip)) { send(res, 429, { erro: "Muitas tentativas. Aguarde 15 minutos." }, origin); return; }
      const { user, password } = await readBody(req);
      if (!safeEqual(String(user || "").trim(), ADMIN_USER) || !safeEqual(String(password || ""), ADMIN_PASSWORD)) {
        failed(ip);
        send(res, 401, { erro: "Usuário ou senha incorretos." }, origin);
        return;
      }
      attempts.delete(ip);
      send(res, 200, { token: sign({ u: ADMIN_USER, exp: Date.now() + SESSION_MS }) }, origin);
      return;
    }

    if (req.method === "PUT" && url.pathname === "/api/loja") {
      if (!origin) { send(res, 403, { erro: "Origem não permitida." }); return; }
      const auth = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
      if (!verify(auth)) { send(res, 401, { erro: "Sessão expirada. Entre no painel de novo." }, origin); return; }
      if (!GITHUB_TOKEN) { send(res, 503, { erro: "Falta a chave do GitHub (GITHUB_TOKEN) no servidor." }, origin); return; }
      const body = await readBody(req);
      const store = body.store || body;
      if (!validStore(store)) { send(res, 400, { erro: "Catálogo inválido." }, origin); return; }
      const updatedAt = await publish(store);
      send(res, 200, { ok: true, updatedAt }, origin);
      return;
    }

    send(res, 404, { erro: "Não encontrado." }, origin);
  } catch (error) {
    console.error(error);
    send(res, error.status || 500, { erro: error.message || "Erro no servidor." }, origin);
  }
});

server.listen(PORT, () => console.log(`Painel da Jardy no ar na porta ${PORT}. Repositório: ${REPO}@${BRANCH}`));
