import express from "express";
import httpProxy from "http-proxy";
import Provider from "oidc-provider";

const app = express();
const PORT = process.env.PORT || 3000;

// === CONFIG ===
const ISSUER_URL = process.env.ISSUER_URL;                    // e.g. https://<your-app>.up.railway.app/oidc
const UPSTREAM_ORIGIN = process.env.UPSTREAM_ORIGIN || "https://mcp.kite.trade";
const UPSTREAM_PATH   = process.env.UPSTREAM_PATH   || "/mcp";

if (!ISSUER_URL) {
  console.error("ISSUER_URL not set");
}

// === 1) OAuth Authorization Server (with DCR + PKCE) ===
const oidc = new Provider(ISSUER_URL, {
  // public clients using PKCE
  clientDefaults: {
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"]
  },
  features: {
    registration: { enabled: true }      // Dynamic Client Registration
  },
  pkce: {
    required: () => true,
    methods: ["S256"]
  },
  // use standard endpoint names
  routes: {
    authorization: "/authorize",
    token: "/token",
    jwks: "/jwks",
    registration: "/register"
  },
  // super-minimal account handling: auto-login a stable account
  findAccount: (ctx, id) => ({
    accountId: id,
    async claims() { return { sub: id, email: "user@example.com" }; }
  }),
  interactions: {
    url: (ctx, interaction) => `/oidc/interaction/${interaction.uid}`
  }
});

// auto-complete login & consent (no UI)
app.get("/oidc/interaction/:uid", async (req, res, next) => {
  try {
    const { prompt, uid } = await oidc.interactionDetails(req, res);
    if (prompt.name === "login") {
      await oidc.interactionFinished(
        req, res,
        { login: { accountId: "chatgpt-user", remember: true } },
        { mergeWithLastSubmission: false }
      );
      return;
    }
    if (prompt.name === "consent") {
      await oidc.interactionFinished(
        req, res,
        { consent: {} },
        { mergeWithLastSubmission: false }
      );
      return;
    }
    return next();
  } catch (e) {
    console.error(e);
    res.status(500).send("interaction error");
  }
});

// mount issuer under /oidc
app.use("/oidc", oidc.callback());

// OPTIONAL: OAuth 2.1 discovery alias (ChatGPT may look here)
app.get("/oidc/.well-known/oauth-authorization-server", (req, res) => {
  const base = ISSUER_URL.replace(/\/$/, "");
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    jwks_uri: `${base}/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none","client_secret_post","client_secret_basic"]
  });
});

// === 2) OAuth Protected Resource Metadata for your /mcp endpoint ===
app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  if (!ISSUER_URL) return res.status(500).json({ error: "ISSUER_URL not set" });
  res.json({
    resource: `https://${req.headers.host}/mcp`,
    authorization_servers: [ISSUER_URL],
    resource_name: "Zerodha Kite MCP via OAuth gateway"
  });
});

// === 3) Bearer challenge + proxy to Zerodha MCP ===
function requireBearer(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    res.set("WWW-Authenticate", 'Bearer realm="mcp"');
    return res.sendStatus(401);
  }
  // NOTE: since this AS issues the token, you could verify here using JWKS.
  // For quick start we accept presence of a Bearer token. Add verification later.
  next();
}

const proxy = httpProxy.createProxyServer({ changeOrigin: true, secure: true, ignorePath: true });

app.all("/mcp", requireBearer, (req, res) => {
  proxy.web(req, res, { target: `${UPSTREAM_ORIGIN}${UPSTREAM_PATH}` }, (err) => {
    console.error("Proxy error:", err);
    if (!res.headersSent) res.status(502).json({ error: "Upstream proxy error" });
  });
});

// Health
app.get("/", (_req, res) => res.type("text/plain").send("mcp-oauth-gateway up"));

app.listen(PORT, () => console.log("listening on", PORT));
