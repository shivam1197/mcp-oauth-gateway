import express from "express";
import httpProxy from "http-proxy";

const app = express();
const PORT = process.env.PORT || 3000;

// Your OAuth Authorization Server (issuer) — e.g., Okta or Keycloak
const ISSUER_URL = process.env.ISSUER_URL; // e.g. https://dev-XXXXX.okta.com/oauth2/default

// Zerodha's hosted MCP upstream
const UPSTREAM_ORIGIN = process.env.UPSTREAM_ORIGIN || "https://mcp.kite.trade";
const UPSTREAM_PATH = process.env.UPSTREAM_PATH || "/mcp";

// 1) Publish OAuth Protected Resource Metadata for your /mcp resource
//    Path includes the resource path ("mcp") per RFC 9728 §3 (pathful resources). 
app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  if (!ISSUER_URL) return res.status(500).json({ error: "ISSUER_URL not set" });
  res.json({
    resource: `https://${req.headers.host}/mcp`,
    authorization_servers: [ISSUER_URL],
    resource_name: "Zerodha Kite MCP via OAuth gateway"
  });
});

// 2) Challenge unauthenticated requests with WWW-Authenticate so ChatGPT runs OAuth
function requireBearer(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    res.set("WWW-Authenticate", 'Bearer realm="mcp"');
    return res.sendStatus(401);
  }
  // TODO (hardening): verify JWT from ISSUER_URL (jwks, audience, expiry)
  next();
}

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: true,
  ignorePath: true, // we’ll pass the full target URL including path
});

// 3) Proxy authenticated traffic to Zerodha’s MCP
app.all("/mcp", requireBearer, (req, res) => {
  proxy.web(
    req,
    res,
    { target: `${UPSTREAM_ORIGIN}${UPSTREAM_PATH}` },
    (err) => {
      console.error("Proxy error:", err);
      if (!res.headersSent) res.status(502).json({ error: "Upstream proxy error" });
    }
  );
});

// Health
app.get("/", (_req, res) => res.type("text/plain").send("mcp-oauth-gateway up"));

app.listen(PORT, () => console.log(`listening on ${PORT}`));
