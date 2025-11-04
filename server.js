const http = require('http');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/.well-known/oauth-protected-resource/mcp') {
    const body = JSON.stringify({
      name: 'mcp-oauth-gateway',
      status: 'ok'
    });

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body)
    });
    res.end(body);
    return;
  }

  if (url.pathname === '/mcp') {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.trim().toLowerCase().startsWith('bearer ')) {
      res.writeHead(401, {
        'WWW-Authenticate': 'Bearer'
      });
      res.end();
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'application/json'
    });
    res.end(JSON.stringify({ message: 'Authorized access placeholder' }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`MCP OAuth gateway listening on port ${PORT}`);
});
