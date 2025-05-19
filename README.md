# keycloak-koa

A simple Keycloak integration for Express/Koa applications.

## Installation

```bash
npm install keycloak-koa
```

## Usage

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const initKeycloak = require('keycloak-koa');

const app = express();
app.use(cookieParser());

// Initialize Keycloak
const keycloak = initKeycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.CLIENT_SECRET
});

// Protect routes with Keycloak authentication
app.get('/api/protected', keycloak.middleware.extractJwtToken, (req, res) => {
  res.json({ user: req.user });
});

// Handle token exchange
app.post('/api/token', async (req, res) => {
  try {
    const { code } = req.body;
    const redirectUri = `${req.protocol}://${req.get('host')}/callback`;
    
    const { user } = await keycloak.handleTokenExchange(code, redirectUri, res);
    
    res.json({ message: 'Authentication successful', user });
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Handle logout
app.get('/api/logout', (req, res) => {
  keycloak.logout(res);
  res.json({ message: 'Logged out successfully' });
});

app.listen(3000);
```

## API

### initKeycloak(options)

Initializes the Keycloak integration.

Options:
- `keycloakUrl`: Keycloak server URL with realm (required)
- `clientId`: Client ID (required)
- `clientSecret`: Client secret for confidential clients

Returns an object with:
- `tokenService`: Service for token operations
- `jwksService`: Service for JWKS operations
- `middleware.extractJwtToken`: Middleware to extract and verify JWT tokens
- `handleTokenExchange(code, redirectUri, res)`: Helper to exchange authorization code for tokens
- `logout(res)`: Helper to clear auth cookies

## License

MIT
