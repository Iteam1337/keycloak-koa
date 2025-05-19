# keycloak-koa

A simple, secure Keycloak authentication library for Express and Koa applications.

## Installation

```bash
npm install keycloak-koa cookie-parser
```

## Quick Start

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const keycloak = require('keycloak-koa');

const app = express();
app.use(cookieParser());

// Initialize Keycloak
const auth = keycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
});

// Protect routes
app.get('/api/profile', auth.middleware.extractJwtToken, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

## Complete Example

Here's a complete example showing all the endpoints you'll need:

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const keycloak = require('keycloak-koa');

const app = express();
app.use(express.json());
app.use(cookieParser());

// 1. Initialize Keycloak
const auth = keycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
});

// 2. Login endpoint - redirect users to Keycloak
app.get('/login', (req, res) => {
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
  const keycloakLoginUrl = `${auth.keycloakUrl}/protocol/openid-connect/auth?client_id=${auth.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid`;
  
  res.redirect(keycloakLoginUrl);
});

// 3. Callback endpoint - handle the code from Keycloak
app.get('/auth/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
    
    // Exchange code for tokens and set cookies
    const { user } = await auth.handleTokenExchange(code, redirectUri, res);
    
    // Redirect to the application
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Authentication error:', error);
    res.redirect('/login?error=auth_failed');
  }
});

// 4. Protected API routes
app.get('/api/profile', auth.middleware.extractJwtToken, (req, res) => {
  res.json({ 
    user: req.user,
    message: 'This is a protected endpoint' 
  });
});

// 5. Logout endpoint
app.get('/logout', (req, res) => {
  auth.logout(res);
  
  // Optional: redirect to Keycloak logout
  const redirectUri = `${req.protocol}://${req.get('host')}`;
  const keycloakLogoutUrl = `${auth.keycloakUrl}/protocol/openid-connect/logout?redirect_uri=${encodeURIComponent(redirectUri)}`;
  
  res.redirect(keycloakLogoutUrl);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

## API Reference

### keycloak(options)

Initializes the Keycloak integration with your configuration.

**Options:**
- `keycloakUrl` (required): Keycloak server URL with realm
- `clientId` (required): Your application's client ID
- `clientSecret` (required for confidential clients): Client secret

**Returns an object with:**
- `middleware.extractJwtToken`: Middleware to protect routes
- `handleTokenExchange(code, redirectUri, res)`: Helper to exchange code for tokens
- `logout(res)`: Helper to clear auth cookies

## Security Features

- HTTP-only cookies prevent JavaScript access to tokens
- Automatic token verification using Keycloak's JWKS endpoint
- Protection against token tampering and replay attacks
- Secure cookie settings with sameSite and secure flags

## License

MIT
