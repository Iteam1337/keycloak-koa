# keycloak-koa

A simple, secure Keycloak authentication library for Express and Koa applications with TypeScript support.

## Installation

```bash
npm install keycloak-koa cookie-parser
```

## Quick Start

### Express

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import keycloak from 'keycloak-koa';

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

### Koa

```typescript
import Koa from 'koa';
import Router from 'koa-router';
import koaCookie from 'koa-cookie';
import keycloak from 'keycloak-koa';

const app = new Koa();
app.use(koaCookie());

const router = new Router();

// Initialize Keycloak
const auth = keycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
});

// Protect routes
router.get('/api/profile', auth.middleware.extractJwtToken, async (ctx) => {
  ctx.body = { user: ctx.state.user };
});

app.use(router.routes());
app.listen(3000);
```

## Complete Example

Here's a complete example showing all the endpoints you'll need:

### Express Example

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import keycloak from 'keycloak-koa';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// 1. Initialize Keycloak
const auth = keycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
});

// 2. Login endpoint - redirect users to Keycloak
app.get('/login', (req, res) => {
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
  
  // Generate a random state for CSRF protection
  const state = auth.generateRandomState();
  req.session.authState = state; // Store in session
  
  // Use the helper to generate the auth URL
  const authUrl = auth.getAuthUrl(redirectUri, { state });
  res.redirect(authUrl);
});

// 3. Callback endpoint - handle the code from Keycloak
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    
    // Verify state parameter to prevent CSRF attacks
    if (state !== req.session.authState) {
      return res.redirect('/login?error=invalid_state');
    }
    
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
    
    // Exchange code for tokens and set cookies
    const { user } = await auth.handleTokenExchange(code as string, redirectUri, res);
    
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
  
  // Use the helper to generate the logout URL
  const redirectUri = `${req.protocol}://${req.get('host')}`;
  const logoutUrl = auth.getLogoutUrl(redirectUri);
  
  res.redirect(logoutUrl);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

### Koa Example

```typescript
import Koa from 'koa';
import Router from 'koa-router';
import koaBody from 'koa-body';
import koaCookie from 'koa-cookie';
import session from 'koa-session';
import keycloak from 'keycloak-koa';

const app = new Koa();
app.keys = ['your-secret-key'];

app.use(koaBody());
app.use(koaCookie());
app.use(session(app));

const router = new Router();

// 1. Initialize Keycloak
const auth = keycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
});

// 2. Login endpoint - redirect users to Keycloak
router.get('/login', async (ctx) => {
  const redirectUri = `${ctx.protocol}://${ctx.host}/auth/callback`;
  
  // Generate a random state for CSRF protection
  const state = auth.generateRandomState();
  ctx.session.authState = state; // Store in session
  
  // Use the helper to generate the auth URL
  const authUrl = auth.getAuthUrl(redirectUri, { state });
  ctx.redirect(authUrl);
});

// 3. Callback endpoint - handle the code from Keycloak
router.get('/auth/callback', async (ctx) => {
  try {
    const { code, state } = ctx.query;
    
    // Verify state parameter to prevent CSRF attacks
    if (state !== ctx.session.authState) {
      return ctx.redirect('/login?error=invalid_state');
    }
    
    const redirectUri = `${ctx.protocol}://${ctx.host}/auth/callback`;
    
    // Exchange code for tokens and set cookies
    const { user } = await auth.handleTokenExchange(code as string, redirectUri, ctx);
    
    // Redirect to the application
    ctx.redirect('/dashboard');
  } catch (error) {
    console.error('Authentication error:', error);
    ctx.redirect('/login?error=auth_failed');
  }
});

// 4. Protected API routes
router.get('/api/profile', auth.middleware.extractJwtToken, async (ctx) => {
  ctx.body = { 
    user: ctx.state.user,
    message: 'This is a protected endpoint' 
  };
});

// 5. Logout endpoint
router.get('/logout', async (ctx) => {
  auth.logout(ctx);
  
  // Use the helper to generate the logout URL
  const redirectUri = `${ctx.protocol}://${ctx.host}`;
  const logoutUrl = auth.getLogoutUrl(redirectUri);
  
  ctx.redirect(logoutUrl);
});

app.use(router.routes());
app.use(router.allowedMethods());

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
- `getAuthUrl(redirectUri, options)`: Helper to generate Keycloak authorization URL
- `getLogoutUrl(redirectUri, options)`: Helper to generate Keycloak logout URL
- `generateRandomState(length)`: Helper to generate random state for CSRF protection

### URL Helper Functions

These functions are also available directly from the module:

#### getAuthUrl(options)

Generates a Keycloak authorization URL.

```javascript
const { getAuthUrl } = require('keycloak-koa');

const authUrl = getAuthUrl({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  redirectUri: 'https://myapp.com/callback',
  scope: 'openid profile email',
  state: 'random-state-string',
  prompt: 'login' // Force login even if already authenticated
});
```

#### getLogoutUrl(options)

Generates a Keycloak logout URL.

```javascript
const { getLogoutUrl } = require('keycloak-koa');

const logoutUrl = getLogoutUrl({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  redirectUri: 'https://myapp.com/logged-out',
  idTokenHint: 'optional-id-token'
});
```

#### generateRandomState(length)

Generates a random string for CSRF protection.

```javascript
const { generateRandomState } = require('keycloak-koa');

const state = generateRandomState(32); // Default length is 32
```

## Security Features

- HTTP-only cookies prevent JavaScript access to tokens
- Automatic token verification using Keycloak's JWKS endpoint
- Protection against token tampering and replay attacks
- Secure cookie settings with sameSite and secure flags

## License

MIT
