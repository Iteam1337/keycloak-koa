# keycloak-koa

A lightweight, secure Keycloak integration library for Express and Koa applications.

## Overview

This package provides a simple way to integrate Keycloak authentication into your Node.js web applications. It handles token verification, cookie management, and user session management with a focus on security.

## Features

- 🔒 Secure token verification using JWKS
- 🍪 HTTP-only cookie management
- 🔄 Authorization code flow support
- 🛡️ Protection for API routes
- 🧩 Easy integration with Express/Koa

## Installation

```bash
npm install keycloak-koa cookie-parser
```

## Server-Side Usage

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const initKeycloak = require('keycloak-koa');

const app = express();
app.use(cookieParser());  // Required for cookie handling

// Initialize Keycloak with your configuration
const keycloak = initKeycloak({
  keycloakUrl: 'https://auth.example.com/realms/my-realm',
  clientId: 'my-client',
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
});

// Protect routes with Keycloak authentication
app.get('/api/profile', keycloak.middleware.extractJwtToken, (req, res) => {
  // req.user contains the authenticated user information
  res.json({ 
    profile: req.user,
    message: 'This route is protected' 
  });
});

// Handle the OAuth callback
app.get('/auth/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
    
    // Exchange code for tokens and set cookies
    const { user } = await keycloak.handleTokenExchange(code, redirectUri, res);
    
    // Redirect to the application
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Authentication error:', error);
    res.redirect('/login?error=auth_failed');
  }
});

// Logout endpoint
app.get('/auth/logout', (req, res) => {
  keycloak.logout(res);
  res.redirect('/login');
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

## API Reference

### initKeycloak(options)

Initializes the Keycloak integration.

**Options:**
- `keycloakUrl` (required): Keycloak server URL with realm (e.g., 'https://auth.example.com/realms/my-realm')
- `clientId` (required): Your application's client ID in Keycloak
- `clientSecret` (required for confidential clients): Client secret for secure backend applications

**Returns an object with:**
- `tokenService`: Service for token operations
- `jwksService`: Service for JWKS operations
- `middleware.extractJwtToken`: Middleware to extract and verify JWT tokens
- `handleTokenExchange(code, redirectUri, res)`: Helper to exchange authorization code for tokens
- `logout(res)`: Helper to clear authentication cookies

## Security Features

- Tokens are stored in HTTP-only cookies to prevent JavaScript access
- Automatic token verification using Keycloak's JWKS endpoint
- Protection against token tampering and replay attacks
- Secure cookie settings with sameSite and secure flags

## License

MIT
