declare module 'keycloak-koa' {
  interface KeycloakOptions {
    keycloakUrl: string;
    clientId: string;
    clientSecret?: string;
  }

  interface TokenData {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    refresh_expires_in?: number;
    token_type?: string;
    id_token?: string;
  }

  interface User {
    id: string;
    email?: string;
    name?: string;
    preferred_username?: string;
    source: string;
  }

  interface TokenExchangeResult {
    tokenData: TokenData;
    user: User;
  }

  interface JwksService {
    getJwks(): Promise<any>;
    verifyToken(token: string): Promise<any>;
  }

  interface TokenService {
    exchangeCodeForTokens(code: string, redirectUri: string): Promise<TokenData>;
    decodeToken(token: string): any;
    extractUserFromToken(token: string, jwksService?: JwksService): Promise<User>;
    setCookies(res: any, tokenData: TokenData): void;
    clearAuthCookies(res: any): void;
  }

  interface AuthUrlOptions {
    scope?: string;
    responseType?: string;
    state?: string;
    prompt?: string;
  }

  interface LogoutUrlOptions {
    idTokenHint?: string;
  }

  interface KeycloakInstance {
    // Services
    tokenService: TokenService;
    jwksService: JwksService;

    // Configuration
    keycloakUrl: string;
    clientId: string;

    // Middleware
    middleware: {
      extractJwtToken: (req: any, res: any, next: any) => Promise<void>;
    };

    // Helper methods
    handleTokenExchange: (code: string, redirectUri: string, res: any) => Promise<TokenExchangeResult>;
    logout: (res: any) => void;
    getAuthUrl: (redirectUri: string, options?: AuthUrlOptions) => string;
    getLogoutUrl: (redirectUri: string, options?: LogoutUrlOptions) => string;
    generateRandomState: (length?: number) => string;
  }

  // Main export function
  function initKeycloak(options: KeycloakOptions): KeycloakInstance;

  // URL helper functions
  export function getAuthUrl(options: {
    keycloakUrl: string;
    clientId: string;
    redirectUri: string;
    scope?: string;
    responseType?: string;
    state?: string;
    prompt?: string;
  }): string;

  export function getLogoutUrl(options: {
    keycloakUrl: string;
    redirectUri?: string;
    idTokenHint?: string;
  }): string;

  export function generateRandomState(length?: number): string;

  export default initKeycloak;
}
