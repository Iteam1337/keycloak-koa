export interface KeycloakOptions {
  keycloakUrl: string
  clientId: string
  clientSecret?: string
}

export interface TokenData {
  access_token: string
  refresh_token?: string
  expires_in: number
  refresh_expires_in?: number
  token_type?: string
  id_token?: string
}

export interface User {
  id: string
  email?: string
  name?: string
  preferred_username?: string
  source: string
}

export interface TokenExchangeResult {
  tokenData: TokenData
  user: User
}

export interface JwksService {
  getJwks(): Promise<any>
  verifyToken(token: string): Promise<any>
}

export interface TokenService {
  exchangeCodeForTokens(code: string, redirectUri: string): Promise<TokenData>
  decodeToken(token: string): any
  extractUserFromToken(token: string, jwksService?: JwksService): Promise<User>
  setCookies(res: any, tokenData: TokenData): void
  clearAuthCookies(res: any): void
}

export interface AuthUrlOptions {
  scope?: string
  responseType?: string
  state?: string
  prompt?: string
}

export interface LogoutUrlOptions {
  idTokenHint?: string
}

export interface KeycloakInstance {
  // Services
  tokenService: TokenService
  jwksService: JwksService

  // Configuration
  keycloakUrl: string
  clientId: string

  // Middleware
  middleware: {
    extractJwtToken: (ctx: any, next: any) => Promise<void>
  }

  // Helper methods
  handleTokenExchange: (
    code: string,
    redirectUri: string,
    res: any
  ) => Promise<TokenExchangeResult>
  logout: (res: any) => void
  getAuthUrl: (redirectUri: string, options?: AuthUrlOptions) => string
  getLogoutUrl: (redirectUri: string, options?: LogoutUrlOptions) => string
  generateRandomState: (length?: number) => string
}

export interface GetAuthUrlOptions {
  keycloakUrl: string
  clientId: string
  redirectUri: string
  scope?: string
  responseType?: string
  state?: string
  prompt?: string
}

export interface GetLogoutUrlOptions {
  keycloakUrl: string
  redirectUri?: string
  idTokenHint?: string
}
