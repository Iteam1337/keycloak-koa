import * as jose from 'jose'

export class JwksService {
  private keycloakUrl: string
  private jwksUri: string
  private keyStore: any
  private lastFetched: number | null
  private cacheExpiryMs: number

  constructor(keycloakUrl: string) {
    this.keycloakUrl = keycloakUrl
    this.jwksUri = `${keycloakUrl}/protocol/openid-connect/certs`
    this.keyStore = null
    this.lastFetched = null
    this.cacheExpiryMs = 3600000 // 1 hour
  }

  getJwks() {
    // Check if we need to refresh the JWKS
    const now = Date.now()
    if (
      !this.keyStore ||
      !this.lastFetched ||
      now - this.lastFetched > this.cacheExpiryMs
    ) {
      try {
        // Create a JWKS from the response
        this.keyStore = jose.createRemoteJWKSet(new URL(this.jwksUri))
        this.lastFetched = now
      } catch (error: any) {
        // Only log errors in non-test environments
        if (process.env.NODE_ENV !== 'test') {
          console.error('Error fetching JWKS:', error.message)
        }
        throw error
      }
    }

    return this.keyStore
  }

  async verifyToken(token: string): Promise<any> {
    try {
      const jwks = await this.getJwks()

      // Verify the token
      const { payload } = await jose.jwtVerify(token, jwks, {
        issuer: this.keycloakUrl,
        audience: 'account', // This might need to be adjusted based on your Keycloak configuration
      })

      return payload
    } catch (error: any) {
      // Only log errors in non-test environments
      if (process.env.NODE_ENV !== 'test') {
        console.error('Token verification failed:', error.message)
      }
      throw error
    }
  }
}
