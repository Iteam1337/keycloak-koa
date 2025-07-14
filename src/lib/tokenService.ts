import axios from 'axios'
import * as jose from 'jose'
import { TokenData, User } from '../types'
import { JwksService } from './jwksService'
import { Context } from 'koa'

export class TokenService {
  private keycloakUrl: string
  private clientId: string
  private clientSecret: string | undefined
  private tokenEndpoint: string

  constructor(keycloakUrl: string, clientId: string, clientSecret?: string) {
    this.keycloakUrl = keycloakUrl
    this.clientId = clientId
    this.clientSecret = clientSecret
    this.tokenEndpoint = `${keycloakUrl}/protocol/openid-connect/token`
  }

  async exchangeCodeForTokens(
    code: string,
    redirectUri: string
  ): Promise<TokenData> {
    try {
      // Check if client secret is available
      if (!this.clientSecret) {
        throw new Error('Missing client secret configuration')
      }

      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code: code,
        redirect_uri: redirectUri,
      }).toString()

      const response = await axios.post(this.tokenEndpoint, params, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      })

      return response.data
    } catch (error) {
      throw error
    }
  }

  decodeToken(token: string): any {
    return jose.decodeJwt(token)
  }

  async extractUserFromToken(
    token: string,
    jwksService?: JwksService
  ): Promise<User> {
    try {
      // If jwksService is provided, use it to verify the token
      if (jwksService) {
        const verifiedToken = await jwksService.verifyToken(token)
        return {
          id: verifiedToken.sub,
          email: verifiedToken.email,
          name: verifiedToken.name,
          preferred_username: verifiedToken.preferred_username,
          source: 'keycloak',
        }
      } else {
        // Fall back to just decoding without verification
        const decodedToken = this.decodeToken(token)
        return {
          id: decodedToken.sub,
          email: decodedToken.email,
          name: decodedToken.name,
          preferred_username: decodedToken.preferred_username,
          source: 'keycloak',
        }
      }
    } catch (error) {
      throw error
    }
  }

  setCookies(
    ctx: Context,
    { access_token, refresh_token, expires_in }: TokenData
  ): void {
    ctx.cookies.set('auth_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: expires_in * 1000,
    })

    if (refresh_token) {
      ctx.cookies.set('refresh_token', refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      })
    }
  }

  clearAuthCookies(ctx: Context): void {
    ctx.cookies.set('auth_token', null, { maxAge: 0 })
    ctx.cookies.set('refresh_token', null, { maxAge: 0 })
  }
}
