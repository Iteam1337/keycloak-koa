import { GetAuthUrlOptions, GetLogoutUrlOptions } from '../types'

/**
 * Generates a Keycloak authorization URL for the login flow
 */
export function getAuthUrl({
  keycloakUrl,
  clientId,
  redirectUri,
  scope = 'openid',
  responseType = 'code',
  state,
  prompt,
}: GetAuthUrlOptions): string {
  if (!keycloakUrl) throw new Error('keycloakUrl is required')
  if (!clientId) throw new Error('clientId is required')
  if (!redirectUri) throw new Error('redirectUri is required')

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: responseType,
    scope,
  })

  if (state) params.append('state', state)
  if (prompt) params.append('prompt', prompt)

  return `${keycloakUrl}/protocol/openid-connect/auth?${params.toString()}`
}

/**
 * Generates a Keycloak logout URL
 */
export function getLogoutUrl({
  keycloakUrl,
  redirectUri,
  idTokenHint,
}: GetLogoutUrlOptions): string {
  if (!keycloakUrl) throw new Error('keycloakUrl is required')

  const params = new URLSearchParams()

  if (redirectUri) params.append('redirect_uri', redirectUri)
  if (idTokenHint) params.append('id_token_hint', idTokenHint)

  const queryString = params.toString()
  return `${keycloakUrl}/protocol/openid-connect/logout${
    queryString ? '?' + queryString : ''
  }`
}

/**
 * Generates a random string for use as a state parameter
 */
export function generateRandomState(length = 32): string {
  const characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  const charactersLength = characters.length

  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength))
  }

  return result
}
