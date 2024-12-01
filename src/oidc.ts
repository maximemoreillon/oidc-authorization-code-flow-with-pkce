export const { OAUTH_AUTHORITY = "http://localhost", OAUTH_CLIENT_ID = "" } =
  process.env

type OidcConfig = {
  authorization_endpoint: string
  token_endpoint: string
}

export let oidcConfig: OidcConfig

export async function getOidcConfig() {
  if (!oidcConfig) {
    const openIdConfigUrl = `${OAUTH_AUTHORITY}/.well-known/openid-configuration`
    const response = await fetch(openIdConfigUrl)
    oidcConfig = await response.json()
  }
  return oidcConfig
}
