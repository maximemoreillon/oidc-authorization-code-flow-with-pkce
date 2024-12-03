import { Hono } from "hono"
import { createCodVerifierAndChallenge } from "./pkce"
import { getCookie, setCookie } from "hono/cookie"
import { getOidcConfig, OAUTH_CLIENT_ID } from "./oidc"

const app = new Hono()

app.get("/", (c) => c.html(`<a href="/login">Click here to login</a>`))

app.get("/login", async (c) => {
  const { authorization_endpoint } = await getOidcConfig()
  const { origin } = new URL(c.req.url)
  const redirect_uri = `${origin}/callback`

  const { verifier, challenge } = createCodVerifierAndChallenge()

  const authUrl = new URL(authorization_endpoint)

  authUrl.searchParams.append("response_type", "code")
  authUrl.searchParams.append("client_id", OAUTH_CLIENT_ID)
  authUrl.searchParams.append("scope", "openid profile")
  authUrl.searchParams.append("code_challenge_method", "S256")
  authUrl.searchParams.append("code_challenge", challenge)
  authUrl.searchParams.append("redirect_uri", redirect_uri)

  setCookie(c, "code_verifier", verifier)

  return c.redirect(authUrl)
})

app.get("/callback", async (c) => {
  const { token_endpoint } = await getOidcConfig()
  const code = new URL(c.req.url).searchParams.get("code")
  if (!code) throw new Error("Code not available")

  const code_verifier = getCookie(c, "code_verifier")
  if (!code_verifier) throw new Error("Verifier not available")

  const { origin } = new URL(c.req.url)
  const redirect_uri = `${origin}/callback`

  const tokenUrl = new URL(token_endpoint)
  const body = new URLSearchParams({
    code,
    code_verifier,
    redirect_uri,
    client_id: OAUTH_CLIENT_ID,
    grant_type: "authorization_code",
  })

  const options: RequestInit = {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  }

  const response = await fetch(tokenUrl.toString(), options)

  const data = await response.json()

  setCookie(c, "access_token", data.access_token)

  return c.json(data)
})

app.get("/userinfo", async (c) => {
  const access_token = getCookie(c, "access_token")
  if (!access_token) throw new Error("Access token not available")
  const { userinfo_endpoint } = await getOidcConfig()

  const options: RequestInit = {
    headers: {
      authorization: `Bearer ${access_token}`,
    },
  }

  const response = await fetch(userinfo_endpoint, options)

  const data = await response.json()

  return c.json(data)
})

export default app
