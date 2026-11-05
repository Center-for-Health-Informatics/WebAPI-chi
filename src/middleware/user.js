import { createRemoteJWKSet, jwtVerify } from 'jose'
import config from '../config.js'

// jose's codes for a token that is simply not good: forged, expired, for another
// host. Anything else (key set unreachable, malformed key set response) is this
// service's problem, not the caller's, and must not read as "signed out".
// Same set as Center-for-Health-Informatics/monitor lib/identity.js.
const INVALID = new Set([
  'ERR_JWS_SIGNATURE_VERIFICATION_FAILED', 'ERR_JWS_INVALID', 'ERR_JWT_INVALID', 'ERR_JWT_EXPIRED',
  'ERR_JWT_CLAIM_VALIDATION_FAILED', 'ERR_JOSE_ALG_NOT_ALLOWED', 'ERR_JOSE_NOT_SUPPORTED',
  'ERR_JWKS_NO_MATCHING_KEY', 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'
])

function fail (res, status, message) {
  res.status(status).json({ status, message })
}

/**
 * Identifies the caller from CHI Authentication's SSO assertion: an ES256 JWT
 * that nginx obtains from `auth_request /auth/check_permissions` and forwards as
 * a request header. Verified against CHI Authentication's JWKS, with `iss` and
 * `aud` pinned to configured values, so nothing a client writes is trusted.
 *
 * - no assertion          -> 401 (nginx not forwarding it, or the route bypassed auth)
 * - assertion refused     -> 403
 * - key set unreachable   -> 503
 */
export function assertionMiddleware ({ header, keys, issuer, audience, log = console }) {
  return async (req, res, next) => {
    const token = req.get(header)
    if (!token) {
      if (req.get('sso-username')) {
        log.error(`request carried SSO-Username but no ${header}: nginx must forward the signed assertion`)
      }
      return fail(res, 401, 'Not signed in.')
    }
    let payload
    try {
      ({ payload } = await jwtVerify(token, keys, {
        algorithms: ['ES256'],
        issuer,
        audience,
        clockTolerance: 30
      }))
    } catch (err) {
      if (!INVALID.has(err.code)) {
        log.error(`cannot verify ${header}: ${err.code ?? err.name}: ${err.message}`)
        return fail(res, 503, 'Sign-in cannot be checked right now.')
      }
      log.warn(`${header} refused from ${req.ip}: ${err.code}: ${err.message}`)
      return fail(res, 403, 'Your sign-in could not be verified.')
    }
    if (typeof payload.sub !== 'string' || payload.sub === '') {
      log.warn(`${header} refused from ${req.ip}: no subject`)
      return fail(res, 403, 'Your sign-in could not be verified.')
    }
    const str = v => (typeof v === 'string' ? v : '')
    const name = [str(payload.given_name), str(payload.family_name)].filter(Boolean).join(' ')
    req.user = { login: payload.sub, name: name || payload.sub, email: str(payload.email) }
    next()
  }
}

/**
 * Legacy mode: trusts a plain username header. Only safe when nothing can reach
 * this service except through a proxy that overwrites the header.
 */
export function headerMiddleware ({ header }) {
  return (req, res, next) => {
    const login = req.headers[header] || 'anonymous'
    req.user = { login, name: login }
    next()
  }
}

function fromConfig () {
  if (config.sso.jwksUrl) {
    return assertionMiddleware({
      header: config.sso.header,
      keys: createRemoteJWKSet(new URL(config.sso.jwksUrl)),
      issuer: config.sso.issuer,
      audience: config.sso.audience
    })
  }
  console.warn(`Warning: WEBAPI_SSO_JWKS_URL is not set; trusting the unsigned ${config.authHeader} header`)
  return headerMiddleware({ header: config.authHeader })
}

export default fromConfig()
