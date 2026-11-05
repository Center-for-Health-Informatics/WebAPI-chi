import { readFileSync } from 'node:fs'

const sources = JSON.parse(process.env.WEBAPI_SOURCES || '[]')
if (sources.length === 0) {
  console.warn('Warning: WEBAPI_SOURCES is empty — no CDM sources available')
}

const sso = {
  jwksUrl: process.env.WEBAPI_SSO_JWKS_URL || '',
  issuer: process.env.WEBAPI_SSO_ISSUER || '',
  audience: process.env.WEBAPI_SSO_AUDIENCE || '',
  header: (process.env.WEBAPI_SSO_HEADER || 'sso-assertion').toLowerCase()
}
if (sso.jwksUrl && (!sso.issuer || !sso.audience)) {
  throw new Error('WEBAPI_SSO_JWKS_URL requires WEBAPI_SSO_ISSUER and WEBAPI_SSO_AUDIENCE')
}

const npmPackage = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

const config = Object.freeze({
  package: {
    name: npmPackage.name,
    version: npmPackage.version
  },
  port: parseInt(process.env.EXPRESS_PORT || '80', 10),
  host: process.env.EXPRESS_HOST || '0.0.0.0',
  dbPath: process.env.DB_PATH || '/data/webapi.db',
  authHeader: process.env.WEBAPI_AUTH_HEADER || 'x-forwarded-user',
  sso: Object.freeze(sso),
  version: process.env.WEBAPI_VERSION || '2.15.1',
  sources
})

export default config
