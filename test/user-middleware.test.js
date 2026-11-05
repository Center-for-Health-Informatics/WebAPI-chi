import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, exportJWK, createLocalJWKSet, createRemoteJWKSet, SignJWT } from 'jose'
import { assertionMiddleware } from '../src/middleware/user.js'

const ISSUER = 'https://chi.example.org/auth/'
const AUDIENCE = 'chi.example.org'
const HEADER = 'sso-assertion'
const quiet = { warn () {}, error () {} }

const { privateKey, publicKey } = await generateKeyPair('ES256')
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256' }
const keys = createLocalJWKSet({ keys: [jwk] })

function sign (claims = {}, { key = privateKey, alg = 'ES256', iss = ISSUER, aud = AUDIENCE, exp = '2m' } = {}) {
  return new SignJWT({ email: 'pat@example.org', given_name: 'Pat', family_name: 'Doe', ...claims })
    .setProtectedHeader({ alg, kid: 'k1' })
    .setSubject(claims.sub ?? 'pat')
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key)
}

async function run (headers, mw = assertionMiddleware({ header: HEADER, keys, issuer: ISSUER, audience: AUDIENCE, log: quiet })) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  const req = { get: h => lower[h.toLowerCase()], ip: '127.0.0.1' }
  const res = { statusCode: 200, body: null, status (s) { this.statusCode = s; return this }, json (b) { this.body = b; return this } }
  let nextCalled = false
  await mw(req, res, () => { nextCalled = true })
  return { req, res, nextCalled }
}

test('valid assertion sets req.user', async () => {
  const { req, nextCalled } = await run({ [HEADER]: await sign() })
  assert.ok(nextCalled)
  assert.deepEqual(req.user, { login: 'pat', name: 'Pat Doe', email: 'pat@example.org' })
})

test('missing assertion is 401', async () => {
  const { res, nextCalled } = await run({ 'x-forwarded-user': 'admin' })
  assert.equal(nextCalled, false)
  assert.equal(res.statusCode, 401)
})

test('expired assertion is 403', async () => {
  const past = Math.floor(Date.now() / 1000) - 120
  const { res } = await run({ [HEADER]: await sign({}, { exp: past }) })
  assert.equal(res.statusCode, 403)
})

test('wrong audience is 403', async () => {
  const { res } = await run({ [HEADER]: await sign({}, { aud: 'other.example.org' }) })
  assert.equal(res.statusCode, 403)
})

test('wrong issuer is 403', async () => {
  const { res } = await run({ [HEADER]: await sign({}, { iss: 'https://evil.example.org/auth/' }) })
  assert.equal(res.statusCode, 403)
})

test('signature from another key is 403', async () => {
  const other = await generateKeyPair('ES256')
  const { res } = await run({ [HEADER]: await sign({}, { key: other.privateKey }) })
  assert.equal(res.statusCode, 403)
})

test('HS256 assertion is refused', async () => {
  const secret = new TextEncoder().encode('x'.repeat(32))
  const { res } = await run({ [HEADER]: await sign({}, { key: secret, alg: 'HS256' }) })
  assert.equal(res.statusCode, 403)
})

test('unsigned (alg none) assertion is refused', async () => {
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url')
  const now = Math.floor(Date.now() / 1000)
  const token = `${b64({ alg: 'none' })}.${b64({ sub: 'admin', iss: ISSUER, aud: AUDIENCE, iat: now, exp: now + 60 })}.`
  const { res } = await run({ [HEADER]: token })
  assert.equal(res.statusCode, 403)
})

test('garbage assertion is 403', async () => {
  const { res } = await run({ [HEADER]: 'not-a-jwt' })
  assert.equal(res.statusCode, 403)
})

test('unreachable JWKS is 503, not 403', async () => {
  const mw = assertionMiddleware({
    header: HEADER,
    keys: createRemoteJWKSet(new URL('http://127.0.0.1:1/auth/.well-known/jwks.json'), { timeoutDuration: 1000 }),
    issuer: ISSUER,
    audience: AUDIENCE,
    log: quiet
  })
  const { res } = await run({ [HEADER]: await sign() }, mw)
  assert.equal(res.statusCode, 503)
})
