import { createPublicKey } from 'node:crypto';

import jwt from 'jsonwebtoken';

import Service from '@thzero/library_server/service/index.js';

// Where Epic publishes the keys EOS Connect ID tokens are signed with.
const DEFAULT_JWKS_URL = 'https://api.epicgames.dev/auth/v1/oauth/jwks';
const DEFAULT_ISSUER_PREFIX = 'https://api.epicgames.dev';
// How long fetched keys are kept, and the least time between fetches for an unknown key id.
const JWKS_TTL_MS = 60 * 60 * 1000;
const JWKS_REFETCH_MIN_MS = 60 * 1000;
// An EOS Product User Id: 32 hex characters.
const PUID = /^[0-9a-f]{32}$/;

// Checks an EOS Connect ID token: the JWT a game client gets from EOS Connect (CopyIdToken) after
// its EOS Connect login, signed by Epic. It proves which Product User Id (PUID, the player's
// identity across EOS) the holder is, and which external account (Steam, Epic, device id, ...) that PUID
// is linked to.
// Checked: the signature against Epic's published keys (config eos.jwksUrl), the issuer
// (eos.issuerPrefix), the audience (the application's EOS client id, eos.clientId), expiry, and, when
// configured, the deployment (eos.deploymentId).
class EosIdTokenService extends Service {
	constructor() {
		super();

		// kid -> KeyObject
		this._keys = new Map();
		this._fetchedAt = 0;
	}

	// Returns { puid, externalType, externalId, platform } for a valid [idToken].
	async verify(correlationId, idToken) {
		try {
			const clientId = this._config.get('eos.clientId');
			if (String.isNullOrEmpty(clientId))
				return this._error('EosIdTokenService', 'verify', 'eos.clientId is not configured.', null, null, null, correlationId);

			const decoded = jwt.decode(idToken, { complete: true });
			const kid = decoded?.header?.kid;
			if (!kid)
				return this._error('EosIdTokenService', 'verify', 'Not an EOS ID token.', null, null, null, correlationId);
			const key = await this._key(kid);
			if (!key)
				return this._error('EosIdTokenService', 'verify', 'The ID token was signed with an unknown key.', null, null, null, correlationId);

			const payload = jwt.verify(idToken, key, { algorithms: [ 'RS256' ], audience: clientId });
			const issuerPrefix = String(this._config.get('eos.issuerPrefix') ?? DEFAULT_ISSUER_PREFIX);
			if (!String(payload.iss ?? '').startsWith(issuerPrefix))
				return this._error('EosIdTokenService', 'verify', 'The ID token has the wrong issuer.', null, null, null, correlationId);
			const deploymentId = this._config.get('eos.deploymentId');
			if (!String.isNullOrEmpty(deploymentId) && (payload.pfdid !== deploymentId))
				return this._error('EosIdTokenService', 'verify', 'The ID token is for another deployment.', null, null, null, correlationId);

			const puid = String(payload.sub ?? '').toLowerCase();
			if (!PUID.test(puid))
				return this._error('EosIdTokenService', 'verify', 'The ID token has no product user id.', null, null, null, correlationId);

			return this._successResponse({
				puid,
				externalType: payload.act?.eat ?? null,
				externalId: (payload.act?.eaid !== undefined) ? String(payload.act.eaid) : null,
				platform: payload.act?.pltfm ?? null
			}, correlationId);
		}
		catch (err) {
			return this._error('EosIdTokenService', 'verify', 'The ID token is not valid.', err, null, null, correlationId);
		}
	}

	async _key(kid) {
		const stale = (Date.now() - this._fetchedAt) > JWKS_TTL_MS;
		const unknown = !this._keys.has(kid) && ((Date.now() - this._fetchedAt) > JWKS_REFETCH_MIN_MS);
		if (stale || unknown)
			await this._fetchKeys();
		return this._keys.get(kid) ?? null;
	}

	async _fetchKeys() {
		const url = String(this._config.get('eos.jwksUrl') ?? DEFAULT_JWKS_URL);
		const response = await fetch(url);
		if (!response.ok)
			throw Error(`Fetching EOS keys failed: HTTP ${response.status}`);
		const body = await response.json();
		const keys = new Map();
		for (const jwk of (body?.keys ?? [])) {
			if (!jwk.kid || (jwk.kty !== 'RSA'))
				continue;
			keys.set(jwk.kid, createPublicKey({ key: jwk, format: 'jwk' }));
		}
		this._keys = keys;
		this._fetchedAt = Date.now();
	}
}

export default EosIdTokenService;
