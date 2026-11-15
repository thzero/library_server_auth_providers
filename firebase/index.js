import { X509Certificate } from 'node:crypto';

import jwt from 'jsonwebtoken';

import Service from '@thzero/library_server/service/index.js';

// Where Google publishes the certificates Firebase ID tokens are signed with, by key id.
const CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const ISSUER_PREFIX = 'https://securetoken.google.com/';
// The longest certificates are kept when Google's answer says nothing, and the least time between
// fetches for an unknown key id.
const CERTS_TTL_MS = 60 * 60 * 1000;
const CERTS_REFETCH_MIN_MS = 60 * 1000;

// Checks a Firebase ID token: the JWT the browser client gets from Firebase Auth after signing in
// with Google (or another Firebase provider). It proves the player's Firebase user id.
// Checked, as Firebase documents for verifying ID tokens without its SDK: the signature against
// Google's published certificates, RS256, the audience and issuer (the Firebase project, config
// firebase.projectId), expiry, the time it was issued and signed in, and a user id.
class FirebaseIdTokenService extends Service {
	constructor() {
		super();

		// kid -> public KeyObject
		this._keys = new Map();
		this._expiresAt = 0;
		this._fetchedAt = 0;
	}

	// Returns { externalType: 'firebase', externalId (the Firebase user id), provider } for a valid
	// [idToken].
	async verify(correlationId, idToken) {
		try {
			const projectId = this._config.get('firebase.projectId');
			if (String.isNullOrEmpty(projectId))
				return this._error('FirebaseIdTokenService', 'verify', 'firebase.projectId is not configured.', null, null, null, correlationId);

			const decoded = jwt.decode(String(idToken ?? ''), { complete: true });
			const kid = decoded?.header?.kid;
			if (!kid || (decoded.header.alg !== 'RS256'))
				return this._error('FirebaseIdTokenService', 'verify', 'Not a Firebase ID token.', null, null, null, correlationId);
			const key = await this._key(kid);
			if (!key)
				return this._error('FirebaseIdTokenService', 'verify', 'The ID token was signed with an unknown key.', null, null, null, correlationId);

			const payload = jwt.verify(idToken, key, {
				algorithms: [ 'RS256' ],
				audience: projectId,
				issuer: `${ISSUER_PREFIX}${projectId}`
			});
			const now = Math.floor(Date.now() / 1000);
			if (!payload.iat || (payload.iat > now + 60) || !payload.auth_time || (payload.auth_time > now + 60))
				return this._error('FirebaseIdTokenService', 'verify', 'The ID token is from the future.', null, null, null, correlationId);
			const uid = String(payload.sub ?? '');
			if (!uid || (uid.length > 128))
				return this._error('FirebaseIdTokenService', 'verify', 'The ID token has no user id.', null, null, null, correlationId);

			return this._successResponse({
				externalType: 'firebase',
				externalId: uid,
				name: payload.name ?? null,
				provider: payload.firebase?.sign_in_provider ?? null
			}, correlationId);
		}
		catch (err) {
			return this._error('FirebaseIdTokenService', 'verify', 'The ID token is not valid.', err, null, null, correlationId);
		}
	}

	// The public key for [kid], fetching Google's certificates when they are stale, or when the key
	// is unknown and they weren't fetched in the last minute (Google rotates keys).
	async _key(kid) {
		const now = Date.now();
		if ((now >= this._expiresAt) || (!this._keys.has(kid) && ((now - this._fetchedAt) >= CERTS_REFETCH_MIN_MS)))
			await this._fetchCerts();
		return this._keys.get(kid) ?? null;
	}

	async _fetchCerts() {
		this._fetchedAt = Date.now();
		const response = await fetch(CERTS_URL);
		if (!response.ok)
			throw Error(`Fetching the Firebase certificates failed (${response.status}).`);

		const certs = await response.json();
		const keys = new Map();
		for (const [ kid, pem ] of Object.entries(certs))
			keys.set(kid, new X509Certificate(pem).publicKey);
		this._keys = keys;

		const maxAge = /max-age=(\d+)/.exec(response.headers.get('cache-control') ?? '');
		this._expiresAt = this._fetchedAt + (maxAge ? Number(maxAge[1]) * 1000 : CERTS_TTL_MS);
	}
}

export default FirebaseIdTokenService;
