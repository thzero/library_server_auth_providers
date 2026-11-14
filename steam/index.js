import Service from '@thzero/library_server/service/index.js';

// Steam's OpenID 2.0 provider.
const STEAM_LOGIN = 'https://steamcommunity.com/openid/login';
const OPENID_NS = 'http://specs.openid.net/auth/2.0';
// The claimed id Steam answers with: its OpenID id url ending in the SteamID64.
const CLAIMED_ID = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/;
// How old an answer may be (its nonce starts with the time Steam made it), and how long a used
// nonce is remembered so the same answer can't be sent twice.
const NONCE_MAX_AGE_MS = 5 * 60 * 1000;

// Checks a "Sign in through Steam" answer: Steam's OpenID 2.0 sign-in. The browser
// client sends the player to Steam's sign-in page with openid.return_to set to its own callback
// page (config steam.returnUrl), and posts the openid.* fields Steam returned to it here.
// Checked: the fields themselves (mode, provider, return_to, claimed id), the nonce's age and that
// it hasn't been used before, and then Steam itself (check_authentication), which answers
// is_valid:true only for an answer it signed. Used nonces are kept in memory, so the replay check
// covers one instance.
class SteamOpenIdService extends Service {
	constructor() {
		super();

		// nonce -> time it was used
		this._nonces = new Map();
	}

	// Returns { externalType: 'steam', externalId (the SteamID64) } for a valid answer [params].
	async verify(correlationId, params) {
		try {
			const returnUrl = this._config.get('steam.returnUrl');
			if (String.isNullOrEmpty(returnUrl))
				return this._error('SteamOpenIdService', 'verify', 'steam.returnUrl is not configured.', null, null, null, correlationId);

			if (!params || (typeof params !== 'object'))
				return this._error('SteamOpenIdService', 'verify', 'No Steam answer.', null, null, null, correlationId);
			if ((params['openid.ns'] !== OPENID_NS) || (params['openid.mode'] !== 'id_res'))
				return this._error('SteamOpenIdService', 'verify', 'Not a Steam sign-in answer.', null, null, null, correlationId);
			if (params['openid.op_endpoint'] !== STEAM_LOGIN)
				return this._error('SteamOpenIdService', 'verify', 'The answer is not from Steam.', null, null, null, correlationId);
			if (params['openid.return_to'] !== returnUrl)
				return this._error('SteamOpenIdService', 'verify', 'The answer was for another site.', null, null, null, correlationId);

			const claimedId = String(params['openid.claimed_id'] ?? '');
			const match = CLAIMED_ID.exec(claimedId);
			if (!match || (params['openid.identity'] !== claimedId))
				return this._error('SteamOpenIdService', 'verify', 'The answer has no Steam id.', null, null, null, correlationId);

			const nonce = String(params['openid.response_nonce'] ?? '');
			if (!this._useNonce(nonce))
				return this._error('SteamOpenIdService', 'verify', 'The answer is too old or was already used.', null, null, null, correlationId);

			if (!await this._checkWithSteam(params))
				return this._error('SteamOpenIdService', 'verify', 'Steam did not confirm the sign-in.', null, null, null, correlationId);

			return this._successResponse({
				externalType: 'steam',
				externalId: match[1]
			}, correlationId);
		}
		catch (err) {
			return this._error('SteamOpenIdService', 'verify', null, err, null, null, correlationId);
		}
	}

	// Sends the answer back to Steam unchanged except for the mode. Only the openid.* fields go.
	async _checkWithSteam(params) {
		const body = new URLSearchParams();
		for (const [ key, value ] of Object.entries(params)) {
			if (key.startsWith('openid.'))
				body.set(key, String(value));
		}
		body.set('openid.mode', 'check_authentication');

		const response = await fetch(STEAM_LOGIN, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body
		});
		if (!response.ok)
			return false;
		const text = await response.text();
		return /^is_valid:true$/m.test(text);
	}

	// An OpenID nonce starts with the UTC time it was made (2026-11-14T12:00:00Z...). Accepts one
	// that is recent and unused, and remembers it.
	_useNonce(nonce) {
		const now = Date.now();
		for (const [ key, usedAt ] of this._nonces) {
			if ((now - usedAt) > NONCE_MAX_AGE_MS)
				this._nonces.delete(key);
		}

		const madeAt = Date.parse(nonce.slice(0, 20));
		if (Number.isNaN(madeAt) || (Math.abs(now - madeAt) > NONCE_MAX_AGE_MS))
			return false;
		if (this._nonces.has(nonce))
			return false;
		this._nonces.set(nonce, now);
		return true;
	}
}

export default SteamOpenIdService;
