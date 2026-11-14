import Service from '@thzero/library_server/service/index.js';

const TOKEN_URL = 'https://discord.com/api/oauth2/token';
const ME_URL = 'https://discord.com/api/users/@me';
// A Discord user id: a snowflake.
const USER_ID = /^\d{15,25}$/;

// Checks a "Sign in with Discord" answer: Discord's OAuth2 authorization code flow. The browser client sends the player to Discord's authorize page with
// the identify scope; Discord returns them to the client's callback page (config
// discord.redirectUrl) with a code, which the client posts here. The code is exchanged for an
// access token with the application's secret (discord.clientId, discord.clientSecret), which
// reads the player's Discord user. A code works once, and only with the redirect it was issued for.
class DiscordOAuthService extends Service {
	// Returns { externalType: 'discord', externalId (the Discord user id), name } for a valid [code].
	async verify(correlationId, code) {
		try {
			const clientId = this._config.get('discord.clientId');
			const clientSecret = this._config.get('discord.clientSecret');
			const redirectUrl = this._config.get('discord.redirectUrl');
			if (String.isNullOrEmpty(clientId) || String.isNullOrEmpty(clientSecret) || String.isNullOrEmpty(redirectUrl))
				return this._error('DiscordOAuthService', 'verify', 'discord.clientId, clientSecret and redirectUrl must be configured.', null, null, null, correlationId);
			if (String.isNullOrEmpty(code) || (typeof code !== 'string') || (code.length > 512))
				return this._error('DiscordOAuthService', 'verify', 'No Discord answer.', null, null, null, correlationId);

			const tokenResponse = await fetch(TOKEN_URL, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					client_id: clientId,
					client_secret: clientSecret,
					grant_type: 'authorization_code',
					code,
					redirect_uri: redirectUrl
				})
			});
			const tokens = await tokenResponse.json().catch(() => null);
			if (!tokenResponse.ok || !tokens?.access_token)
				return this._error('DiscordOAuthService', 'verify', 'Discord did not confirm the sign-in.', null, null, null, correlationId);
			if (!String(tokens.scope ?? '').split(' ').includes('identify'))
				return this._error('DiscordOAuthService', 'verify', 'Discord did not grant the identify scope.', null, null, null, correlationId);

			const meResponse = await fetch(ME_URL, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
			const me = await meResponse.json().catch(() => null);
			if (!meResponse.ok || !USER_ID.test(String(me?.id ?? '')))
				return this._error('DiscordOAuthService', 'verify', 'Discord did not say who signed in.', null, null, null, correlationId);

			return this._successResponse({
				externalType: 'discord',
				externalId: String(me.id),
				name: me.global_name ?? me.username ?? null
			}, correlationId);
		}
		catch (err) {
			return this._error('DiscordOAuthService', 'verify', null, err, null, null, correlationId);
		}
	}
}

export default DiscordOAuthService;
