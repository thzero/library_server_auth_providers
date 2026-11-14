import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import DiscordOAuthService from '../discord/index.js';
import { setup } from './helpers.js';

const config = {
	'discord.clientId': '1571199451295523017',
	'discord.clientSecret': 'secret',
	'discord.redirectUrl': 'https://example.com/auth/discord'
};

let service;
let sent;
let token;
const realFetch = globalThis.fetch;

beforeEach(() => {
	service = setup(DiscordOAuthService, { ...config });
	sent = null;
	token = { ok: true, body: { access_token: 'access', scope: 'identify' } };
	// Stands in for Discord's token and user endpoints.
	globalThis.fetch = async (url, options) => {
		if (url.includes('oauth2/token')) {
			sent = Object.fromEntries(options.body);
			return { ok: token.ok, json: async () => token.body };
		}
		return { ok: true, json: async () => ({ id: '80351110224678912', username: 'player', global_name: 'Player' }) };
	};
});

afterEach(() => {
	globalThis.fetch = realFetch;
});

describe('DiscordOAuthService', () => {
	it('answers the Discord user for a good code', async () => {
		const response = await service.verify('c', 'code');
		assert.equal(response.success, true);
		assert.deepEqual(response.results, { externalType: 'discord', externalId: '80351110224678912', name: 'Player' });
	});

	it('exchanges the code with the secret and the registered redirect', async () => {
		await service.verify('c', 'code');
		assert.equal(sent.grant_type, 'authorization_code');
		assert.equal(sent.code, 'code');
		assert.equal(sent.client_secret, 'secret');
		assert.equal(sent.redirect_uri, config['discord.redirectUrl']);
	});

	it('refuses a code Discord refuses', async () => {
		token = { ok: false, body: { error: 'invalid_grant' } };
		assert.equal((await service.verify('c', 'code')).success, false);
	});

	it('refuses a grant without the identify scope', async () => {
		token.body.scope = 'email';
		assert.equal((await service.verify('c', 'code')).success, false);
	});

	it('refuses no code, and an unconfigured secret', async () => {
		assert.equal((await service.verify('c', '')).success, false);
		const unconfigured = setup(DiscordOAuthService, { ...config, 'discord.clientSecret': '' });
		assert.equal((await unconfigured.verify('c', 'code')).success, false);
	});
});
