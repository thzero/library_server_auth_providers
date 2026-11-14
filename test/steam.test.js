import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import SteamOpenIdService from '../steam/index.js';
import { setup } from './helpers.js';

const RETURN = 'https://example.com/auth/steam';
const CLAIMED = 'https://steamcommunity.com/openid/id/76561197960287930';

let service;
let sent;
let valid;
const realFetch = globalThis.fetch;
const nonce = (suffix = 'a') => `${new Date().toISOString().slice(0, 19)}Z${suffix}`;
const answer = (fields = {}) => ({
	'openid.ns': 'http://specs.openid.net/auth/2.0',
	'openid.mode': 'id_res',
	'openid.op_endpoint': 'https://steamcommunity.com/openid/login',
	'openid.return_to': RETURN,
	'openid.claimed_id': CLAIMED,
	'openid.identity': CLAIMED,
	'openid.response_nonce': nonce(),
	'openid.sig': 'sig',
	...fields
});

beforeEach(() => {
	service = setup(SteamOpenIdService, { 'steam.returnUrl': RETURN });
	sent = null;
	valid = true;
	// Stands in for Steam's check_authentication.
	globalThis.fetch = async (url, options) => {
		sent = options.body.toString();
		return { ok: true, text: async () => `ns:http://specs.openid.net/auth/2.0\nis_valid:${valid}\n` };
	};
});

afterEach(() => {
	globalThis.fetch = realFetch;
});

describe('SteamOpenIdService', () => {
	it('answers the SteamID64 for an answer Steam confirms', async () => {
		const response = await service.verify('c', answer());
		assert.equal(response.success, true);
		assert.deepEqual(response.results, { externalType: 'steam', externalId: '76561197960287930' });
		assert.match(sent, /openid\.mode=check_authentication/);
	});

	it('refuses an answer Steam does not confirm', async () => {
		valid = false;
		assert.equal((await service.verify('c', answer())).success, false);
	});

	it('refuses the same answer twice', async () => {
		const once = answer({ 'openid.response_nonce': nonce('replay') });
		assert.equal((await service.verify('c', once)).success, true);
		assert.equal((await service.verify('c', once)).success, false);
	});

	it('refuses an answer for another site, an old one, and one that is not from Steam', async () => {
		assert.equal((await service.verify('c', answer({ 'openid.return_to': 'https://other.example/', 'openid.response_nonce': nonce('b') }))).success, false);
		assert.equal((await service.verify('c', answer({ 'openid.response_nonce': '2020-01-01T00:00:00Zold' }))).success, false);
		assert.equal((await service.verify('c', answer({ 'openid.op_endpoint': 'https://evil.example/', 'openid.response_nonce': nonce('c') }))).success, false);
	});
});
