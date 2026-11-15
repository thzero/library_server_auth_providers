import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeEach, describe, it } from 'node:test';

import jwt from 'jsonwebtoken';

import EosIdTokenService from '../eos/index.js';
import { setup } from './helpers.js';

const CLIENT_ID = 'xyza7891eosclientid';
const DEPLOYMENT_ID = 'deployment-1';
const ISSUER = 'https://api.epicgames.dev/auth/v1/oauth';
const PUID = '0002aa3cbd7d47ef8f73b6ae4c5f3a1b';

// Epic's signing key, as a test stands in for it, and one Epic never published.
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { privateKey: otherKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'test-key-1';

let service;
let fetches;
const realFetch = globalThis.fetch;

// An EOS Connect ID token: [claims] over the usual ones, signed with [key] under [kid].
const token = (claims = {}, { key = privateKey, kid = KID, expiresIn = '1h' } = {}) => jwt.sign({
	iss: ISSUER,
	aud: CLIENT_ID,
	sub: PUID,
	pfdid: DEPLOYMENT_ID,
	act: { eat: 'steam', eaid: '76561197960287930', pltfm: 'other' },
	...claims
}, key, { algorithm: 'RS256', keyid: kid, expiresIn });

const configure = (config = {}) => setup(EosIdTokenService, {
	'eos.clientId': CLIENT_ID,
	'eos.jwksUrl': 'https://keys.example/jwks',
	...config
});

beforeEach(() => {
	service = configure();
	fetches = 0;
	// Stands in for Epic's published keys.
	globalThis.fetch = async () => {
		fetches++;
		return { ok: true, json: async () => ({ keys: [ { ...publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' } ] }) };
	};
});

afterEach(() => {
	globalThis.fetch = realFetch;
});

describe('EosIdTokenService', () => {
	it('answers the PUID and its linked account for a token Epic signed', async () => {
		const response = await service.verify('c', token());
		assert.equal(response.success, true);
		assert.deepEqual(response.results, { puid: PUID, externalType: 'steam', externalId: '76561197960287930', platform: 'other' });
	});

	it('fetches the keys once and keeps them', async () => {
		assert.equal((await service.verify('c', token())).success, true);
		assert.equal((await service.verify('c', token())).success, true);
		assert.equal(fetches, 1);
	});

	it('answers a token with no linked account', async () => {
		const response = await service.verify('c', token({ act: undefined }));
		assert.equal(response.success, true);
		assert.deepEqual(response.results, { puid: PUID, externalType: null, externalId: null, platform: null });
	});

	it('refuses a token signed with a key Epic did not publish', async () => {
		assert.equal((await service.verify('c', token({}, { key: otherKey }))).success, false);
		assert.equal((await service.verify('c', token({}, { key: otherKey, kid: 'unknown-key' }))).success, false);
	});

	it('refuses a token for another application, from another issuer, or expired', async () => {
		assert.equal((await service.verify('c', token({ aud: 'another-client' }))).success, false);
		assert.equal((await service.verify('c', token({ iss: 'https://evil.example' }))).success, false);
		assert.equal((await service.verify('c', token({}, { expiresIn: -10 }))).success, false);
	});

	it('refuses a token without a product user id', async () => {
		assert.equal((await service.verify('c', token({ sub: 'not-a-puid' }))).success, false);
		assert.equal((await service.verify('c', token({ sub: undefined }))).success, false);
	});

	it('refuses something that is not a JWT', async () => {
		assert.equal((await service.verify('c', 'not.a.token')).success, false);
		assert.equal((await service.verify('c', '')).success, false);
	});

	it('checks the deployment only when one is configured', async () => {
		service = configure({ 'eos.deploymentId': DEPLOYMENT_ID });
		assert.equal((await service.verify('c', token())).success, true);
		assert.equal((await service.verify('c', token({ pfdid: 'another-deployment' }))).success, false);

		service = configure();
		assert.equal((await service.verify('c', token({ pfdid: 'another-deployment' }))).success, true);
	});

	it('refuses everything until a client id is configured', async () => {
		service = configure({ 'eos.clientId': null });
		assert.equal((await service.verify('c', token())).success, false);
		assert.equal(fetches, 0);
	});
});
