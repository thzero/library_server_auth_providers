import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, describe, it } from 'node:test';

import jwt from 'jsonwebtoken';

import FirebaseIdTokenService from '../firebase/index.js';
import { setup } from './helpers.js';

const PROJECT = 'example-project';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

let service;
const now = () => Math.floor(Date.now() / 1000);
const sign = (claims, options = {}) => jwt.sign(
	{ iat: now(), auth_time: now(), firebase: { sign_in_provider: 'google.com' }, sub: 'uid', aud: PROJECT, iss: `https://securetoken.google.com/${PROJECT}`, ...claims },
	privateKey, { algorithm: 'RS256', keyid: 'k1', expiresIn: '1h', ...options });

beforeEach(() => {
	service = setup(FirebaseIdTokenService, { 'firebase.projectId': PROJECT });
	// Stands in for Google's published certificates.
	service._key = async (kid) => (kid === 'k1' ? publicKey : null);
});

describe('FirebaseIdTokenService', () => {
	it('answers the Firebase user for a good token', async () => {
		const response = await service.verify('c', sign({}));
		assert.equal(response.success, true);
		assert.deepEqual(response.results, { externalType: 'firebase', externalId: 'uid', name: null, provider: 'google.com' });
	});

	it('answers the name the token carries', async () => {
		assert.equal((await service.verify('c', sign({ name: 'Ada Lovelace' }))).results.name, 'Ada Lovelace');
	});

	it('refuses a token for another project', async () => {
		assert.equal((await service.verify('c', sign({ aud: 'other', iss: 'https://securetoken.google.com/other' }))).success, false);
	});

	it('refuses an expired token', async () => {
		assert.equal((await service.verify('c', sign({}, { expiresIn: -10 }))).success, false);
	});

	it('refuses a token with no user id', async () => {
		assert.equal((await service.verify('c', sign({ sub: '' }))).success, false);
	});

	it('refuses a bad signature, an unknown key and garbage', async () => {
		const token = sign({});
		assert.equal((await service.verify('c', token.slice(0, -4) + 'AAAA')).success, false);
		assert.equal((await service.verify('c', sign({}, { keyid: 'k2' }))).success, false);
		assert.equal((await service.verify('c', 'nonsense')).success, false);
	});
});
