import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, describe, it } from 'node:test';

import jwt from 'jsonwebtoken';

import AccountsService from '../accounts/index.js';
import { setup } from './helpers.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const config = { 'auth.jwt.algorithm': 'RS256', 'auth.jwt.privateKey': privateKey, 'auth.jwt.publicKey': publicKey };
const BASIC = 'basic';
const PUID = 'b'.repeat(32);
const PUID2 = 'c'.repeat(32);

// An app's accounts, as a game would set them up: EOS accounts (keyed by PUID) are primary, and
// two accounts that both play in games don't merge.
class GameAccountsService extends AccountsService {
	async _canMerge(correlationId, user, other) {
		if (games.has(user.id) && games.has(other.id))
			return this._error('GameAccountsService', '_canMerge', 'Both play in games.', null, null, null, correlationId);
		return this._success(correlationId);
	}

	async _conflictDetails(correlationId, other) {
		return { hasGames: games.has(other.id) };
	}

	_isPrimary(user) {
		return /^[0-9a-f]{32}$/.test(String(user?.id ?? ''));
	}

	_mergeInto(survivor, retired, created) {
		const basic = survivor.planId === BASIC;
		super._mergeInto(survivor, retired, created);
		if (basic && retired.planId)
			survivor.planId = retired.planId;
	}

	async _newUser() {
		return { id: `new${++created}`, planId: BASIC, roles: [ 'user' ] };
	}

	async _signIn(correlationId, user, identity) {
		signedInWith = identity;
		return this._successResponse({ token: `token:${user.id}`, user }, correlationId);
	}
}

let signedInWith = null;
let users;
let games;
let created;
let service;

// The users repository AccountsService needs, in memory. fetchByLogin finds a sign-in in a user's
// logins or external account, never a retired user, as BaseUserMongoRepository's does.
const matches = (user, type, id, excludeId) => !user.mergedInto
	&& (user.id !== excludeId)
	&& ((user.logins ?? []).some((login) => (login.type === type) && (login.id === id))
		|| ((user.external?.type === type) && (user.external?.id === id)));
const found = (correlationId, results) => ({ success: !!results, results: results ? structuredClone(results) : null, correlationId });
const repository = {
	fetch: async (correlationId, id) => found(correlationId, users.get(id)),
	fetchByLogin: async (correlationId, type, id, excludeId) => found(correlationId, [ ...users.values() ].find((user) => matches(user, type, id, excludeId))),
	updateFromExternal: async (correlationId, id, user) => {
		users.set(id, structuredClone(user));
		return found(correlationId, user);
	}
};

const add = (user) => users.set(user.id, user);
// A proof stands in for a checked Steam answer, Firebase token or Discord code.
const proof = (type, id) => ({ type, id });

beforeEach(() => {
	users = new Map();
	games = new Set();
	created = 0;
	service = setup(GameAccountsService, config);
	service._repositoryUsers = repository;
	service._verifyProof = async (correlationId, request) => ({ success: true, results: { externalType: request.type, externalId: request.id } });
});

describe('AccountsService.signInWith', () => {
	it('creates a user for a new sign-in, and finds it the next time', async () => {
		const first = await service.signInWith('c', { externalType: 'discord', externalId: 'd1' });
		assert.equal(first.results.token, 'token:new1');
		assert.deepEqual(users.get('new1').logins, [ { type: 'discord', id: 'd1' } ]);
		const second = await service.signInWith('c', { externalType: 'discord', externalId: 'd1' });
		assert.equal(second.results.user.id, 'new1');
		assert.equal(users.size, 1);
	});

	it('hands the sign-in, with its name, to the app, and stores no name', async () => {
		await service.signInWith('c', { externalType: 'discord', externalId: 'd2', name: 'Disco' });
		assert.equal(signedInWith.name, 'Disco');
		const stored = [ ...users.values() ].find((user) => user.logins?.some((login) => login.id === 'd2'));
		assert.equal(JSON.stringify(stored).includes('Disco'), false);
	});

	it('finds a game account by its external account', async () => {
		add({ id: PUID, external: { type: 'steam', id: 's1' } });
		assert.equal((await service.signInWith('c', { externalType: 'steam', externalId: 's1' })).results.user.id, PUID);
	});
});

describe('AccountsService.link', () => {
	it('links a sign-in nobody has', async () => {
		add({ id: 'g1', logins: [ { type: 'firebase', id: 'f1' } ] });
		const response = await service.link('c', users.get('g1'), proof('steam', 's1'));
		assert.equal(response.results.status, 'linked');
		assert.deepEqual(response.results.account.logins.map((login) => login.type), [ 'firebase', 'steam' ]);
	});

	it('asks to merge when the sign-in has its own account, and merges into the primary one', async () => {
		add({ id: 'g1', planId: 'paid', roles: [ 'user' ], logins: [ { type: 'firebase', id: 'f1' } ] });
		add({ id: PUID, planId: BASIC, roles: [ 'user', 'admin' ], external: { type: 'steam', id: 's1' }, logins: [ { type: 'steam', id: 's1' } ] });

		const conflict = await service.link('c', users.get('g1'), proof('steam', 's1'));
		assert.equal(conflict.results.status, 'conflict');
		assert.equal(conflict.results.hasGames, false);

		const merged = await service.linkConfirm('c', users.get('g1'), { ticket: conflict.results.ticket });
		assert.equal(merged.results.token, `token:${PUID}`);
		const survivor = users.get(PUID);
		assert.deepEqual(survivor.logins.map((login) => login.type).sort(), [ 'firebase', 'steam' ]);
		assert.deepEqual(survivor.roles.sort(), [ 'admin', 'user' ]);
		assert.equal(survivor.planId, 'paid');
		assert.equal(users.get('g1').mergedInto, PUID);
		assert.deepEqual(users.get('g1').logins, []);
		assert.equal((await repository.fetchByLogin('c', 'firebase', 'f1')).results.id, PUID);
		assert.equal((await service.currentUser('c', users.get('g1'))).results.id, PUID);
	});

	it('refuses a ticket for someone else, and the same ticket twice', async () => {
		add({ id: 'g1', logins: [ { type: 'firebase', id: 'f1' } ] });
		add({ id: 'g2', logins: [ { type: 'steam', id: 's1' } ] });
		const { ticket } = (await service.link('c', users.get('g1'), proof('steam', 's1'))).results;
		assert.equal((await service.linkConfirm('c', users.get('g2'), { ticket })).success, false);
		assert.equal((await service.linkConfirm('c', users.get('g1'), { ticket })).success, true);
		assert.equal((await service.linkConfirm('c', users.get('g1'), { ticket })).success, false);
	});

	it('refuses to merge two primary accounts, and when the app refuses', async () => {
		add({ id: PUID, external: { type: 'steam', id: 's1' }, logins: [ { type: 'steam', id: 's1' } ] });
		add({ id: PUID2, external: { type: 'firebase', id: 'f1' }, logins: [ { type: 'firebase', id: 'f1' } ] });
		let ticket = (await service.link('c', users.get(PUID), proof('firebase', 'f1'))).results.ticket;
		assert.equal((await service.linkConfirm('c', users.get(PUID), { ticket })).success, false);

		add({ id: 'g1', logins: [ { type: 'discord', id: 'd1' } ] });
		add({ id: 'g2', logins: [ { type: 'discord', id: 'd2' } ] });
		games.add('g1');
		games.add('g2');
		ticket = (await service.link('c', users.get('g1'), proof('discord', 'd2'))).results.ticket;
		assert.equal((await service.linkConfirm('c', users.get('g1'), { ticket })).message, 'Both play in games.');
	});

	it('issues tickets that are never a login token', async () => {
		add({ id: 'g1', logins: [] });
		add({ id: 'g2', logins: [ { type: 'steam', id: 's1' } ] });
		const { ticket } = (await service.link('c', users.get('g1'), proof('steam', 's1'))).results;
		assert.equal(jwt.decode(ticket).typ, 'link');
	});

	it('does not store the plan a fetched user carries', async () => {
		add({ id: 'g1', logins: [] });
		await service.link('c', { ...users.get('g1'), plan: { name: 'basic' } }, proof('steam', 's9'));
		assert.equal('plan' in users.get('g1'), false);
	});
});

describe('AccountsService.unlink', () => {
	it('unlinks a sign-in, but never the last or the external account', async () => {
		add({ id: PUID, external: { type: 'steam', id: 's1' }, logins: [ { type: 'steam', id: 's1' }, { type: 'firebase', id: 'f1' } ] });
		assert.equal((await service.unlink('c', users.get(PUID), { type: 'steam', id: 's1' })).success, false);
		const response = await service.unlink('c', users.get(PUID), { type: 'firebase', id: 'f1' });
		assert.deepEqual(response.results.account.logins, [ { type: 'steam', id: 's1', locked: true } ]);

		add({ id: 'g1', logins: [ { type: 'discord', id: 'd1' } ] });
		assert.equal((await service.unlink('c', users.get('g1'), { type: 'discord', id: 'd1' })).success, false);
	});
});

describe('AccountsService.mergeLinked', () => {
	it('folds an account on the same sign-in into a new primary account', async () => {
		add({ id: 'g1', planId: 'paid', roles: [ 'user', 'admin' ], logins: [ { type: 'steam', id: 's1' }, { type: 'discord', id: 'd1' } ] });
		const user = { id: PUID, planId: BASIC, roles: [ 'user' ], external: { type: 'steam', id: 's1' }, logins: [ { type: 'steam', id: 's1' } ] };
		await service.mergeLinked('c', user, { externalType: 'steam', externalId: 's1' }, true);
		assert.equal(user.planId, 'paid');
		assert.deepEqual(user.logins.map((login) => login.type), [ 'steam', 'discord' ]);
		assert.deepEqual(user.mergedIds, [ 'g1' ]);
		assert.equal(users.get('g1').mergedInto, PUID);
	});
});

describe('AccountsService defaults', () => {
	it('has no primary accounts, and needs the app to issue its token', async () => {
		const plain = setup(AccountsService, config);
		plain._repositoryUsers = repository;
		assert.equal(plain._isPrimary({ id: PUID }), false);
		const response = await plain.signInWith('c', { externalType: 'steam', externalId: 's1' });
		assert.equal(response.success, false);
	});
});

describe('AccountsService merge ordering', () => {
	it('keeps every sign-in when saving the survivor fails, and a second try finishes the merge', async () => {
		add({ id: 'g1', planId: 'paid', roles: [ 'user' ], logins: [ { type: 'firebase', id: 'f1' } ] });
		add({ id: PUID, planId: BASIC, roles: [ 'user' ], external: { type: 'steam', id: 's1' }, logins: [ { type: 'steam', id: 's1' } ] });
		const conflict = await service.link('c', users.get('g1'), proof('steam', 's1'));

		const save = repository.updateFromExternal;
		repository.updateFromExternal = async (correlationId, id, user) => {
			if (id === PUID)
				return { success: false, results: null, correlationId };
			return save(correlationId, id, user);
		};
		try {
			const failed = await service.linkConfirm('c', users.get('g1'), { ticket: conflict.results.ticket });
			assert.equal(failed.success, false);
		}
		finally {
			repository.updateFromExternal = save;
		}

		assert.deepEqual(users.get('g1').logins, [ { type: 'firebase', id: 'f1' } ], 'the other account still has its sign-in');
		assert.equal(users.get('g1').mergedInto, undefined);

		const again = await service.link('c', users.get('g1'), proof('steam', 's1'));
		const merged = await service.linkConfirm('c', users.get('g1'), { ticket: again.results.ticket });
		assert.equal(merged.results.token, `token:${PUID}`);
		assert.equal(users.get('g1').mergedInto, PUID);
	});

	it('mergeLinked saves the survivor before retiring the other', async () => {
		const order = [];
		const save = repository.updateFromExternal;
		repository.updateFromExternal = async (correlationId, id, user) => { order.push(id); return save(correlationId, id, user); };
		try {
			add({ id: 'g1', logins: [ { type: 'steam', id: 's1' } ] });
			const user = { id: PUID, logins: [] };
			add(user);
			await service.mergeLinked('c', user, { externalType: 'steam', externalId: 's1' }, true);
		}
		finally {
			repository.updateFromExternal = save;
		}
		assert.deepEqual(order, [ PUID, 'g1' ]);
	});
});

describe('AccountsService.currentUser', () => {
	it('follows a chain of merges to the end', async () => {
		add({ id: 'a', mergedInto: 'b' });
		add({ id: 'b', mergedInto: 'c' });
		add({ id: 'c', logins: [ { type: 'steam', id: 's1' } ] });
		assert.equal((await service.currentUser('c', users.get('a'))).results.id, 'c');
	});

	it('refuses a chain that loops', async () => {
		add({ id: 'a', mergedInto: 'b' });
		add({ id: 'b', mergedInto: 'a' });
		assert.equal((await service.currentUser('c', users.get('a'))).success, false);
	});

	it('refuses a chain that ends in a missing account', async () => {
		add({ id: 'a', mergedInto: 'gone' });
		assert.equal((await service.currentUser('c', users.get('a'))).success, false);
	});
});
