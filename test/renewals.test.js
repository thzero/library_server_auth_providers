import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';

import RenewalsService from '../renewals/index.js';
import { setup } from './helpers.js';

let service;
let records;
let users;

const ok = (results) => ({ success: true, results });

beforeEach(() => {
	service = setup(RenewalsService, {});
	records = new Map();
	users = new Map([
		[ 'u1', { id: 'u1' } ],
		[ 'retired', { id: 'retired', mergedInto: 'u1' } ]
	]);
	// Stand in for the renewals repository, the users repository and the accounts service.
	service._repositoryRenewals = {
		create: async (correlationId, record) => { records.set(record.id, { ...record }); return ok(record); },
		fetch: async (correlationId, id) => ok(records.get(id) ?? null),
		delete: async (correlationId, id) => ok(records.delete(id))
	};
	service._repositoryUsers = { fetch: async (correlationId, id) => ok(users.get(id) ?? null) };
	service._serviceAccounts = {
		currentUser: async (correlationId, user) => ok(user.mergedInto ? users.get(user.mergedInto) : user)
	};
});

const issue = async (user = users.get('u1')) => (await service.issue('c', user)).results.renewal;

describe('RenewalsService', () => {
	it('issues a key that lasts 30 days, storing only a hash of its secret', async () => {
		const response = await service.issue('c', users.get('u1'));
		assert.equal(response.success, true);
		assert.match(response.results.renewal, /^[0-9a-f]{32}\.[0-9a-f]{64}$/);
		const days = (response.results.renewalExpiresAt - Date.now()) / (24 * 60 * 60 * 1000);
		assert.ok((days > 29.9) && (days <= 30));

		const [ id, secret ] = response.results.renewal.split('.');
		const record = records.get(id);
		assert.equal(record.userId, 'u1');
		assert.notEqual(record.hash, secret);
		assert.equal(JSON.stringify(record).includes(secret), false);
	});

	it('trades a key for its user and a new key, once', async () => {
		const renewal = await issue();

		const response = await service.renew('c', renewal);
		assert.equal(response.success, true);
		assert.deepEqual(response.results.user, { id: 'u1' });
		assert.notEqual(response.results.renewal, renewal);

		assert.equal((await service.renew('c', renewal)).success, false);
		assert.equal((await service.renew('c', response.results.renewal)).success, true);
	});

	it('lets only one of two renewals with the same key through', async () => {
		const renewal = await issue();
		const answers = await Promise.all([ service.renew('c', renewal), service.renew('c', renewal) ]);
		assert.equal(answers.filter(answer => answer.success).length, 1);
	});

	it('refuses a forged, malformed or expired key', async () => {
		const renewal = await issue();
		const [ id ] = renewal.split('.');
		assert.equal((await service.renew('c', `${id}.${'0'.repeat(64)}`)).success, false);
		assert.equal((await service.renew('c', 'garbage')).success, false);
		assert.equal((await service.renew('c', null)).success, false);

		records.get(id).expiresAt = new Date(Date.now() - 1000);
		assert.equal((await service.renew('c', renewal)).success, false);
		assert.equal(records.has(id), false);
	});

	it('follows an account merged since the key was issued', async () => {
		const renewal = await issue(users.get('retired'));
		assert.deepEqual((await service.renew('c', renewal)).results.user, { id: 'u1' });
	});

	it('refuses a key whose user is gone', async () => {
		const renewal = await issue();
		users.delete('u1');
		assert.equal((await service.renew('c', renewal)).success, false);
	});

	it('revokes a key on sign-out, and answers the same for an unknown one', async () => {
		const renewal = await issue();
		assert.equal((await service.revoke('c', renewal)).success, true);
		assert.equal((await service.renew('c', renewal)).success, false);
		assert.equal((await service.revoke('c', renewal)).success, true);
		assert.equal((await service.revoke('c', 'garbage')).success, true);
	});

	it('does not revoke with only the id of someone else\'s key', async () => {
		const renewal = await issue();
		const [ id ] = renewal.split('.');
		await service.revoke('c', `${id}.${'f'.repeat(64)}`);
		assert.equal((await service.renew('c', renewal)).success, true);
	});

	it('keeps a key for auth.renewal.days', async () => {
		service = Object.assign(setup(RenewalsService, { 'auth.renewal.days': 7 }), { _repositoryRenewals: service._repositoryRenewals });
		const response = await service.issue('c', users.get('u1'));
		const days = (response.results.renewalExpiresAt - Date.now()) / (24 * 60 * 60 * 1000);
		assert.ok((days > 6.9) && (days <= 7));
	});
});
