import { Buffer } from 'node:buffer';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import LibraryServerConstants from '@thzero/library_server/constants.js';

import Service from '@thzero/library_server/service/index.js';

import Constants from '../constants.js';

const DEFAULT_DAYS = 30;
// A renewal key: '<id>.<secret>', both hex.
const KEY = /^([0-9a-f]{32})\.([0-9a-f]{64})$/;

// Renewal keys, so a browser stays signed in past its short-lived login token. A browser sign-in
// gets one beside its token (issue); before the token expires, or on a later visit after it has,
// the browser trades the key for a new token and a new key (renew); signing out deletes it
// (revoke). A key works once: each renewal replaces it, so a copied key stops working as soon as
// either copy is used. A key unused for auth.renewal.days (30 by default) expires.
// Only a hash of the key's secret is stored.
//
// Needs the renewals repository (REPOSITORY_AUTH_RENEWALS) to have create(correlationId,
// { id, userId, hash, expiresAt }), fetch(correlationId, id) and delete(correlationId, id), which
// answers whether it deleted; the users repository (REPOSITORY_USERS); and the accounts service
// (SERVICE_AUTH_ACCOUNTS) for the user a key belongs to now (an account merged since is followed to
// the one it was merged into).
class RenewalsService extends Service {
	constructor() {
		super();

		this._repositoryRenewals = null;
		this._repositoryUsers = null;
		this._serviceAccounts = null;
	}

	async init(injector) {
		await super.init(injector);

		this._repositoryRenewals = this._injector.getService(Constants.InjectorKeys.REPOSITORY_AUTH_RENEWALS);
		this._repositoryUsers = this._injector.getService(LibraryServerConstants.InjectorKeys.REPOSITORY_USERS);
		this._serviceAccounts = this._injector.getService(Constants.InjectorKeys.SERVICE_AUTH_ACCOUNTS);
	}

	// A new renewal key for [user]: { renewal, renewalExpiresAt }.
	async issue(correlationId, user) {
		try {
			if (!user?.id)
				return this._error('RenewalsService', 'issue', 'No user to issue a renewal key for.', null, null, null, correlationId);

			const id = randomBytes(16).toString('hex');
			const secret = randomBytes(32).toString('hex');
			const expiresAt = new Date(Date.now() + (this._days() * 24 * 60 * 60 * 1000));
			const createResponse = await this._repositoryRenewals.create(correlationId, { id, userId: user.id, hash: this._hash(secret), expiresAt });
			if (this._hasFailed(createResponse))
				return createResponse;

			return this._successResponse({ renewal: `${id}.${secret}`, renewalExpiresAt: expiresAt.getTime() }, correlationId);
		}
		catch (err) {
			return this._error('RenewalsService', 'issue', null, err, null, null, correlationId);
		}
	}

	// Trades [renewal] for the user it belongs to and a new key: { user, renewal, renewalExpiresAt }.
	// The old key stops working. Refuses a key that's unknown, used, expired or forged.
	async renew(correlationId, renewal) {
		try {
			const parsed = KEY.exec(String(renewal ?? ''));
			if (!parsed)
				return this._refused(correlationId);
			const [ , id, secret ] = parsed;

			const fetchResponse = await this._repositoryRenewals.fetch(correlationId, id);
			const record = this._hasSucceeded(fetchResponse) ? fetchResponse.results : null;
			if (!record || !this._matches(secret, record.hash))
				return this._refused(correlationId);
			if (new Date(record.expiresAt).getTime() <= Date.now()) {
				await this._repositoryRenewals.delete(correlationId, id);
				return this._refused(correlationId);
			}

			// Whoever deletes it uses it: two renewals with the same key can't both succeed.
			const deleteResponse = await this._repositoryRenewals.delete(correlationId, id);
			if (this._hasFailed(deleteResponse) || !deleteResponse.results)
				return this._refused(correlationId);

			const userResponse = await this._user(correlationId, record.userId);
			if (this._hasFailed(userResponse) || !userResponse.results)
				return this._refused(correlationId);
			const user = userResponse.results;

			const issueResponse = await this.issue(correlationId, user);
			if (this._hasFailed(issueResponse))
				return issueResponse;

			return this._successResponse({ user, ...issueResponse.results }, correlationId);
		}
		catch (err) {
			return this._error('RenewalsService', 'renew', null, err, null, null, correlationId);
		}
	}

	// Deletes [renewal], on sign-out. Succeeds whether or not the key was known, so the answer
	// says nothing about it.
	async revoke(correlationId, renewal) {
		try {
			const parsed = KEY.exec(String(renewal ?? ''));
			if (parsed) {
				const [ , id, secret ] = parsed;
				const fetchResponse = await this._repositoryRenewals.fetch(correlationId, id);
				const record = this._hasSucceeded(fetchResponse) ? fetchResponse.results : null;
				if (record && this._matches(secret, record.hash))
					await this._repositoryRenewals.delete(correlationId, id);
			}
			return this._success(correlationId);
		}
		catch (err) {
			return this._error('RenewalsService', 'revoke', null, err, null, null, correlationId);
		}
	}

	_days() {
		const days = Number(this._config.get('auth.renewal.days') ?? DEFAULT_DAYS);
		return (Number.isFinite(days) && (days > 0)) ? days : DEFAULT_DAYS;
	}

	_hash(secret) {
		return createHash('sha256').update(secret).digest('hex');
	}

	_matches(secret, hash) {
		const actual = Buffer.from(this._hash(secret), 'hex');
		const expected = Buffer.from(String(hash ?? ''), 'hex');
		return (actual.length === expected.length) && timingSafeEqual(actual, expected);
	}

	_refused(correlationId) {
		return this._error('RenewalsService', 'renew', 'The renewal key is not valid; sign in again.', null, null, null, correlationId);
	}

	// The user [userId] is now: the account it was merged into, if it was.
	async _user(correlationId, userId) {
		const userResponse = await this._repositoryUsers.fetch(correlationId, userId);
		if (this._hasFailed(userResponse) || !userResponse.results)
			return userResponse;
		return await this._serviceAccounts.currentUser(correlationId, userResponse.results);
	}
}

export default RenewalsService;
