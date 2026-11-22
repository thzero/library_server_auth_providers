import jwt from 'jsonwebtoken';

import LibraryServerConstants from '@thzero/library_server/constants.js';

import LibraryCommonUtility from '@thzero/library_common/utility/index.js';

import Service from '@thzero/library_server/service/index.js';

import Constants from '../constants.js';

// The asymmetric algorithms tickets may be signed with, as login tokens.
const ALLOWED_ALGORITHMS = [ 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512' ];

// Accounts with several sign-ins (Google, Steam, Discord, ...), each one recorded in the user's
// logins ([ { type, id } ]). The auth server uses it to:
//  - sign in with a provider's identity (signInWith): the user that sign-in is linked to, or a new one;
//  - link another sign-in to the signed-in user (link), and when that sign-in already has its own
//    account, merge the two once the player confirms (linkConfirm, with a short-lived ticket: a
//    provider's answer can be single use, so it can't be sent twice);
//  - unlink one (unlink), never the last;
//  - fold an account linked to the same sign-in into another (mergeLinked), for a sign-in that
//    always lands on its own account, such as a game's EOS account.
// A merge keeps one account, the survivor, and retires the other: no sign-ins, mergedInto set.
// currentUser follows mergedInto, so a token issued before the merge still reaches the survivor.
//
// Needs the users repository (REPOSITORY_USERS) to have fetch(correlationId, id),
// updateFromExternal(correlationId, id, user) (saves the whole user, creating it when new) and
// fetchByLogin(correlationId, type, id, excludeId), which never answers a retired user: as
// @thzero/library_server_repository_mongo's BaseUserMongoRepository has them. And the provider
// services (SERVICE_AUTH_DISCORD, _FIREBASE, _STEAM) for the proofs it checks.
//
// The app's rules are hooks:
//  - _signIn: issues the app's login token for a user ({ token, user }), given the sign-in's
//    identity (its name, when the provider gave one, is the app's to use; nothing here stores it);
//  - _newUser: what a new user starts with;
//  - _isPrimary: an account that must survive a merge (a game's EOS account, for one);
//  - _canMerge: whether two accounts may merge (refuse with an error response);
//  - _conflictDetails: what the player is told about the other account before merging;
//  - _mergeInto: what the survivor takes from the retired account;
//  - _isLocked: a sign-in that can't be unlinked (by default, the user's external account).
class AccountsService extends Service {
	constructor() {
		super();

		this._repositoryUsers = null;
		this._serviceDiscord = null;
		this._serviceFirebase = null;
		this._serviceSteam = null;
	}

	async init(injector) {
		await super.init(injector);

		this._repositoryUsers = this._injector.getService(LibraryServerConstants.InjectorKeys.REPOSITORY_USERS);
		this._serviceDiscord = this._injector.getService(Constants.InjectorKeys.SERVICE_AUTH_DISCORD);
		this._serviceFirebase = this._injector.getService(Constants.InjectorKeys.SERVICE_AUTH_FIREBASE);
		this._serviceSteam = this._injector.getService(Constants.InjectorKeys.SERVICE_AUTH_STEAM);
	}

	// The signed-in [user]'s account, for the client: { id, logins: [ { type, id, locked } ], primary }.
	account(correlationId, user) {
		return this._successResponse(this._accountView(user), correlationId);
	}

	// The user [user] stands for now: the account it was merged into, if it was.
	async currentUser(correlationId, user) {
		const seen = new Set();
		while (user?.mergedInto) {
			if (seen.has(user.mergedInto) || (seen.size >= AccountsService.MergeHopsMax))
				return this._error('AccountsService', 'currentUser', 'The account merge chain does not end.', null, null, null, correlationId);
			seen.add(user.mergedInto);

			const response = await this._repositoryUsers.fetch(correlationId, user.mergedInto);
			if (this._hasFailed(response) || !response.results)
				return this._hasFailed(response) ? response : this._error('AccountsService', 'currentUser', 'The account it was merged into is missing.', null, null, null, correlationId);
			user = response.results;
		}
		return this._successResponse(user, correlationId);
	}

	static MergeHopsMax = 10;

	// Links another sign-in to the signed-in [user]. [request] is the sign-in's proof:
	// { type: 'steam', params }, { type: 'firebase', idToken } or { type: 'discord', code }.
	// Answers { status: 'linked', account }, or { status: 'conflict', ticket, ...details } when that
	// sign-in already has its own account; linkConfirm merges them with the ticket.
	async link(correlationId, user, request) {
		try {
			user = this._storedUser(user);
			const proofResponse = await this._verifyProof(correlationId, request);
			if (this._hasFailed(proofResponse))
				return proofResponse;
			const identity = proofResponse.results;

			const other = await this._repositoryUsers.fetchByLogin(correlationId, identity.externalType, identity.externalId, user.id);
			if (this._hasSucceeded(other) && other.results) {
				const ticket = this._signTicket('link', {
					userId: user.id,
					otherId: other.results.id,
					type: identity.externalType,
					id: identity.externalId,
					name: identity.name ?? null
				});
				const details = await this._conflictDetails(correlationId, other.results);
				return this._successResponse({ ...details, status: 'conflict', ticket }, correlationId);
			}

			user.logins = this._addLogin(user.logins, identity.externalType, identity.externalId);
			const updateResponse = await this._repositoryUsers.updateFromExternal(correlationId, user.id, user);
			if (this._hasFailed(updateResponse))
				return updateResponse;
			return this._successResponse({ status: 'linked', account: this._accountView(updateResponse.results) }, correlationId);
		}
		catch (err) {
			return this._error('AccountsService', 'link', null, err, null, null, correlationId);
		}
	}

	// Merges the account a link found (link's ticket: { ticket }) with the signed-in [user]. The
	// survivor is the primary account when one of the two is (_isPrimary), otherwise the signed-in
	// one; it takes the other's sign-ins and what _mergeInto gives it. Refused when both are primary,
	// or _canMerge refuses. Answers the survivor's sign-in (_signIn): the client signs in to it.
	async linkConfirm(correlationId, user, request) {
		try {
			user = this._storedUser(user);
			const payload = this._verifyTicket('link', request?.ticket);
			if (!payload || (payload.userId !== user.id))
				return this._error('AccountsService', 'linkConfirm', 'The link has expired; link the sign-in again.', null, null, null, correlationId);

			const otherResponse = await this._repositoryUsers.fetchByLogin(correlationId, payload.type, payload.id, user.id);
			if (!this._hasSucceeded(otherResponse) || !otherResponse.results || (otherResponse.results.id !== payload.otherId))
				return this._error('AccountsService', 'linkConfirm', 'That sign-in changed since; link it again.', null, null, null, correlationId);
			const other = this._storedUser(otherResponse.results);

			if (this._isPrimary(user) && this._isPrimary(other))
				return this._error('AccountsService', 'linkConfirm', 'Both accounts are primary accounts, and two can\'t be merged.', null, null, null, correlationId);
			const canMerge = await this._canMerge(correlationId, user, other);
			if (this._hasFailed(canMerge))
				return canMerge;

			const survivor = this._isPrimary(other) ? other : user;
			const retired = (survivor === other) ? user : other;
			this._mergeInto(survivor, retired, false);
			survivor.logins = this._addLogin(survivor.logins, payload.type, payload.id);

			const survivorResponse = await this._repositoryUsers.updateFromExternal(correlationId, survivor.id, survivor);
			if (this._hasFailed(survivorResponse))
				return survivorResponse;
			const response = await this._retire(correlationId, survivor, retired);
			if (this._hasFailed(response))
				return response;

			return await this._signIn(correlationId, survivorResponse.results, { externalType: payload.type, externalId: payload.id, name: payload.name ?? null });
		}
		catch (err) {
			return this._error('AccountsService', 'linkConfirm', null, err, null, null, correlationId);
		}
	}

	// Folds another account linked to the same sign-in ([identity]: { externalType, externalId })
	// into [user], which must keep it (a primary account on its own sign-in). [user] takes the
	// other's sign-ins, and when [created] (it's new), what _mergeInto gives a new account. Changes
	// [user] in place and saves it.
	async mergeLinked(correlationId, user, identity, created) {
		if (!identity?.externalType || !identity?.externalId)
			return this._success(correlationId);

		const linked = await this._repositoryUsers.fetchByLogin(correlationId, identity.externalType, identity.externalId, user.id);
		if (!this._hasSucceeded(linked) || !linked.results)
			return this._success(correlationId);
		const other = this._storedUser(linked.results);

		this._mergeInto(user, other, created);
		const userResponse = await this._repositoryUsers.updateFromExternal(correlationId, user.id, user);
		if (this._hasFailed(userResponse))
			return userResponse;
		return await this._retire(correlationId, user, other);
	}

	// Signs in with a provider's identity ({ externalType, externalId }): the user that sign-in is
	// linked to, or a new one (_newUser), with the sign-in recorded. Answers the sign-in (_signIn).
	async signInWith(correlationId, identity) {
		try {
			let user = null;
			const existing = await this._repositoryUsers.fetchByLogin(correlationId, identity.externalType, identity.externalId);
			if (this._hasSucceeded(existing) && existing.results)
				user = this._storedUser(existing.results);
			if (!user)
				user = await this._newUser(correlationId, identity);
			user.logins = this._addLogin(user.logins, identity.externalType, identity.externalId);

			const updateResponse = await this._repositoryUsers.updateFromExternal(correlationId, user.id, user);
			if (this._hasFailed(updateResponse))
				return updateResponse;
			return await this._signIn(correlationId, updateResponse.results, identity);
		}
		catch (err) {
			return this._error('AccountsService', 'signInWith', null, err, null, null, correlationId);
		}
	}

	// Removes a sign-in ({ type, id }) from the signed-in [user]. Never the last one, and never a
	// locked one (_isLocked).
	async unlink(correlationId, user, request) {
		try {
			user = this._storedUser(user);
			const type = request?.type;
			const id = request?.id;
			const logins = Array.isArray(user.logins) ? user.logins : [];
			const login = logins.find(item => (item.type === type) && (item.id === id));
			if (!login)
				return this._error('AccountsService', 'unlink', 'That sign-in isn\'t linked to this account.', null, null, null, correlationId);
			if (this._isLocked(user, login))
				return this._error('AccountsService', 'unlink', 'This sign-in belongs to the account itself, so it stays linked.', null, null, null, correlationId);
			if (logins.length <= 1)
				return this._error('AccountsService', 'unlink', 'This is the only sign-in for the account, so it stays linked.', null, null, null, correlationId);

			user.logins = logins.filter(item => item !== login);
			const updateResponse = await this._repositoryUsers.updateFromExternal(correlationId, user.id, user);
			if (this._hasFailed(updateResponse))
				return updateResponse;
			return this._successResponse({ account: this._accountView(updateResponse.results) }, correlationId);
		}
		catch (err) {
			return this._error('AccountsService', 'unlink', null, err, null, null, correlationId);
		}
	}

	// What the client sees of an account: its sign-ins (the external account included), which can't
	// be unlinked, and whether it's primary.
	_accountView(user) {
		const logins = [ ...(user.logins ?? []) ];
		if (user.external?.type && user.external?.id)
			this._addLogin(logins, user.external.type, user.external.id);
		return {
			id: user.id,
			logins: logins.map(login => ({ type: login.type, id: login.id, locked: this._isLocked(user, login) })),
			primary: this._isPrimary(user)
		};
	}

	// [logins] with { type, id } added, once.
	_addLogin(logins, type, id) {
		logins = Array.isArray(logins) ? logins : [];
		if (!type || !id)
			return logins;
		if (!logins.some(login => (login.type === type) && (login.id === id)))
			logins.push({ type, id });
		return logins;
	}

	// Whether [user] and [other] may merge: success, or an error saying why not.
	async _canMerge(correlationId, user, other) {
		return this._success(correlationId);
	}

	// What the player is told about the account a link found, before merging.
	async _conflictDetails(correlationId, other) {
		return {};
	}

	// Whether [user] is a primary account: one that survives a merge.
	_isPrimary(user) {
		return false;
	}

	// Whether [login] can't be unlinked from [user]: by default, the user's external account.
	_isLocked(user, login) {
		return (user.external?.type === login.type) && (user.external?.id === login.id);
	}

	// What [survivor] takes from [retired]: its sign-ins, its roles, its claims when the survivor
	// has none, and its plan when the survivor has none (or is [created], so has only the default).
	_mergeInto(survivor, retired, created) {
		for (const login of (retired.logins ?? []))
			survivor.logins = this._addLogin(survivor.logins, login.type, login.id);
		survivor.roles = [ ...new Set([ ...(survivor.roles ?? []), ...(retired.roles ?? []) ]) ];
		if ((created || !survivor.planId) && retired.planId)
			survivor.planId = retired.planId;
		if (!survivor.claims && retired.claims)
			survivor.claims = retired.claims;
		survivor.mergedIds = [ ...(survivor.mergedIds ?? []), retired.id ];
	}

	// A new user for a provider's [identity]: a new id, no plan, no roles.
	async _newUser(correlationId, identity) {
		return { id: LibraryCommonUtility.generateId(), roles: [] };
	}

	// Retires [retired] into [survivor]: no sign-ins, mergedInto set, so it is never found by a
	// sign-in again.
	async _retire(correlationId, survivor, retired) {
		retired.logins = [];
		retired.mergedInto = survivor.id;
		return await this._repositoryUsers.updateFromExternal(correlationId, retired.id, retired);
	}

	// The app's login token for [user]: { token, user }.
	async _signIn(correlationId, user, identity) {
		throw new Error('AccountsService._signIn: issue the app\'s login token.');
	}

	// [user] as the users collection stores it: a fetched user can carry its plan, which isn't
	// saved with the user.
	_storedUser(user) {
		const stored = { ...user };
		delete stored.plan;
		return stored;
	}

	// The keys tickets are signed with: the login token's (config auth.jwt).
	_ticketKeys() {
		const algorithm = this._config.get('auth.jwt.algorithm');
		if (!ALLOWED_ALGORITHMS.includes(algorithm))
			throw Error(`auth.jwt.algorithm must be one of ${ALLOWED_ALGORITHMS.join(', ')}.`);
		return {
			algorithm,
			privateKey: String(this._config.get('auth.jwt.privateKey') ?? '').replace(/\\n/g, '\n'),
			publicKey: String(this._config.get('auth.jwt.publicKey') ?? '').replace(/\\n/g, '\n')
		};
	}

	// A short-lived ticket ([typ], [claims]). It carries a typ, so it's never taken as a login: an
	// auth server's token check refuses any token with one.
	_signTicket(typ, claims) {
		const keys = this._ticketKeys();
		return jwt.sign({ ...claims, typ }, keys.privateKey, { algorithm: keys.algorithm, expiresIn: '10m' });
	}

	// Checks a sign-in proof with its provider: { type: 'steam', params }, { type: 'firebase',
	// idToken } or { type: 'discord', code }.
	async _verifyProof(correlationId, request) {
		if ((request?.type === Constants.LoginTypes.Discord) && this._serviceDiscord)
			return await this._serviceDiscord.verify(correlationId, request.code);
		if ((request?.type === Constants.LoginTypes.Firebase) && this._serviceFirebase)
			return await this._serviceFirebase.verify(correlationId, request.idToken);
		if ((request?.type === Constants.LoginTypes.Steam) && this._serviceSteam)
			return await this._serviceSteam.verify(correlationId, request.params);
		return this._error('AccountsService', '_verifyProof', 'Unknown sign-in type.', null, null, null, correlationId);
	}

	_verifyTicket(typ, ticket) {
		try {
			const keys = this._ticketKeys();
			const payload = jwt.verify(String(ticket ?? ''), keys.publicKey, { algorithms: [ keys.algorithm ] });
			return (payload?.typ === typ) ? payload : null;
		}
		catch {
			return null;
		}
	}
}

export default AccountsService;
