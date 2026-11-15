![GitHub package.json version](https://img.shields.io/github/package-json/v/thzero/library_server_auth_providers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# library_server_auth_providers

Sign-in through outside providers for [@thzero/library_server](https://github.com/thzero/library_server) auth servers, and accounts with several of them linked.

- **Proof checks.** Each provider service takes the proof a client got from a sign-in provider, checks it with that provider, and answers who signed in.
- **Accounts** (`accounts/index.js`, `AccountsService`). Signs in with a provider's identity (the user that sign-in is linked to, or a new one), links another sign-in to the signed-in user, merges two accounts once the player confirms, and unlinks. The auth server keeps its own token: the app's rules are hooks.
- **Renewals** (`renewals/index.js`, `RenewalsService`). Renewal keys, so a browser stays signed in past its short-lived login token.

| Service | Proof | Answers |
| --- | --- | --- |
| `discord/index.js` (`DiscordOAuthService`) | the OAuth2 authorization code Discord returned to the client | `{ externalType: 'discord', externalId, name }` |
| `eos/index.js` (`EosIdTokenService`) | an EOS Connect ID token | `{ puid, externalType, externalId, platform }` |
| `firebase/index.js` (`FirebaseIdTokenService`) | a Firebase Auth ID token (Google and the other Firebase providers) | `{ externalType: 'firebase', externalId, provider }` |
| `steam/index.js` (`SteamOpenIdService`) | the `openid.*` fields Steam's OpenID 2.0 sign-in returned to the client | `{ externalType: 'steam', externalId }` (the SteamID64) |

Every service has one method, `verify(correlationId, proof)`, and answers a library response: `success` with `results`, or an error with a message saying why the proof was refused.

## Accounts

A user records its sign-ins in `logins` (`[ { type, id } ]`); a user whose identity is an external account (a game's EOS account) also matches on `external` (`{ type, id }`).

| Method | What it does |
| --- | --- |
| `signInWith(correlationId, identity)` | The user a provider's identity is linked to, or a new one (`_newUser`), with the sign-in recorded; answers the app's sign-in (`_signIn`). |
| `account(correlationId, user)` | `{ id, logins: [ { type, id, locked } ], primary }` for the client. |
| `link(correlationId, user, proof)` | Checks the proof with its provider and links it: `{ status: 'linked', account }`, or `{ status: 'conflict', ticket, ...details }` when that sign-in has its own account. |
| `linkConfirm(correlationId, user, { ticket })` | Merges the two: the primary account survives (`_isPrimary`), otherwise the signed-in one. The other is retired (no sign-ins, `mergedInto` set). Answers the survivor's sign-in. |
| `unlink(correlationId, user, { type, id })` | Never the last sign-in, nor a locked one (`_isLocked`: by default the user's external account). |
| `mergeLinked(correlationId, user, identity, created)` | Folds an account linked to the same sign-in into `user`, for a sign-in that always lands on its own account. |
| `currentUser(correlationId, user)` | Follows `mergedInto`, so a token issued before a merge still reaches the survivor. |

Merge tickets are short-lived JWTs signed with the login token's keys (config `auth.jwt`), with a `typ`, so a token check that refuses typed tokens never takes one as a login. A provider's answer can be single use (Steam's is), so the merge uses the ticket instead of the answer.

The app subclasses `AccountsService` for its rules:

| Hook | Default |
| --- | --- |
| `_signIn(correlationId, user, identity)` | none: issue the app's login token, `{ token, user }`. `identity` is the sign-in (`{ externalType, externalId, name }`); its `name` is the provider's name for the player when it gives one (Discord, Firebase), for the app to put in its token. Nothing here stores it. |
| `_newUser(correlationId, identity)` | a new id, no plan, no roles |
| `_isPrimary(user)` | `false` |
| `_canMerge(correlationId, user, other)` | allowed (two primary accounts are always refused) |
| `_conflictDetails(correlationId, other)` | `{}` |
| `_mergeInto(survivor, retired, created)` | the retired account's sign-ins and roles; its claims and plan when the survivor has none |
| `_isLocked(user, login)` | the user's external account |

The users repository (`REPOSITORY_USERS`) needs `fetch(correlationId, id)`, `updateFromExternal(correlationId, id, user)` (saves the whole user, creating it when new), and `fetchByLogin(correlationId, type, id, excludeId)`, which must never answer a retired user. [@thzero/library_server_repository_mongo](https://github.com/thzero/library_server_repository_mongo)'s `BaseUserMongoRepository` has all three. The provider services are found by the injector keys in `constants.js`.

The pairing client library is [@thzero/library_client_auth_providers](https://github.com/thzero/library_client_auth_providers), which gets these proofs in the browser.

## Renewals

A browser sign-in gets a renewal key beside its login token. Before the token expires, or on a later visit after it has, the browser trades the key for a new token and a new key; signing out deletes it. Each key works once: a renewal replaces it, so a copied key stops working as soon as either copy is used. A key unused for `auth.renewal.days` (30 by default) expires.

| Method | What it does |
| --- | --- |
| `issue(correlationId, user)` | A new key: `{ renewal, renewalExpiresAt }`. |
| `renew(correlationId, renewal)` | `{ user, renewal, renewalExpiresAt }`, the user followed through `mergedInto`; the old key stops working. Refuses a key that's unknown, used, expired or forged. |
| `revoke(correlationId, renewal)` | Deletes the key. Succeeds whether or not it was known. |

A key is `<id>.<secret>`; only a SHA-256 hash of the secret is stored. The app issues the login token itself: it adds `issue`'s answer to a browser sign-in (in its `_signIn`), and answers `renew` with a new token for the user. A game client that signs in again on every start doesn't need a key.

The renewals repository (`REPOSITORY_AUTH_RENEWALS`) needs `create(correlationId, { id, userId, hash, expiresAt })`, `fetch(correlationId, id)` and `delete(correlationId, id)`, which answers whether it deleted (so two renewals with one key can't both succeed). Give `expiresAt` a TTL index so the store drops expired keys itself. It also uses the users repository and the accounts service.

## Requirements

### NodeJs

[NodeJs](https://nodejs.org) version 22+

### Installation

[![NPM](https://nodei.co/npm/@thzero/library_server_auth_providers.png?compact=true)](https://npmjs.org/package/@thzero/library_server_auth_providers)

## Usage

Inject the services the server needs, and call them from its auth service:

```js
import steamOpenIdService from '@thzero/library_server_auth_providers/steam/index.js';

this._injectService(Constants.InjectorKeys.SERVICE_AUTH_STEAM, new steamOpenIdService());

const response = await this._serviceSteam.verify(correlationId, request.params);
if (this._hasFailed(response))
	return response;
const { externalType, externalId } = response.results;
```

## Configuration

Each service reads its own section of the server's config.

### Discord

```json
"discord": {
	"clientId": "<application id>",
	"clientSecret": "<client secret>",
	"redirectUrl": "https://example.com/auth/discord"
}
```

`redirectUrl` must be the client page Discord returns to, exactly as registered under the application's OAuth2 redirects. The code is exchanged with the client secret, which never leaves the server, and must have been granted the `identify` scope.

### EOS

```json
"eos": {
	"clientId": "<EOS client id>",
	"deploymentId": "<optional: only tokens for this deployment>",
	"issuerPrefix": "https://api.epicgames.dev",
	"jwksUrl": "https://api.epicgames.dev/auth/v1/oauth/jwks"
}
```

### Firebase

```json
"firebase": {
	"projectId": "<Firebase project id>"
}
```

The token is checked against Google's published certificates, the way Firebase documents for checking ID tokens without its admin SDK: RS256, the project as audience and issuer, expiry, and the times it was issued and signed in. No service account is needed.

### Steam

```json
"steam": {
	"returnUrl": "https://example.com/auth/steam"
}
```

`returnUrl` must be the client page Steam returns to, the `openid.return_to` the client sent. The answer is checked field by field, then with Steam itself (`check_authentication`). Answers older than five minutes, or already used, are refused; used answers are remembered in memory, so the replay check covers one server instance.

## Tests

```
npm test
```

The tests stand in for the providers' endpoints, so they run offline.

## License

[MIT](license.md)
