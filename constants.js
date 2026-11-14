const Constants = {
	InjectorKeys: {
		SERVICE_AUTH_ACCOUNTS: 'serviceAuthAccounts',
		SERVICE_AUTH_DISCORD: 'serviceAuthDiscord',
		SERVICE_AUTH_EOS: 'serviceAuthEos',
		SERVICE_AUTH_FIREBASE: 'serviceAuthFirebase',
		SERVICE_AUTH_STEAM: 'serviceAuthSteam'
	},
	// The sign-in types the providers answer (externalType), and that accounts record (logins).
	LoginTypes: {
		Discord: 'discord',
		Firebase: 'firebase',
		Steam: 'steam'
	}
};

export default Constants;
