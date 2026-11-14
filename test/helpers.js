import '@thzero/library_common/utility/string.js';

// A service with a config and a quiet logger, as the injector would set it up.
export function setup(Service, config) {
	const service = new Service();
	service._config = { get: (key) => config[key] ?? null };
	service._logger = { debug() {}, error() {}, exception() {}, warn() {} };
	return service;
}
