const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {rootCertificates} = require('node:tls');
const {test} = require('node:test');

const helper = fs.readFileSync(path.resolve(__dirname, '../../tools/saiai-cli/src/vscode_certificates.js'), 'utf8');

function fixture(context, options = {}) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'saiai-vscode-certificates-'));
    context.after(() => fs.rmSync(directory, {recursive: true, force: true}));
    const app = path.join(directory, 'app');
    fs.mkdirSync(app);
    const ca = path.join(directory, 'public-ca.crt');
    fs.writeFileSync(ca, options.invalidCa ? 'TEST_ONLY_INVALID_CERTIFICATE' : rootCertificates[0]);
    const certificates = path.join(directory, 'public-certificates.json');
    fs.writeFileSync(certificates, JSON.stringify(options.certificates ?? [rootCertificates[0]]));
    if (!options.missingAgent) {
        const modules = path.join(app, options.asar ? 'node_modules.asar' : 'node_modules');
        const agent = path.join(modules, '@vscode', 'proxy-agent');
        const dependency = path.join(modules, 'saiai-test-public-certificates');
        fs.mkdirSync(agent, {recursive: true});
        fs.mkdirSync(dependency, {recursive: true});
        fs.writeFileSync(path.join(dependency, 'index.js'), "module.exports = require('node:fs').readFileSync(process.env.TEST_ONLY_CERTIFICATES_FILE, 'utf8');\n");
        fs.writeFileSync(path.join(agent, 'index.js'), `
            const certificates = JSON.parse(require('saiai-test-public-certificates'));
            exports.loadSystemCertificates = async options => {
                if (options.loadSystemCertificatesFromNode() !== false || !['trace','debug','info','warn','error'].every(key => typeof options.log[key] === 'function')) throw new Error('TEST_ONLY_LOADER_CONTRACT');
                if (${Boolean(options.loaderFails)}) throw new Error('TEST_ONLY_LOADER_FAILURE');
                return certificates;
            };
        `);
    }
    if (options.brokenFirstAgent) {
        const broken = path.join(app, 'node_modules', '@vscode', 'proxy-agent');
        fs.mkdirSync(broken, {recursive: true});
        fs.writeFileSync(path.join(broken, 'index.js'), "throw new Error('TEST_ONLY_UNAVAILABLE_MODULE');\n");
    }
    if (options.missingCa) fs.unlinkSync(ca);
    const environment = {...process.env, TEST_ONLY_CERTIFICATES_FILE: certificates};
    delete environment.NODE_OPTIONS;
    delete environment.NODE_PATH;
    const networkGuard = "globalThis.fetch = () => { throw new Error('TEST_ONLY_NETWORK_FORBIDDEN'); }; for (const name of ['node:http','node:https','node:net','node:tls']) { const network = require(name); for (const method of ['request','get','connect','createConnection']) if (typeof network[method] === 'function') network[method] = () => { throw new Error('TEST_ONLY_NETWORK_FORBIDDEN'); }; }\n";
    const result = spawnSync(process.execPath, ['-', ca, app], {input: networkGuard + helper, encoding: 'utf8', env: environment, timeout: 5000});
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    assert.equal(result.stderr, '');
    return {status: result.status, result: JSON.parse(result.stdout)};
}

test('recognizes the current public CA with the traditional loader', context => {
    assert.deepEqual(fixture(context), {status: 0, result: {trusted: true}});
});

test('an unrelated trusted CA does not establish current CA trust', context => {
    assert.deepEqual(fixture(context, {certificates: [rootCertificates[1]]}), {status: 0, result: {trusted: false}});
});

test('ignores malformed certificates but still requires the current CA', context => {
    assert.deepEqual(fixture(context, {certificates: ['TEST_ONLY_INVALID_CERTIFICATE', rootCertificates[0]]}), {status: 0, result: {trusted: true}});
});

test('resolves the asar module layout and its sibling dependency', context => {
    assert.deepEqual(fixture(context, {asar: true}), {status: 0, result: {trusted: true}});
});

test('falls back to the asar loader when the ordinary module cannot load', context => {
    assert.deepEqual(fixture(context, {asar: true, brokenFirstAgent: true}), {status: 0, result: {trusted: true}});
});

for (const [name, options] of [
    ['missing loader', {missingAgent: true}],
    ['failed loader', {loaderFails: true}],
    ['invalid current CA', {invalidCa: true}],
    ['missing current CA', {missingCa: true}],
]) {
    test(`${name} is unknown trust, never success`, context => {
        assert.deepEqual(fixture(context, options), {status: 1, result: {trusted: null}});
    });
}
