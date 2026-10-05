const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = process.argv[3];
const modulePaths = ['node_modules', 'node_modules.asar'].map(name => path.join(root, name));
process.env.NODE_PATH = modulePaths.join(path.delimiter);
require('node:module').Module._initPaths();
const log = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

(async () => {
    let agent;
    for (const directory of modulePaths) {
        try {
            agent = require(path.join(directory, '@vscode/proxy-agent'));
            break;
        } catch {}
    }
    if (!agent) {
        throw new Error('certificate loader unavailable');
    }
    const ca = new crypto.X509Certificate(fs.readFileSync(process.argv[2]));
    const certificates = await agent.loadSystemCertificates({ loadSystemCertificatesFromNode: () => false, log });
    const trusted = certificates.some(pem => {
        try {
            return new crypto.X509Certificate(pem).fingerprint256 === ca.fingerprint256;
        } catch {
            return false;
        }
    });
    process.stdout.write(JSON.stringify({ trusted }));
    process.exit(0);
})().catch(() => {
    process.stdout.write(JSON.stringify({ trusted: null }));
    process.exit(1);
});
