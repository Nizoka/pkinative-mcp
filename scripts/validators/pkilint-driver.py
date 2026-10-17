"""pkinative-mcp — the pkilint driver of tests/interop/lint.test.ts.

  python pkilint-driver.py <manifest.json>

Runs DigiCert's pkilint over every certificate the manifest lists:
`lint_pkix_cert` on each, and `lint_pkix_signer_signee_cert_chain` on each
certificate that names an issuer. The linters are called through their own
command-line entry points — the `main()` that `python -m pkilint.bin.…` runs,
with the same arguments — in one process, because importing pkilint costs
seconds. Prints one JSON line per lint with every finding at NOTICE or above;
the test decides: any ERROR or FATAL fails, every WARNING and NOTICE must be
reviewed in scripts/data/lint-waivers.json. Ported from pkinative's driver.
"""

import contextlib
import io
import json
import sys
from importlib.metadata import version

from pkilint.bin import lint_pkix_cert, lint_pkix_signer_signee_cert_chain


def run(main, args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = main(['lint', '-s', 'NOTICE', '-f', 'JSON', *args])
    text = out.getvalue().strip()
    findings = []
    for result in json.loads(text)['results'] if text else []:
        for f in result['finding_descriptions']:
            findings.append({'lint': f['code'], 'severity': f['severity'], 'at': result['node_path']})
    return status, findings


def main(manifest_path):
    with open(manifest_path, encoding='utf-8') as f:
        artefacts = json.load(f)['artefacts']
    by_id = {a['id']: a for a in artefacts}
    lines = [{'t': 'header', 'tool': 'pkilint', 'version': version('pkilint')}]
    for a in artefacts:
        status, findings = run(lint_pkix_cert.main, [a['pem']])
        lines.append({'id': a['id'], 'check': 'lint.cert', 'findings': findings, 'status': status})
        if a.get('issuer'):
            status, findings = run(lint_pkix_signer_signee_cert_chain.main, [by_id[a['issuer']]['pem'], a['pem']])
            lines.append({'id': a['id'], 'check': 'lint.chain', 'findings': findings, 'status': status})
    sys.stdout.write('\n'.join(json.dumps(line) for line in lines) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: pkilint-driver.py <manifest.json>')
    main(sys.argv[1])
