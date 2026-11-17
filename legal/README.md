# Legal register
`legal/manifest.json` is QA SIEM's own-product compliance register.
Build the web copy and validate:
```bash
make legal
../QA-License-Scanner/bin/qa-license-scanner validate legal/manifest.json
```
Schema and specification live in the QA License Scanner project.
