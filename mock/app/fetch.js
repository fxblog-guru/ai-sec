// PLANTED DEFECT — do not copy into real code.
// CWE-918 SSRF: a user-supplied URL is fetched server-side with no allowlist,
// and redirects are followed.
const https = require('https');

function fetchPreview(req, res) {
  const target = req.body.url;
  https.get(target, { followRedirects: true }, (upstream) => upstream.pipe(res));
}

module.exports = { fetchPreview };
