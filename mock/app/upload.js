// PLANTED DEFECT — do not copy into real code.
// CWE-22 path traversal: the filename is joined to a base directory with no
// normalization check, so ../../ escapes it.
const fs = require('fs');
const path = require('path');

const BASE = '/var/app/uploads';

function download(req, res) {
  const file = path.join(BASE, req.query.name);
  return res.send(fs.readFileSync(file));
}

module.exports = { download };
