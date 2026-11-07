// PLANTED DEFECTS — do not copy into real code.
// 1. CWE-862 the admin delete route is registered BEFORE requireAdmin runs.
// 2. CWE-601 open redirect: the target comes straight from a query parameter.
const router = require('express').Router();
const { requireAdmin } = require('./auth');
const { deleteUser } = require('./admin');

router.delete('/admin/users/:userId', deleteUser);

router.use(requireAdmin);
router.post('/admin/settings', (req, res) => res.json({ ok: true }));

router.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

module.exports = router;
