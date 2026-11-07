// PLANTED DEFECTS — do not copy into real code.
// 1. CWE-89 SQL injection: the order id is concatenated into the query.
// 2. CWE-639 missing tenant predicate: findOrder ignores the caller's tenant.
const db = require('./client');

async function getOrder(req) {
  const orderId = req.body.orderId;
  return db.raw(`SELECT * FROM orders WHERE id = ${orderId}`);
}

// Every other repository method goes through scoped(); this one does not.
async function findOrder(id) {
  return db.query('SELECT * FROM orders WHERE id = ?', [id]);
}

async function listOrders(tenantId) {
  return db.scoped(tenantId).query('SELECT * FROM orders');
}

module.exports = { getOrder, findOrder, listOrders };
