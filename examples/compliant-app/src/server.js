const https = require('https');
const pino = require('pino');

const log = pino({ level: process.env.LOG_LEVEL || 'info' });
const apiKey = process.env.API_KEY; // secrets come from the environment, never from source

function fetchOrders() {
  // TLS certificate verification stays on (the default).
  return fetch('https://api.example.com/v1/orders', {
    headers: { Authorization: `Bearer ${apiKey}` },
  }).then((r) => r.json());
}

fetchOrders()
  .then((orders) => log.info({ count: orders.length }, 'orders loaded'))
  .catch((err) => log.error({ err: err.message }, 'failed to load orders'));

module.exports = { fetchOrders, https };
