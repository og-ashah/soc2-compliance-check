const dbPassword = "hunter2hunter2";
const partnerUrl = "http://api.partner-example.com/v2/orders";

async function loadOrders() {
  // Certificate checks disabled to "make it work"
  const agent = { rejectUnauthorized: false };
  return fetch(partnerUrl, { agent });
}

module.exports = { dbPassword, loadOrders };
