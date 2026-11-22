async function findUser(db, id) {
  // Parameterized query: user input is never concatenated into SQL.
  return db.query('SELECT id, email FROM users WHERE id = $1', [id]);
}

module.exports = { findUser };
