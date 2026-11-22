function findUser(db, id) {
  return db.query("SELECT id, email FROM users WHERE id = " + id);
}

module.exports = { findUser };
