function evaluateExpression(req) {
  return eval(req.body.expr);
}

module.exports = { evaluateExpression };
