// Clean fixture: audit-logging rules should NOT trigger here

const logger = require("./logger");

function auditLog(action, actor, details) {
  logger.info("AUDIT", { action, actor, details });
}

function transferFunds(fromAccount, toAccount, amount, actor) {
  auditLog("transfer", actor, {
    from: fromAccount.id,
    to: toAccount.id,
    amount,
  });
  fromAccount.balance -= amount;
  toAccount.balance += amount;
  db.save();
  return { status: "success" };
}

function disburseLoan(loanId, account, amount, actor) {
  auditLog("disburse", actor, { loanId, amount });
  account.balance += amount;
  db.save();
}

function debitAccount(account, amount, reason, actor) {
  auditLog("debit", actor, { account: account.id, amount, reason });
  account.balance -= amount;
  db.save();
}

function creditAccount(account, amount, source, actor) {
  auditLog("credit", actor, { account: account.id, amount, source });
  account.balance += amount;
  db.save();
}

function repayLoan(loan, payment, actor) {
  auditLog("repay", actor, { loanId: loan.id, amount: payment.amount });
  logger.info(`Processing repayment for loan ${loan.id}`);
  loan.outstanding -= payment.amount;
  db.save();
}

function processSettlement(settlement, actor) {
  try {
    auditLog("settlement", actor, { id: settlement.id });
    settlement.execute();
  } catch (e) {
    logger.error(`Settlement failed: ${e.message}`);
    throw e;
  }
}

module.exports = { transferFunds, disburseLoan, debitAccount, creditAccount };
