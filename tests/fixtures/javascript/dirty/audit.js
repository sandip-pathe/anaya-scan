// Dirty fixture: audit-logging rules should trigger here
// Financial functions missing audit log calls

// Should trigger: missing-audit-log-transfer
function transferFunds(fromAccount, toAccount, amount) {
  // No audit log call — violation
  fromAccount.balance -= amount;
  toAccount.balance += amount;
  db.save();
  return { status: "success" };
}

// Should trigger: missing-audit-log-disburse
function disburseLoan(loanId, account, amount) {
  // No audit log call — violation
  account.balance += amount;
  db.save();
}

// Should trigger: missing-audit-log-debit
function debitAccount(account, amount, reason) {
  // No audit log call — violation
  account.balance -= amount;
  db.save();
}

// Should trigger: missing-audit-log-credit
function creditAccount(account, amount, source) {
  // No audit log call — violation
  account.balance += amount;
  db.save();
}

// Should trigger: no-print-in-financial (console.log instead of proper logging)
function repayLoan(loan, payment) {
  console.log(`Processing repayment of ${payment.amount}`);
  loan.outstanding -= payment.amount;
  db.save();
}

// Should trigger: no-bare-catch-financial
function processSettlement(settlement) {
  try {
    settlement.execute();
  } catch (e) {
    // silently swallowing errors in financial code
  }
}
