# Dirty fixture: audit-logging rules should trigger here
# Financial functions that are missing audit log calls

import logging

logger = logging.getLogger(__name__)


# Should trigger: missing-audit-log-transfer (pattern or AST rule)
def transfer_funds(from_account, to_account, amount):
    # No audit_log call — violation
    from_account.balance -= amount
    to_account.balance += amount
    db.session.commit()
    return {"status": "success"}


# Should trigger: missing-audit-log-disburse
def disburse_loan(loan_id, account, amount):
    # No audit_log call — violation
    account.balance += amount
    loan.status = "disbursed"
    db.session.commit()


# Should trigger: missing-audit-log-debit
def debit_account(account, amount, reason):
    # No audit_log call — violation
    account.balance -= amount
    db.session.commit()


# Should trigger: missing-audit-log-credit
def credit_account(account, amount, source):
    # No audit_log call — violation
    account.balance += amount
    db.session.commit()


# Should trigger: no-print-in-financial (print instead of proper logging)
def repay_loan(loan, payment):
    print(f"Processing repayment of {payment.amount} for loan {loan.id}")
    loan.outstanding -= payment.amount
    db.session.commit()


# Should trigger: no-bare-except-financial
def process_settlement(settlement):
    try:
        settlement.execute()
    except:
        pass  # silently swallowing errors in financial operations
