# Clean fixture: audit-logging rules should NOT trigger here

import logging

logger = logging.getLogger(__name__)


def audit_log(action, actor, details):
    """Proper audit logging function."""
    logger.info("AUDIT: action=%s actor=%s details=%s", action, actor, details)


def transfer_funds(from_account, to_account, amount, actor):
    """Transfer with proper audit logging."""
    audit_log("transfer", actor, {"from": from_account.id, "to": to_account.id, "amount": amount})
    from_account.balance -= amount
    to_account.balance += amount
    db.session.commit()
    return {"status": "success"}


def disburse_loan(loan_id, account, amount, actor):
    """Disbursement with proper audit logging."""
    audit_log("disburse", actor, {"loan_id": loan_id, "amount": amount})
    account.balance += amount
    loan.status = "disbursed"
    db.session.commit()


def debit_account(account, amount, reason, actor):
    """Debit with proper audit logging."""
    audit_log("debit", actor, {"account": account.id, "amount": amount, "reason": reason})
    account.balance -= amount
    db.session.commit()


def credit_account(account, amount, source, actor):
    """Credit with proper audit logging."""
    audit_log("credit", actor, {"account": account.id, "amount": amount, "source": source})
    account.balance += amount
    db.session.commit()


def repay_loan(loan, payment, actor):
    """Repayment with proper logging (not print)."""
    audit_log("repay", actor, {"loan_id": loan.id, "amount": payment.amount})
    logger.info("Processing repayment for loan %s", loan.id)
    loan.outstanding -= payment.amount
    db.session.commit()


def process_settlement(settlement, actor):
    """Settlement with proper error handling."""
    try:
        audit_log("settlement", actor, {"settlement_id": settlement.id})
        settlement.execute()
    except Exception as e:  # noqa: generic/audit-logging/no-silent-except
        logger.error("Settlement failed: %s", e)
        raise
