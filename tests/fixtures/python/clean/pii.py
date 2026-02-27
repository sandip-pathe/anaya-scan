# Clean fixture: pii-handling rules should NOT trigger here

import logging

logger = logging.getLogger(__name__)


def process_customer(customer):
    """Process customer without exposing PII."""
    logger.info("Processing customer ID: %s", customer.id)
    # No PAN, Aadhaar, email, phone, password, CC, or DOB in logs


def validate_pan(pan_input):
    """Validate PAN format without logging the value."""
    import re
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", pan_input):
        raise ValueError("Invalid PAN format")
    logger.info("PAN validation passed")


def mask_aadhaar(aadhaar):
    """Mask Aadhaar for display — only last 4 digits shown."""
    return f"XXXX-XXXX-{aadhaar[-4:]}"


def send_notification(customer):
    """Send notification without logging PII."""
    logger.info("Notification sent to customer %s", customer.id)


def handle_error(customer_id, error_code):
    """Raise exception without PII."""
    raise Exception(f"Error {error_code} for customer ref {customer_id}")
