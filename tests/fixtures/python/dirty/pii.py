# Dirty fixture: pii-handling rules should trigger here

import logging

logger = logging.getLogger(__name__)


def process_customer(customer):
    # PAN number exposed — should trigger no-pan-number-exposure
    pan_number = "ABCDE1234F"
    logger.info(f"Processing PAN: {pan_number}")

    # Aadhaar number exposed — should trigger no-aadhaar-exposure
    aadhaar = "1234 5678 9012"
    print(f"Aadhaar: {aadhaar}")

    # Email in log — should trigger no-email-in-logs
    logger.info(f"Customer email: customer@example.com")

    # Phone number in log — should trigger no-phone-number-exposure
    logger.info(f"Phone: +91-9876543210")

    # Password in log — should trigger no-password-in-logs
    logger.info(f"User password is: {customer.password}")

    # Credit card pattern — should trigger no-credit-card-exposure
    cc_number = "4111-1111-1111-1111"
    print(f"Card: {cc_number}")

    # Date of birth in exception — should trigger no-dob-exposure
    raise ValueError(f"Invalid DOB: 15/08/1990 for customer {customer.id}")


def handle_error(customer):
    # Customer ID in exception message — should trigger no-customer-id-in-exception
    raise Exception(f"Error processing customer_id={customer.id} with aadhaar={customer.aadhaar}")
