// Clean fixture: pii-handling rules should NOT trigger here

function processCustomer(customer) {
  console.log(`Processing customer ID: ${customer.id}`);
  // No PAN, Aadhaar, email, phone, password, CC, or DOB in logs
}

function validatePAN(panInput) {
  const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]$/;
  if (!panRegex.test(panInput)) {
    throw new Error("Invalid PAN format");
  }
  console.log("PAN validation passed");
}

function maskAadhaar(aadhaar) {
  return `XXXX-XXXX-${aadhaar.slice(-4)}`;
}

function sendNotification(customer) {
  console.log(`Notification sent to customer ${customer.id}`);
}

function handleError(customerId, errorCode) {
  throw new Error(`Error ${errorCode} for customer ref ${customerId}`);
}
