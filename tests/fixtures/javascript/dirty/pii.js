// Dirty fixture: pii-handling rules should trigger here

// PAN number exposed — should trigger no-pan-number-exposure
function processPAN(customer) {
  const pan = "ABCDE1234F";
  console.log(`Processing PAN: ${pan}`);
}

// Aadhaar exposed — should trigger no-aadhaar-exposure
function processAadhaar(customer) {
  const aadhaar = "1234 5678 9012";
  console.log(`Aadhaar: ${aadhaar}`);
}

// Email in log — should trigger no-email-in-logs
function logEmail(user) {
  console.log(`Customer email: customer@example.com`);
}

// Phone number — should trigger no-phone-number-exposure
function logPhone(user) {
  console.log(`Phone: +91-9876543210`);
}

// Password in log — should trigger no-password-in-logs
function logPassword(user) {
  console.log(`User password is: ${user.password}`);
}

// Credit card — should trigger no-credit-card-exposure
function processCard() {
  const cc = "4111-1111-1111-1111";
  console.log(`Card: ${cc}`);
}

// DOB in exception — should trigger no-dob-exposure
function validateDOB(dob) {
  throw new Error(`Invalid DOB: 15/08/1990 for customer`);
}

// Customer ID in exception — should trigger no-customer-id-in-exception
function handleError(customer) {
  throw new Error(`Error processing customer_id=${customer.id}`);
}
