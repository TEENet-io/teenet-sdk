const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ErrorCode } = require('../dist/index.js');

test('sign error code contract matches shared definition', () => {
  const contractPath = path.resolve(__dirname, '../../docs/error-codes.contract.json');
  const raw = fs.readFileSync(contractPath, 'utf8');
  const contract = JSON.parse(raw);

  const actual = [
    ErrorCode.INVALID_INPUT,
    ErrorCode.SIGN_REQUEST_FAILED,
    ErrorCode.SIGN_REQUEST_REJECTED,
    ErrorCode.SIGNATURE_DECODE_FAILED,
    ErrorCode.UNEXPECTED_STATUS,
    ErrorCode.MISSING_HASH,
    ErrorCode.STATUS_QUERY_FAILED,
    ErrorCode.SIGN_FAILED,
    ErrorCode.THRESHOLD_TIMEOUT,
    ErrorCode.APPROVAL_PENDING,
  ];

  assert.deepEqual(actual, contract.sign_error_codes);
});
