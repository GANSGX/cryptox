import nacl from 'tweetnacl';

const key = nacl.randomBytes(32);
const nonce = nacl.randomBytes(24);
const msg = new TextEncoder().encode('test message for saved messages');
const enc = nacl.secretbox(msg, nonce, key);

const ct = Buffer.from(enc).toString('base64');
const n = Buffer.from(nonce).toString('base64');
const encrypted_content = `${ct}:${n}`;

console.log('Ciphertext:', ct);
console.log('Nonce:', n);
console.log('Encrypted Content:', encrypted_content);
console.log('\nServer Regex Test:', /^[A-Za-z0-9+/=:]+$/.test(encrypted_content) ? '✅ PASS' : '❌ FAIL');

// Check for invalid characters
const invalidChars = encrypted_content.split('').filter(char => !/[A-Za-z0-9+/=:]/.test(char));
if (invalidChars.length > 0) {
  console.log('Invalid characters:', invalidChars.map(c => `'${c}' (code: ${c.charCodeAt(0)})`));
} else {
  console.log('All characters valid');
}
