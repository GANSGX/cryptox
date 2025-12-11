// Тест для проверки формата зашифрованных сообщений
import nacl from 'tweetnacl';

function encodeBase64(arr) {
  return Buffer.from(arr).toString('base64');
}

function generateSessionKey() {
  const key = nacl.randomBytes(32);
  return encodeBase64(key);
}

function encryptMessage(message, key) {
  const keyUint8 = Buffer.from(key, 'base64');
  const nonce = nacl.randomBytes(24);
  const messageUint8 = new TextEncoder().encode(message);

  const encrypted = nacl.secretbox(messageUint8, nonce, keyUint8);

  return {
    ciphertext: encodeBase64(encrypted),
    nonce: encodeBase64(nonce)
  };
}

// Тестируем
const sessionKey = generateSessionKey();
const testMessage = "Hello, this is a test message for Saved Messages!";
const { ciphertext, nonce } = encryptMessage(testMessage, sessionKey);

// Формируем зашифрованный контент
const encrypted_content = `${ciphertext}:${nonce}`;

console.log('\n=== TEST ENCRYPTED MESSAGE FORMAT ===\n');
console.log('Session Key:', sessionKey);
console.log('Message:', testMessage);
console.log('\nCiphertext:', ciphertext);
console.log('Ciphertext length:', ciphertext.length);
console.log('Ciphertext has only base64 chars:', /^[A-Za-z0-9+/=]+$/.test(ciphertext));

console.log('\nNonce:', nonce);
console.log('Nonce length:', nonce.length);
console.log('Nonce has only base64 chars:', /^[A-Za-z0-9+/=]+$/.test(nonce));

console.log('\nEncrypted Content:', encrypted_content);
console.log('Encrypted Content length:', encrypted_content.length);

// Проверяем серверный regex
const serverRegex = /^[A-Za-z0-9+/=:]+$/;
console.log('\n🔍 Server Regex Test:', serverRegex.test(encrypted_content) ? '✅ PASS' : '❌ FAIL');

// Детальная проверка каждого символа
console.log('\n📝 Character Analysis:');
const invalidChars = encrypted_content.split('').filter(char => !/[A-Za-z0-9+/=:]/.test(char));
if (invalidChars.length > 0) {
  console.log('❌ Invalid characters found:', invalidChars.map(c => `'${c}' (code: ${c.charCodeAt(0)})`));
} else {
  console.log('✅ All characters are valid');
}

console.log('\n');
