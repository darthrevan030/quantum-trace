import { generateKeyPairSync, createECDH, publicEncrypt } from 'crypto';

export function makeKeys() {
  const rsa = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ed = generateKeyPairSync('ed25519');
  const ecdh = createECDH('secp384r1');
  return publicEncrypt(rsa.publicKey, Buffer.from('x'));
}
