const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 128 },
  true,
  ['encrypt', 'decrypt'],
);
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
const hash = await crypto.subtle.digest('SHA-256', data);
