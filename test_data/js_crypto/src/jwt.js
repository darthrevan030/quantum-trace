const jwt = require('jsonwebtoken');
const signed = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
const shared = jwt.sign(payload, secret, { algorithm: 'HS256' });
jwt.verify(token, key, { algorithms: ['ES256', 'HS512'] });
