const crypto = require('crypto');
// const old = crypto.createCipheriv('des-cbc', key, iv);
const weak = crypto.createCipheriv('aes-128-cbc', key, iv);
const strong = crypto.createCipheriv('aes-256-gcm', key, iv);
const legacy = crypto.createCipheriv('des-ede3-cbc', key, iv);
const dynamic = crypto.createCipheriv(config.algorithm, key, iv);
const digest = crypto.createHash('sha1').update(data).digest('hex');
const mac = crypto.createHmac('sha256', secret);
setTimeout(refresh, 128);
