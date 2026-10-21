const { Jws } = require('@mojaloop/sdk-standard-components');
const signer = new Jws.signer({ logger, signingKey });
const validator = new JwsValidator({ logger, validationKeys });
