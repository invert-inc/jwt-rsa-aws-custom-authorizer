require("dotenv").config({ silent: true });

const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");
const util = require("util");
const Sentry = require("@sentry/serverless");


const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: "2012-10-17",
    Statement: [
      {
        Action: "execute-api:Invoke",
        Effect: effect,
        Resource: resource,
      },
    ],
  };
  return policyDocument;
};

// extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {
  if (!params.type || params.type !== "TOKEN") {
    throw new Error('Expected "event.type" parameter to have value "TOKEN"');
  }

  const tokenString = params.authorizationToken;
  if (!tokenString) {
    throw new Error('Expected "event.authorizationToken" parameter to be set');
  }

  const match = tokenString.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error(
      `Invalid Authorization token - ${tokenString} does not match "Bearer .*"`
    );
  }
  return match[1];
};

const tokenConfigs = {
  default: {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER,
    jwksUri: process.env.JWKS_URI,
    publicKey: process.env.PUBLIC_KEY,
  },
  external_api_token: {
    audience: process.env.AUDIENCE,
    issuer: process.env.AUTH0_EXTERNAL_API_TOKEN_ISSUER,
    jwksUri: process.env.EXTERNAL_API_JWKS_URI,
    publicKey: process.env.EXTERNAL_API_JWT_PUBLIC_KEY,
  },
};

const clients = {
  default: jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: tokenConfigs.default.jwksUri,
  }),
  external_api_token: jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: tokenConfigs.external_api_token.jwksUri,
  }),
};

module.exports.authenticate = async (params) => {
  Sentry.captureMessage('Event params:', JSON.stringify(params, null, 2));

  const token = getToken(params);
  Sentry.captureMessage('Extracted token:', token);

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header) {
    throw new Error("invalid token");
  }

  Sentry.captureMessage('Decoded token:', JSON.stringify(decoded, null, 2));

  let tokenType = 'default';
  if (decoded.payload.iss === tokenConfigs.external_api_token.issuer) {
    tokenType = 'external_api_token';
  }

  Sentry.captureMessage('Determined tokenType:', tokenType);

  const config = tokenConfigs[tokenType];
  Sentry.captureMessage('Token config being used:', JSON.stringify(config, null, 2));

  const client = clients[tokenType];

  let signingKey;
  if (decoded.header.kid) {
    Sentry.captureMessage('Token has kid:', decoded.header.kid);
    const getSigningKey = util.promisify(client.getSigningKey);
    signingKey = await getSigningKey(decoded.header.kid).then(
      (key) => key.publicKey || key.rsaPublicKey
    );
    Sentry.captureMessage('Fetched signing key from JWKS');
  } else {
    signingKey = config.publicKey.replace(/\\n/g, "\n");
    Sentry.captureMessage('Using static public key');
  }

  const jwtOptions = {
    audience: config.audience,
    issuer: config.issuer,
  };
  Sentry.captureMessage('JWT verification options:', jwtOptions);

  try {
    const verified = await jwt.verify(token, signingKey, jwtOptions);
    Sentry.captureMessage('JWT verified payload:', JSON.stringify(verified, null, 2));
    return {
      principalId: verified.sub,
      policyDocument: getPolicyDocument("Allow", params.methodArn),
      context: { scope: verified.scope },
    };
  } catch (error) {
    Sentry.captureMessage('Token verification failed:', error);
    Sentry.captureMessage('Token issuer in token:', decoded.payload.iss);
    Sentry.captureMessage('Expected issuer:', config.issuer);
    throw new Error('Invalid token');
  }
};