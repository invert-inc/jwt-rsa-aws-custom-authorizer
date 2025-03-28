const lib = require('./lib');
const Sentry = require("@sentry/serverless");

Sentry.AWSLambda.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 0,
});

let data;

module.exports.handler = async (event, context) => {
  console.log("Event received:", JSON.stringify(event, null, 2));
  try {
    data = await lib.authenticate(event);
  }
  catch (err) {
      console.error('Caught error:', err);
      return context.fail("Unauthorized");
  }
  return data;
};

