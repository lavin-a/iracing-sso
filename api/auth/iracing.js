const axios = require('axios');

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
  'https://almeidaracingacademy.outseta.com',
];

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || origin?.endsWith('.framer.app')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { code } = req.query;

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

function handleStart(req, res) {
  if (!process.env.IRACING_CLIENT_ID) {
    return res.status(500).send('iRacing client ID not configured');
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/iracing`;

  const url =
    'https://members.iracing.com/membersite/oauth2/authorize' +
    `?client_id=${encodeURIComponent(process.env.IRACING_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=openid%20profile%20email` +
    `&prompt=none`;

  res.writeHead(302, { Location: url });
  res.end();
}

async function handleCallback(req, res, code) {
  if (req.query.error) {
    console.error('iRacing OAuth error:', req.query.error);
    return res.send(renderErrorPage('iRacing authentication failed.'));
  }

  try {
    const redirectUri = `${getBaseUrl(req)}/api/auth/iracing`;

    const tokenResponse = await axios.post(
      'https://members.iracing.com/membersite/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.IRACING_CLIENT_ID,
        client_secret: process.env.IRACING_CLIENT_SECRET,
        redirect_uri: redirectUri,
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 8000,
      }
    );

    const iRacingAccessToken = tokenResponse.data.access_token;

    const userResponse = await axios.get('https://members.iracing.com/membersite/oauth2/userinfo', {
      headers: { Authorization: `Bearer ${iRacingAccessToken}` },
      timeout: 8000,
    });

    const iRacingUser = userResponse.data;
    console.log('iRacing user:', iRacingUser.email);

    const outsetaPerson = await findOrCreateOutsetaUser(iRacingUser);
    console.log('Outseta person UID:', outsetaPerson.Uid, 'Account UID:', outsetaPerson.Account?.Uid);

    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    console.log('[iRacingSSO]', JSON.stringify({
      email: outsetaPerson.Email,
      uid: outsetaPerson.Uid,
      accountUid: outsetaPerson.Account?.Uid || null,
      iRacingId: iRacingUser.sub || null,
    }));

    return res.send(renderSuccessPage(outsetaToken));
  } catch (err) {
    dumpError('[iRacingSSO]', err);
    return res.send(renderErrorPage('Unable to complete iRacing sign in.'));
  }
}

async function findOrCreateOutsetaUser(iRacingUser) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const email = iRacingUser.email;
  const firstName = iRacingUser.given_name || 'iRacing';
  const lastName = iRacingUser.family_name || 'User';
  const desiredFields = {
    iRacingUsername: iRacingUser.preferred_username || iRacingUser.nickname || '',
    iRacingId: (iRacingUser.sub || '').toString(),
  };

  // Try to find existing person
  try {
    const search = await axios.get(`${apiBase}/crm/people`, {
      headers: authHeader,
      params: { Email: email },
      timeout: 8000,
    });

    if (search.data.items && search.data.items.length > 0) {
      const person = search.data.items[0];
      const needsUpdate =
        person.iRacingUsername !== desiredFields.iRacingUsername ||
        person.iRacingId !== desiredFields.iRacingId;

      if (needsUpdate) {
        await axios.put(
          `${apiBase}/crm/people/${person.Uid}`,
          {
            Uid: person.Uid,
            Email: person.Email,
            FirstName: person.FirstName,
            LastName: person.LastName,
            ...desiredFields,
          },
          {
            headers: { ...authHeader, 'Content-Type': 'application/json' },
            timeout: 8000,
          }
        );
      }

      return person;
    }
  } catch (err) {
    console.warn('Outseta search failed, will try to create:', err.message);
  }

  // Use /crm/registrations endpoint with free subscription
  const createPayload = {
    Name: `${firstName} ${lastName}`,
    PersonAccount: [
      {
        IsPrimary: true,
        Person: {
          Email: email,
          FirstName: firstName,
          LastName: lastName,
          ...desiredFields,
        },
      },
    ],
    Subscriptions: [
      {
        Plan: {
          Uid: process.env.OUTSETA_FREE_PLAN_UID,
        },
        BillingRenewalTerm: 1,
      },
    ],
  };

  console.log('Creating Outseta account via /crm/registrations');

  const createResponse = await axios.post(
    `${apiBase}/crm/registrations`,
    createPayload,
    {
      headers: {
        ...authHeader,
        'Content-Type': 'application/json',
      },
      timeout: 8000,
    }
  );

  console.log('Account created:', createResponse.data.Uid, 'Person:', createResponse.data.PrimaryContact?.Uid);

  return createResponse.data.PrimaryContact;
}

async function generateOutsetaToken(email) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const tokenResponse = await axios.post(
    `${apiBase}/tokens`,
    { username: email },
    {
      headers: { ...authHeader, 'Content-Type': 'application/json' },
      timeout: 8000,
    }
  );

  return tokenResponse.data.access_token || tokenResponse.data;
}

function renderSuccessPage(token) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>iRacing Sign In</title>
    <style>
      body { margin: 0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
      button { padding: 12px 24px; background: #c8102e; color: #fff; border: none; border-radius: 8px; cursor: pointer; }
    </style>
  </head>
  <body>
    <div style="text-align:center;">
      <h1>Signed in with iRacing</h1>
      <p>You can close this window.</p>
      <button onclick="window.close()">Close</button>
    </div>
    <script>
      (function() {
        const token = ${JSON.stringify(token)};
        if (window.opener) {
          window.opener.postMessage({ type: 'IRACING_AUTH_SUCCESS', outsetaToken: token }, '*');
        }
        setTimeout(() => window.close(), 1200);
      })();
    </script>
  </body>
</html>`;
}

function renderErrorPage(message) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>iRacing Sign In</title>
    <style>
      body { margin: 0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
      p { color: #555; }
    </style>
  </head>
  <body>
    <div style="text-align:center;">
      <h1>Sign in failed</h1>
      <p>${message}</p>
      <button onclick="window.close()" style="padding: 10px 20px;">Close</button>
    </div>
  </body>
</html>`;
}

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

function dumpError(tag, error) {
  const payload = {
    tag,
    message: error?.message,
    stack: error?.stack,
    response: error?.response
      ? {
          status: error.response.status,
          statusText: error.response.statusText,
          data: toJsonSafe(error.response.data),
          headers: error.response.headers,
        }
      : null,
    request: error?.config
      ? {
          method: error.config.method,
          url: error.config.url,
          data: toJsonSafe(error.config.data),
          headers: error.config.headers,
        }
      : null,
  };

  try {
    console.error(`${tag} error`, JSON.stringify(payload, null, 2));
  } catch (serializationError) {
    console.error(`${tag} error (serialization failed)`, payload);
  }
}

function toJsonSafe(value) {
  if (value == null) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (err) {
    return String(value);
  }
}