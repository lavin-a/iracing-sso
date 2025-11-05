const axios = require('axios');
const crypto = require('crypto');

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
  'https://almeidaracingacademy.outseta.com',
];

// In-memory store for PKCE verifiers (in production, use Redis or similar)
const pkceStore = new Map();

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

  // Generate PKCE code_verifier and code_challenge
  // https://oauth.iracing.com/oauth2/book/pkce_overview.html
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Generate a state parameter to link the verifier to the callback
  const state = crypto.randomBytes(16).toString('hex');
  
  // Store the verifier for the callback (expires in 10 minutes)
  pkceStore.set(state, codeVerifier);
  setTimeout(() => pkceStore.delete(state), 10 * 60 * 1000);

  // Using new OAuth endpoints: https://oauth.iracing.com/oauth2/book/authorize_endpoint.html
  const url =
    'https://oauth.iracing.com/oauth2/authorize' +
    `?client_id=${encodeURIComponent(process.env.IRACING_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=iracing.auth` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256` +
    `&state=${encodeURIComponent(state)}`;

  res.writeHead(302, { Location: url });
  res.end();
}

async function handleCallback(req, res, code) {
  if (req.query.error) {
    console.error('iRacing OAuth error:', req.query.error, req.query.error_description);
    return res.send(renderErrorPage('iRacing authentication failed.'));
  }

  try {
    const redirectUri = `${getBaseUrl(req)}/api/auth/iracing`;
    const state = req.query.state;

    // Retrieve the PKCE code_verifier
    const codeVerifier = pkceStore.get(state);
    if (!codeVerifier) {
      console.error('PKCE verifier not found for state:', state);
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    // Clean up the verifier
    pkceStore.delete(state);

    // Using new OAuth endpoints: https://oauth.iracing.com/oauth2/book/token_endpoint.html
    // For Authorization Code Grant with PKCE, client_secret is "required only if issued"
    const tokenParams = {
      grant_type: 'authorization_code',
      code,
      client_id: process.env.IRACING_CLIENT_ID,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    };

    // If client_secret was issued, mask it with client_id before sending
    if (process.env.IRACING_CLIENT_SECRET) {
      console.log('Masking client secret with client_id');
      tokenParams.client_secret = maskClientSecret(
        process.env.IRACING_CLIENT_SECRET,
        process.env.IRACING_CLIENT_ID
      );
    }

    const tokenResponse = await axios.post(
      'https://oauth.iracing.com/oauth2/token',
      new URLSearchParams(tokenParams),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 8000,
      }
    );

    const iRacingAccessToken = tokenResponse.data.access_token;

    // Decode JWT to get user info (iRacing includes user data in the token)
    const tokenParts = iRacingAccessToken.split('.');
    if (tokenParts.length !== 3) {
      throw new Error('Invalid JWT token format');
    }
    
    const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString('utf-8'));
    console.log('iRacing token payload:', payload);

    // Map iRacing token data to expected user format
    const iRacingUser = {
      sub: payload.sub || payload.cust_id,
      email: payload.email,
      given_name: payload.given_name || payload.first_name,
      family_name: payload.family_name || payload.last_name,
      preferred_username: payload.preferred_username || payload.display_name,
      nickname: payload.nickname || payload.display_name,
    };

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

function maskClientSecret(secret, identifier) {
  // iRacing requires client secrets to be masked using SHA-256
  // https://oauth.iracing.com/oauth2/book/token_endpoint.html
  // Format: SHA256(secret + normalized_identifier) in base64
  const normalizedId = identifier.trim().toLowerCase();
  const combined = secret + normalizedId;
  const hash = crypto.createHash('sha256').update(combined).digest('base64');
  return hash;
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