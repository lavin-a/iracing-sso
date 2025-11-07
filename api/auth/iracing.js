const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
  'https://almeidaracingacademy.outseta.com',
];

// In-memory store for PKCE verifiers (in production, use Redis or similar)
const pkceStore = new Map();

// In-memory store for temporary OAuth data (in production, use Redis or similar)
const tempDataStore = new Map();
const TOKEN_TTL_MS = 5 * 60 * 1000;

function storeTokenForClient(clientState, token) {
  if (!clientState || !token) {
    return;
  }

  tempDataStore.set(clientState, {
    token,
    createdAt: Date.now(),
  });

  setTimeout(() => {
    const entry = tempDataStore.get(clientState);
    if (entry && Date.now() - entry.createdAt >= TOKEN_TTL_MS) {
      tempDataStore.delete(clientState);
    }
  }, TOKEN_TTL_MS);
}

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

  const { code, action } = req.query;

  // Handle complete-registration endpoint (POST)
  if (req.method === 'POST' && action === 'complete-registration') {
    return handleCompleteRegistration(req, res);
  }

  if (req.method === 'GET' && action === 'poll') {
    return handlePoll(req, res);
  }

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

function handleStart(req, res) {
  if (!process.env.IRACING_CLIENT_ID) {
    return res.status(500).send('iRacing client ID not configured');
  }

  const clientState = req.query.clientState;
  const emailPageUrl = req.query.emailPageUrl;
  
  if (!clientState) {
    return res.status(400).send('Missing client state');
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/iracing`;

  // Generate PKCE code_verifier and code_challenge
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Generate a state parameter that includes both PKCE state and client state
  const pkceState = crypto.randomBytes(16).toString('hex');

  pkceStore.set(pkceState, {
    codeVerifier,
    clientState,
    emailPageUrl,
    createdAt: Date.now(),
  });
  setTimeout(() => pkceStore.delete(pkceState), 10 * 60 * 1000);

  const statePayload = Buffer.from(
    JSON.stringify({ pkce: pkceState, client: clientState })
  ).toString('base64url');

  // Using new OAuth endpoints: https://oauth.iracing.com/oauth2/book/authorize_endpoint.html
  const url =
    'https://oauth.iracing.com/oauth2/authorize' +
    `?client_id=${encodeURIComponent(process.env.IRACING_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=iracing.auth` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256` +
    `&state=${encodeURIComponent(statePayload)}` +
    `&prompt=none`;

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
    const rawState = req.query.state;

    let stateData;
    try {
      stateData = JSON.parse(Buffer.from(rawState, 'base64url').toString('utf8'));
    } catch (err) {
      console.error('Unable to decode state parameter:', err.message);
      return res.send(renderErrorPage('Invalid authentication state. Please try again.'));
    }

    const pkceState = stateData?.pkce;
    const clientState = stateData?.client;

    const pkceEntry = pkceStore.get(pkceState);
    const codeVerifier = pkceEntry?.codeVerifier || pkceEntry;
    const clientStateValue = pkceEntry?.clientState || clientState;
    const emailPageUrl = pkceEntry?.emailPageUrl;
    
    if (!codeVerifier) {
      console.error('PKCE verifier not found for state:', pkceState);
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    if (!clientStateValue) {
      console.error('Missing client state during callback');
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    const clientStateResult = clientStateValue;

    // Clean up the verifier entry
    pkceStore.delete(pkceState);

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

    // iRacing JWT only provides iracing_cust_id, no username/email
    const iRacingCustId = String(payload.iracing_cust_id || '');

    // Check if user already exists by iRacingId
    const existingUser = await findExistingUserByIRacingId(iRacingCustId);
    
    if (existingUser) {
      // Existing user - auto-login (just like Discord)
      const outsetaToken = await generateOutsetaToken(existingUser.Email);
      storeTokenForClient(clientStateResult, outsetaToken);
      return res.send(renderSuccessPage());
    }

    // New user - need email (iRacing doesn't provide it)
    const tempToken = jwt.sign(
      {
        iRacingCustId,
        clientState: clientStateResult,
        provider: 'iracing',
        firstName: payload.given_name || payload.first_name || 'iRacing',
        lastName: payload.family_name || payload.last_name || 'User',
      },
      process.env.TEMP_TOKEN_SECRET,
      { expiresIn: '10m' }
    );

    // Redirect to Framer page for email collection
    const framerEmailPage = emailPageUrl;
    return res.send(renderRedirectToFramer(framerEmailPage, tempToken));
  } catch (err) {
    dumpError('[iRacingSSO]', err);
    return res.send(renderErrorPage('Unable to complete iRacing sign in.'));
  }
}

async function handleCompleteRegistration(req, res) {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { tempToken, email, name } = body;

    if (!tempToken || !email) {
      return res.status(400).json({ error: 'Missing tempToken or email' });
    }

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Name is required' });
    }

    // Verify and decode the temporary token
    let oauthData;
    try {
      oauthData = jwt.verify(tempToken, process.env.TEMP_TOKEN_SECRET);
    } catch (err) {
      console.error('Invalid or expired temp token:', err.message);
      return res.status(400).json({ error: 'Invalid or expired token. Please try signing in again.' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Split name into first and last name
    const nameParts = name.trim().split(/\s+/);
    const firstName = nameParts[0] || 'iRacing';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'User';

    // Create user data object
    const userData = {
      email,
      sub: oauthData.iRacingCustId, // Use customer ID (e.g., 1173000)
      given_name: firstName,
      family_name: lastName,
    };

    // Create Outseta account
    const outsetaPerson = await findOrCreateOutsetaUser(userData);

    // Generate Outseta token
    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    if (!oauthData.clientState) {
      console.error('Missing clientState in temp token payload');
      return res.status(400).json({ error: 'Invalid session. Please start the sign in again.' });
    }

    storeTokenForClient(oauthData.clientState, outsetaToken);
    return res.status(200).json({ success: true });
  } catch (err) {
    dumpError('[iRacingSSO] complete-registration', err);
    return res.status(500).json({ error: 'Unable to complete registration' });
  }
}

async function handlePoll(req, res) {
  const clientState = req.query.clientState;

  if (!clientState) {
    return res.status(400).json({ error: 'Missing clientState' });
  }

  const entry = tempDataStore.get(clientState);
  if (!entry) {
    return res.json({ success: false, pending: true });
  }

  if (Date.now() - entry.createdAt > TOKEN_TTL_MS) {
    tempDataStore.delete(clientState);
    return res.json({ success: false, pending: true });
  }

  tempDataStore.delete(clientState);
  return res.json({ success: true, outsetaToken: entry.token });
}

async function findExistingUserByIRacingId(iRacingId) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  try {
    const search = await axios.get(`${apiBase}/crm/people`, {
      headers: authHeader,
      params: { iRacingId },
      timeout: 8000,
    });

    if (search.data.items && search.data.items.length > 0) {
      return search.data.items[0];
    }
  } catch (err) {
    console.warn('iRacing ID search failed:', err.message);
  }

  return null;
}

async function findOrCreateOutsetaUser(iRacingUser) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const email = iRacingUser.email;
  const firstName = iRacingUser.given_name || 'iRacing';
  const lastName = iRacingUser.family_name || 'User';
  const iRacingId = String(iRacingUser.sub || '');
  const desiredFields = {
    iRacingId,
  };

  // Try to find existing person by email
  try {
    const search = await axios.get(`${apiBase}/crm/people`, {
      headers: authHeader,
      params: { Email: email },
      timeout: 8000,
    });

    if (search.data.items && search.data.items.length > 0) {
      const person = search.data.items[0];
      const needsUpdate = person.iRacingId !== desiredFields.iRacingId;

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
    console.warn('Outseta search failed:', err.message);
  }

  // Try to create new account via /crm/registrations endpoint with free subscription
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

  try {
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

    return createResponse.data.PrimaryContact;
  } catch (createErr) {
    // If account already exists, fetch the actual person record
    if (createErr.response?.status === 400 && createErr.response?.data?.EntityValidationErrors?.[0]?.ValidationErrors?.[0]?.ErrorCode === 'Duplicate') {
      const search = await axios.get(`${apiBase}/crm/people`, {
        headers: authHeader,
        params: { Email: email },
        timeout: 8000,
      });

      if (search.data.items && search.data.items.length > 0) {
        const person = search.data.items[0];
        
        // Update iRacing fields if needed
        const needsUpdate = person.iRacingId !== desiredFields.iRacingId;

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
    }
    
    throw createErr;
  }
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

function renderSuccessPage() {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Signing in...</title>
  </head>
  <body>
    <script>
      window.close();
    </script>
  </body>
</html>`;
}

function renderRedirectToFramer(framerUrl, tempToken) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Redirecting...</title>
  </head>
  <body>
    <script>
      const baseUrl = ${JSON.stringify(framerUrl)};
      const separator = baseUrl.includes('?') ? '&' : '?';
      window.location.href = baseUrl + separator + 'popup=true#token=' + ${JSON.stringify(tempToken)};
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