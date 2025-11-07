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

  if (req.method === 'POST' && action === 'complete-registration') {
    return handleCompleteRegistration(req, res);
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

  const returnUrl = req.query.return_url;
  const emailPageUrl = req.query.email_page_url;
  
  if (!returnUrl) {
    return res.status(400).send('Missing return_url parameter');
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/iracing`;

  // Generate PKCE code_verifier and code_challenge
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  const pkceState = crypto.randomBytes(16).toString('hex');

  pkceStore.set(pkceState, {
    codeVerifier,
    returnUrl,
    emailPageUrl,
    createdAt: Date.now(),
  });
  setTimeout(() => pkceStore.delete(pkceState), 10 * 60 * 1000);

  const url =
    'https://oauth.iracing.com/oauth2/authorize' +
    `?client_id=${encodeURIComponent(process.env.IRACING_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=iracing.auth` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256` +
    `&state=${encodeURIComponent(pkceState)}` +
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
    const pkceState = req.query.state;

    const pkceEntry = pkceStore.get(pkceState);
    const codeVerifier = pkceEntry?.codeVerifier;
    const returnUrl = pkceEntry?.returnUrl;
    const emailPageUrl = pkceEntry?.emailPageUrl;
    
    if (!codeVerifier || !returnUrl) {
      console.error('PKCE verifier not found for state:', pkceState);
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    pkceStore.delete(pkceState);

    const tokenParams = {
      grant_type: 'authorization_code',
      code,
      client_id: process.env.IRACING_CLIENT_ID,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    };

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

    const tokenParts = iRacingAccessToken.split('.');
    if (tokenParts.length !== 3) {
      throw new Error('Invalid JWT token format');
    }
    
    const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString('utf-8'));
    const iRacingCustId = String(payload.iracing_cust_id || '');

    // Check if user already exists by iRacingId
    const existingUser = await findExistingUserByIRacingId(iRacingCustId);
    
    if (existingUser) {
      // Existing user - auto-login
      const outsetaToken = await generateOutsetaToken(existingUser.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    // New user - need email
    const tempToken = jwt.sign(
      {
        iRacingCustId,
        returnUrl,
        provider: 'iracing',
        firstName: payload.given_name || payload.first_name || 'iRacing',
        lastName: payload.family_name || payload.last_name || 'User',
      },
      process.env.TEMP_TOKEN_SECRET,
      { expiresIn: '10m' }
    );

    // Redirect to Framer email collection page
    return res.send(renderRedirectToFramer(emailPageUrl, tempToken));
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

    let oauthData;
    try {
      oauthData = jwt.verify(tempToken, process.env.TEMP_TOKEN_SECRET);
    } catch (err) {
      console.error('Invalid or expired temp token:', err.message);
      return res.status(400).json({ error: 'Invalid or expired token. Please try signing in again.' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const nameParts = name.trim().split(/\s+/);
    const firstName = nameParts[0] || 'iRacing';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'User';

    const userData = {
      email,
      sub: oauthData.iRacingCustId,
      given_name: firstName,
      family_name: lastName,
    };

    const outsetaPerson = await findOrCreateOutsetaUser(userData);
    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    return res.status(200).json({ 
      success: true, 
      outsetaToken,
      returnUrl: oauthData.returnUrl 
    });
  } catch (err) {
    dumpError('[iRacingSSO] complete-registration', err);
    return res.status(500).json({ error: 'Unable to complete registration' });
  }
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

  // Create new account
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
    if (createErr.response?.status === 400 && createErr.response?.data?.EntityValidationErrors?.[0]?.ValidationErrors?.[0]?.ErrorCode === 'Duplicate') {
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

function renderSuccessPage(token, returnUrl) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Signing in...</title>
  </head>
  <body>
    <script>
      (function() {
        const token = ${JSON.stringify(token)};
        const returnUrl = ${JSON.stringify(returnUrl)};
        
        const url = new URL(returnUrl);
        url.hash = 'iracing_token=' + token;
        window.location.href = url.toString();
      })();
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
      window.location.href = baseUrl + separator + 'popup=false#token=' + ${JSON.stringify(tempToken)};
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
