const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { kv } = require('@vercel/kv');

const allowedOrigins = [
  'https://almeidaracingacademy.com',
  'https://aware-amount-178968.framer.app',
  'https://new.almeidaracingacademy.com',
];

const allowedReturnUrls = [
  'https://almeidaracingacademy.com/success',
  'https://aware-amount-178968.framer.app/success',
  'https://new.almeidaracingacademy.com/success',
];
const allowedEmailUrls = [
  'https://almeidaracingacademy.com/link-email',
  'https://aware-amount-178968.framer.app/link-email',
  'https://new.almeidaracingacademy.com/link-email',
];
const DEFAULT_RETURN_URL = allowedReturnUrls[0];
const DEFAULT_EMAIL_PAGE_URL = allowedEmailUrls[0];
const ACCOUNT_CONFLICT_MESSAGE = "This email is already registered. Please sign in using a known method, then link this provider from your account settings.";

const redirectHostAllowlist = new Set([
  ...allowedReturnUrls.map(getHost),
  ...allowedEmailUrls.map(getHost),
  'almeidaracingacademy.com',
  'aware-amount-178968.framer.app',
  'new.almeidaracingacademy.com',
].filter(Boolean));

function getHost(url) {
  try {
    return new URL(url).host;
  } catch (err) {
    return null;
  }
}

function sanitizeRedirect(targetUrl, fallbackUrl) {
  if (!targetUrl) return fallbackUrl;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'https:') {
      return fallbackUrl;
    }
    if (allowedReturnUrls.includes(parsed.toString()) || allowedEmailUrls.includes(parsed.toString())) {
      return parsed.toString();
    }
    if (redirectHostAllowlist.has(parsed.host)) {
      return parsed.toString();
    }
  } catch (err) {
    return fallbackUrl;
  }
  return fallbackUrl;
}

// Rate limiting: 10 requests per minute per IP
async function checkRateLimit(ip) {
  const key = `iracing:ratelimit:${ip}`;
  const count = await kv.incr(key);
  if (count === 1) await kv.expire(key, 60);
  return count <= 10;
}

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
  if (!await checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const { code, action } = req.query;

  if (req.method === 'POST') {
    if (action === 'complete-registration') {
      return handleCompleteRegistration(req, res);
    }
    if (action === 'send-password-reset') {
      return handleSendPasswordReset(req, res);
    }
    if (action === 'disconnect') {
      return handleDisconnect(req, res);
    }
  }

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

async function handleStart(req, res) {
  if (!process.env.IRACING_CLIENT_ID) {
    return res.status(500).send('iRacing client ID not configured');
  }

  const intent = (req.query.intent || 'login').toLowerCase();
  if (!['login', 'link'].includes(intent)) {
    return res.status(400).send('Invalid intent');
  }

  const requestedReturnUrl = req.query.return_url;
  const requestedEmailPageUrl = req.query.email_page_url;

  const returnUrl = sanitizeRedirect(requestedReturnUrl, DEFAULT_RETURN_URL);
  const emailPageUrl = sanitizeRedirect(requestedEmailPageUrl, DEFAULT_EMAIL_PAGE_URL);

  let linkPersonUid = null;
  if (intent === 'link') {
    const linkToken = req.query.link_token;
    const requestedLinkUid = req.query.link_person_uid;

    if (!linkToken || !requestedLinkUid) {
      return res.status(400).send('Missing linking parameters');
    }

    try {
      const profile = await verifyOutsetaAccessToken(linkToken);
      if (profile?.Uid !== requestedLinkUid) {
        return res.status(403).send('Invalid linking session');
      }
    } catch (err) {
      console.error('Failed to verify Outseta token for linking', err.message);
      return res.status(403).send('Invalid linking session');
    }

    linkPersonUid = requestedLinkUid;
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/iracing`;

  // Generate PKCE code_verifier and code_challenge
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  const pkceState = crypto.randomBytes(16).toString('hex');

  // Store in Vercel KV with 10 minute expiration
  await kv.set(`iracing:pkce:${pkceState}`, {
    codeVerifier,
    returnUrl,
    emailPageUrl,
    intent,
    linkPersonUid,
    createdAt: Date.now(),
  }, { ex: 600 });

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

    const pkceEntry = await kv.get(`iracing:pkce:${pkceState}`);
    const codeVerifier = pkceEntry?.codeVerifier;
    const returnUrl = pkceEntry?.returnUrl;
    const emailPageUrl = pkceEntry?.emailPageUrl;
    const intent = (pkceEntry?.intent || 'login').toLowerCase();
    const linkPersonUid = pkceEntry?.linkPersonUid || null;

    if (!codeVerifier || !returnUrl) {
      console.error('PKCE verifier not found for state:', pkceState);
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    await kv.del(`iracing:pkce:${pkceState}`);

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
    const displayName =
      payload.display_name ||
      payload.preferred_username ||
      payload.iracing_username ||
      payload.username ||
      '';
    const firstName =
      payload.given_name ||
      payload.first_name ||
      (displayName ? displayName.split(' ')[0] : 'iRacing');
    const lastName =
      payload.family_name ||
      payload.last_name ||
      (displayName ? displayName.split(' ').slice(1).join(' ') || 'User' : 'User');
    const normalizedEmail = payload.email ? String(payload.email).trim().toLowerCase() : null;

    const existingByiRacingId = iRacingCustId
      ? await findPersonByField('iRacingId', iRacingCustId)
      : null;

    if (existingByiRacingId) {
      if (intent === 'link') {
        if (!linkPersonUid || existingByiRacingId.Uid !== linkPersonUid) {
          return res.send(
            renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'iracing')
          );
        }

        return res.send(renderLinkSuccessPage(returnUrl, 'iracing'));
      }

      const outsetaToken = await generateOutsetaToken(existingByiRacingId.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    if (intent === 'link') {
      if (!linkPersonUid) {
        return res.send(renderErrorPage('Linking session expired.'));
      }

      const person = await getPersonByUid(linkPersonUid);
      if (!person) {
        return res.send(renderErrorPage('Unable to locate your account.'));
      }

      await updatePerson(linkPersonUid, {
        Uid: person.Uid,
        Email: person.Email,
        FirstName: person.FirstName,
        LastName: person.LastName,
        iRacingId: iRacingCustId,
        iRacingUsername: displayName || person.iRacingUsername || '',
      });

      return res.send(renderLinkSuccessPage(returnUrl, 'iracing'));
    }

    if (normalizedEmail) {
      const existingByEmail = await findPersonByEmail(normalizedEmail);
      if (existingByEmail) {
        return res.send(
          renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'iracing')
        );
      }

      const createdPerson = await createIracingOutsetaUser({
        email: normalizedEmail,
        firstName,
        lastName,
        iRacingCustId,
        displayName,
      });
      const outsetaToken = await generateOutsetaToken(createdPerson.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    const csrfToken = crypto.randomBytes(16).toString('hex');
    const tempToken = jwt.sign(
      {
        iRacingCustId,
        returnUrl,
        provider: 'iracing',
        firstName,
        lastName,
        displayName,
        csrf: csrfToken,
      },
      process.env.TEMP_TOKEN_SECRET,
      { expiresIn: '10m' }
    );

    return res.send(renderRedirectToFramer(emailPageUrl, tempToken));
  } catch (err) {
    dumpError('[iRacingSSO]', err);
    return res.send(renderErrorPage('Unable to complete iRacing sign in.'));
  }
}

async function handleCompleteRegistration(req, res) {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { tempToken, email, name, csrf } = body;

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

    // CSRF protection
    if (!csrf || oauthData.csrf !== csrf) {
      console.error('CSRF token mismatch');
      return res.status(403).json({ error: 'Invalid request. Please try again.' });
    }

    // Validate and sanitize email
    const sanitizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (sanitizedEmail.length > 254) {
      return res.status(400).json({ error: 'Email address is too long' });
    }

    // Validate and sanitize name
    const sanitizedName = name.trim().replace(/\s+/g, ' '); // Normalize whitespace
    if (sanitizedName.length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters' });
    }
    if (sanitizedName.length > 100) {
      return res.status(400).json({ error: 'Name must be less than 100 characters' });
    }

    // Prevent malicious input
    const dangerousPattern = /<|>|javascript:|on\w+=/i;
    if (dangerousPattern.test(sanitizedName) || dangerousPattern.test(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid characters in input' });
    }

    if (!oauthData.iRacingCustId) {
      return res.status(400).json({ error: 'Missing iRacing identifier. Please restart sign in.' });
    }

    const existingByEmail = await findPersonByEmail(sanitizedEmail);
    if (existingByEmail) {
      if (
        existingByEmail.iRacingId &&
        String(existingByEmail.iRacingId) === String(oauthData.iRacingCustId)
      ) {
        const outsetaToken = await generateOutsetaToken(existingByEmail.Email);
        return res.status(200).json({
          success: true,
          outsetaToken,
          returnUrl: oauthData.returnUrl,
        });
      }

      return res.status(409).json({ error: ACCOUNT_CONFLICT_MESSAGE });
    }

    const nameParts = sanitizedName.split(/\s+/);
    const firstName = nameParts[0] || 'iRacing';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : 'User';
    const displayName = oauthData.displayName || sanitizedName;

    const createdPerson = await createIracingOutsetaUser({
      email: sanitizedEmail,
      firstName,
      lastName,
      iRacingCustId: oauthData.iRacingCustId,
      displayName,
    });
    const outsetaToken = await generateOutsetaToken(createdPerson.Email);

    return res.status(200).json({
      success: true,
      outsetaToken,
      returnUrl: oauthData.returnUrl,
    });
  } catch (err) {
    dumpError('[iRacingSSO] complete-registration', err);
    return res.status(500).json({ error: 'Unable to complete registration' });
  }
}

async function handleSendPasswordReset(req, res) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const accessToken = authHeader.slice(7).trim();
    if (!accessToken) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const profile = await verifyOutsetaAccessToken(accessToken);
    if (!profile?.Uid) {
      return res.status(403).json({ error: 'Unable to validate session.' });
    }

    const person = await getPersonByUid(profile.Uid);
    if (!person?.Email) {
      return res.status(400).json({ error: 'No email found for this account.' });
    }

    await sendPasswordResetEmail(person.Email);

    return res.status(200).json({ success: true });
  } catch (err) {
    dumpError('[iRacingSSO][password-reset]', err);
    return res.status(500).json({ error: 'Unable to send password email. Please try again later.' });
  }
}

async function createIracingOutsetaUser({ email, firstName, lastName, iRacingCustId, displayName }) {
  const fullName = `${firstName} ${lastName}`.trim();
  const registration = await createRegistration({
    Name: fullName || 'iRacing User',
    PersonAccount: [
      {
        IsPrimary: true,
        Person: {
          Email: email,
          FirstName: firstName,
          LastName: lastName,
          iRacingId: iRacingCustId,
          iRacingUsername: displayName || fullName || 'iRacing User',
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
  });

  return registration.PrimaryContact;
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

function renderRedirectWithError(returnUrl, code, message, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('error', code);
  if (message) {
    params.set('message', message);
  }
  if (provider) {
    params.set('provider', provider);
  }
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Redirecting...</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function renderLinkSuccessPage(returnUrl, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('link', 'success');
  params.set('provider', provider);
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Link Successful</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
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

function getOutsetaApiBase() {
  if (!process.env.OUTSETA_DOMAIN) {
    throw new Error('OUTSETA_DOMAIN not configured');
  }
  return `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
}

function getOutsetaAuthHeaders() {
  if (!process.env.OUTSETA_API_KEY || !process.env.OUTSETA_SECRET_KEY) {
    throw new Error('Outseta API credentials not configured');
  }

  return {
    Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };
}

async function verifyOutsetaAccessToken(token) {
  if (!token) {
    throw new Error('Missing Outseta access token');
  }

  const apiBase = getOutsetaApiBase();

  const response = await axios.get(`${apiBase}/profile`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    timeout: 8000,
  });

  return response.data;
}

async function getPersonByUid(uid) {
  if (!uid) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people/${uid}`, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
}

async function findPersonByEmail(email) {
  if (!email) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: { Email: email },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function findPersonByField(field, value) {
  if (!field || value == null) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: { [field]: value },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function updatePerson(uid, payload) {
  if (!uid) throw new Error('Cannot update person without UID');

  const apiBase = getOutsetaApiBase();
  await axios.put(`${apiBase}/crm/people/${uid}`, payload, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });
}

async function createRegistration(payload) {
  const apiBase = getOutsetaApiBase();
  const response = await axios.post(`${apiBase}/crm/registrations`, payload, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
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

async function handleDisconnect(req, res) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const accessToken = authHeader.slice(7).trim();
    if (!accessToken) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const profile = await verifyOutsetaAccessToken(accessToken);
    if (!profile?.Uid) {
      return res.status(403).json({ error: 'Unable to validate session.' });
    }

    const person = await getPersonByUid(profile.Uid);
    if (!person) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    if (!hasPassword(person)) {
      return res.status(412).json({
        error: 'Add a password to your account before disconnecting iRacing.',
      });
    }

    const alreadyDisconnected =
      !person.iRacingId && !person.iRacingUsername;

    if (!alreadyDisconnected) {
      await updatePerson(person.Uid, {
        Uid: person.Uid,
        Email: person.Email,
        FirstName: person.FirstName,
        LastName: person.LastName,
        iRacingId: '',
        iRacingUsername: '',
      });
    }

    return res.status(200).json({
      success: true,
      provider: 'iracing',
      disconnected: !alreadyDisconnected,
    });
  } catch (err) {
    dumpError('[iRacingSSO][disconnect]', err);
    return res.status(500).json({ error: 'Unable to disconnect iRacing at this time.' });
  }
}

function hasPassword(person) {
  if (!person) return false;

  const candidateKeys = [
    'PasswordLastUpdated',
    'PasswordLastUpdatedUtc',
    'PasswordLastUpdatedDate',
    'PasswordLastUpdatedDateUtc',
    'PasswordLastUpdatedDateTime',
    'PasswordLastUpdatedDateTimeUtc',
  ];

  for (const key of candidateKeys) {
    const value = person[key];
    if (!value) continue;
    if (typeof value === 'string' && value.trim().length > 0) return true;
    if (value instanceof Date && !isNaN(value.getTime())) return true;
    if (typeof value === 'number' && value > 0) return true;
  }

  if (person.PasswordMustChange === true) return false;
  if (person.HasPassword === true) return true;

  return false;
}
