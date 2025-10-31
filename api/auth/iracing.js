/**
 * 🏁 VERCEL SERVERLESS FUNCTION FOR iRACING SSO
 * 
 * File structure for Vercel:
 * /api
 *   /auth
 *     /iracing.js  ← This file
 * 
 * Endpoint: https://your-project.vercel.app/api/auth/iracing
 * 
 * Environment Variables (in Vercel Dashboard):
 * - IRACING_CLIENT_ID
 * - IRACING_CLIENT_SECRET
 * - OUTSETA_DOMAIN
 * - OUTSETA_API_KEY
 * - OUTSETA_SECRET_KEY
 */

const axios = require('axios');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main Handler (Vercel Serverless Function)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

module.exports = async (req, res) => {
  // Enable CORS for your Framer site
  res.setHeader('Access-Control-Allow-Origin', '*'); // Or specific domain
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;

  try {
    switch (action) {
      case 'start':
        return handleStart(req, res);
      case 'callback':
        return handleCallback(req, res);
      case 'exchange':
        return handleExchange(req, res);
      default:
        return res.status(404).json({ error: 'Unknown action' });
    }
  } catch (error) {
    console.error('iRacing SSO error:', error);
    return res.status(500).json({
      error: 'Authentication failed',
      message: error.message,
    });
  }
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Action: Start OAuth Flow
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function handleStart(req, res) {
  const redirectUri = `${getBaseUrl(req)}/api/auth/iracing?action=callback`;
  
  const iRacingAuthUrl = new URL('https://members.iracing.com/membersite/oauth2/authorize');
  iRacingAuthUrl.searchParams.append('client_id', process.env.IRACING_CLIENT_ID);
  iRacingAuthUrl.searchParams.append('redirect_uri', redirectUri);
  iRacingAuthUrl.searchParams.append('response_type', 'code');
  iRacingAuthUrl.searchParams.append('scope', 'openid profile email');

  res.redirect(307, iRacingAuthUrl.toString());
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Action: Handle OAuth Callback
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function handleCallback(req, res) {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send('Missing authorization code');
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/iracing?action=callback`;

  // 1. Exchange code for iRacing access token
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
    }
  );

  const { access_token: iRacingAccessToken } = tokenResponse.data;

  // 2. Get iRacing user info
  const userInfoResponse = await axios.get(
    'https://members.iracing.com/membersite/oauth2/userinfo',
    {
      headers: { Authorization: `Bearer ${iRacingAccessToken}` },
    }
  );

  const iRacingUser = userInfoResponse.data;

  // 3. Find or create Outseta user
  const outsetaUser = await findOrCreateOutsetaUser(iRacingUser);

  // 4. Generate Outseta JWT access token
  const outsetaAccessToken = await generateOutsetaToken(outsetaUser);

  // 5. Close popup and send token to opener window
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Authentication Successful</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
          }
          .container {
            text-align: center;
            padding: 2rem;
          }
          .checkmark {
            font-size: 4rem;
            animation: scaleIn 0.5s ease-out;
          }
          @keyframes scaleIn {
            from { transform: scale(0); }
            to { transform: scale(1); }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="checkmark">✓</div>
          <h1>Authentication Successful!</h1>
          <p>This window will close automatically...</p>
        </div>
        <script>
          (function() {
            try {
              // Send token to parent window
              if (window.opener) {
                window.opener.postMessage({
                  type: 'IRACING_AUTH_SUCCESS',
                  outsetaToken: '${outsetaAccessToken}'
                }, '*');
                
                // Close after a short delay
                setTimeout(() => window.close(), 1500);
              }
            } catch (error) {
              console.error('Failed to communicate with parent window:', error);
            }
          })();
        </script>
      </body>
    </html>
  `);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Action: Exchange Token (Alternative API endpoint)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function handleExchange(req, res) {
  const { iRacingToken } = req.body;

  if (!iRacingToken) {
    return res.status(400).json({ error: 'Missing iRacing token' });
  }

  // 1. Verify iRacing token
  const userInfoResponse = await axios.get(
    'https://members.iracing.com/membersite/oauth2/userinfo',
    {
      headers: { Authorization: `Bearer ${iRacingToken}` },
    }
  );

  const iRacingUser = userInfoResponse.data;

  // 2. Find or create Outseta user
  const outsetaUser = await findOrCreateOutsetaUser(iRacingUser);

  // 3. Generate Outseta JWT access token
  const outsetaAccessToken = await generateOutsetaToken(outsetaUser);

  return res.json({
    success: true,
    outsetaAccessToken,
    user: {
      email: outsetaUser.Email,
      name: `${outsetaUser.FirstName} ${outsetaUser.LastName}`.trim(),
    },
  });
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: Find or Create Outseta User
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function findOrCreateOutsetaUser(iRacingUser) {
  const outsetaApiUrl = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const auth = Buffer.from(
    `${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`
  ).toString('base64');

  // Try to find existing user
  try {
    const searchResponse = await axios.get(
      `${outsetaApiUrl}/crm/people`,
      {
        headers: { Authorization: `Basic ${auth}` },
        params: { Email: iRacingUser.email },
      }
    );

    if (searchResponse.data.items && searchResponse.data.items.length > 0) {
      console.log('✓ Found existing Outseta user:', iRacingUser.email);
      return searchResponse.data.items[0];
    }
  } catch (error) {
    console.log('User not found, will create new user');
  }

  // Create new user
  console.log('✓ Creating new Outseta user:', iRacingUser.email);
  const createResponse = await axios.post(
    `${outsetaApiUrl}/crm/people`,
    {
      Email: iRacingUser.email,
      FirstName: iRacingUser.given_name || '',
      LastName: iRacingUser.family_name || '',
      Account: {
        Name: iRacingUser.name || iRacingUser.email,
        // Optional: Assign to a default plan (e.g., Free tier)
        // PlanUid: 'YOUR_FREE_PLAN_UID',
      },
    },
    {
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
    }
  );

  return createResponse.data;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: Generate Outseta JWT Token
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function generateOutsetaToken(outsetaUser) {
  const outsetaApiUrl = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const auth = Buffer.from(
    `${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`
  ).toString('base64');

  const tokenResponse = await axios.post(
    `${outsetaApiUrl}/auth/token`,
    {
      Email: outsetaUser.Email,
    },
    {
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
    }
  );

  console.log('✓ Generated Outseta token for:', outsetaUser.Email);
  return tokenResponse.data.access_token;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: Get Base URL
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

