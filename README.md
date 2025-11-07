# iRacing SSO Backend

Backend API for iRacing Single Sign-On integration with Outseta.

**Note:** iRacing does not provide email addresses in their OAuth flow. Users will be prompted to enter their email after authenticating with iRacing.

## Deployment

Deploy to Vercel with the following environment variables:

- `IRACING_CLIENT_ID` - Your iRacing OAuth client ID
- `IRACING_CLIENT_SECRET` - Your iRacing OAuth client secret (if using confidential client)
- `OUTSETA_DOMAIN` - Your Outseta domain (e.g., yourcompany.outseta.com)
- `OUTSETA_API_KEY` - Your Outseta API key
- `OUTSETA_SECRET_KEY` - Your Outseta secret key
- `OUTSETA_FREE_PLAN_UID` - Your Outseta free plan UID
- `TEMP_TOKEN_SECRET` - Secret for temporary JWT tokens (generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`)

### Example TEMP_TOKEN_SECRET:
```
03f59572c18f32822809960143471d1422db56deff9aff473cdeef1439419573
```

## Endpoints

- `GET /api/auth/iracing` - Start OAuth flow (redirects to iRacing)
- `GET /api/auth/iracing?code=...` - OAuth callback (handles iRacing response)
- `POST /api/auth/iracing?action=complete-registration` - Complete registration with email

## User Flow

1. User clicks "Sign in with iRacing" button
2. User authenticates with iRacing
3. Popup shows email collection form
4. User enters email and submits
5. Backend creates Outseta account with iRacing data + email
6. User is signed in automatically

## Usage

After deployment, use this URL in your Framer iRacingSSOButton component:
```
https://your-project.vercel.app/api/auth/iracing
```

The email collection page URL is configured in the Framer button's `emailPageUrl` property (defaults to `/link-email`).

