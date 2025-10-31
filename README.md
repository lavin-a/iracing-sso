# iRacing SSO Backend

Backend API for iRacing Single Sign-On integration with Outseta.

## Deployment

Deploy to Vercel with the following environment variables:

- `IRACING_CLIENT_ID` - Your iRacing OAuth client ID
- `IRACING_CLIENT_SECRET` - Your iRacing OAuth client secret
- `OUTSETA_DOMAIN` - Your Outseta domain (e.g., yourcompany.outseta.com)
- `OUTSETA_API_KEY` - Your Outseta API key
- `OUTSETA_SECRET_KEY` - Your Outseta secret key

## Endpoints

- `GET /api/auth/iracing?action=start` - Start OAuth flow
- `GET /api/auth/iracing?action=callback` - OAuth callback
- `POST /api/auth/iracing?action=exchange` - Token exchange

## Usage

After deployment, use this URL in your Framer iRacingSSOButton component:
```
https://your-project.vercel.app/api/auth/iracing
```

