/**
 * Test script to verify Outseta API credentials
 * Run: node test-outseta.js
 */

const axios = require('axios');

// REPLACE THESE WITH YOUR ACTUAL VALUES:
const OUTSETA_DOMAIN = 'yourcompany.outseta.com'; // e.g., almeidaracing.outseta.com
const OUTSETA_API_KEY = 'your_api_key';
const OUTSETA_SECRET_KEY = 'your_secret_key';
const TEST_EMAIL = 'test@example.com'; // Use a test email from your Outseta account

async function testOutseta() {
  console.log('🧪 Testing Outseta API connection...\n');
  
  const outsetaApiUrl = `https://${OUTSETA_DOMAIN}/api/v1`;
  const auth = Buffer.from(`${OUTSETA_API_KEY}:${OUTSETA_SECRET_KEY}`).toString('base64');

  try {
    // Test 1: Search for a user
    console.log('📋 Test 1: Searching for user by email...');
    const searchResponse = await axios.get(
      `${outsetaApiUrl}/crm/people`,
      {
        headers: { Authorization: `Basic ${auth}` },
        params: { Email: TEST_EMAIL },
      }
    );

    if (searchResponse.data.items && searchResponse.data.items.length > 0) {
      console.log('✅ Found user:', searchResponse.data.items[0].Email);
      console.log('   Name:', searchResponse.data.items[0].FirstName, searchResponse.data.items[0].LastName);
      
      const user = searchResponse.data.items[0];
      
      // Test 2: Generate JWT token
      console.log('\n🔑 Test 2: Generating JWT access token...');
      const tokenResponse = await axios.post(
        `${outsetaApiUrl}/auth/token`,
        { Email: user.Email },
        {
          headers: {
            Authorization: `Basic ${auth}`,
            'Content-Type': 'application/json',
          },
        }
      );

      console.log('✅ Token generated successfully!');
      console.log('   Token (first 50 chars):', tokenResponse.data.access_token.substring(0, 50) + '...');
      
      console.log('\n🎉 All tests passed! Your Outseta credentials are working correctly.');
    } else {
      console.log('⚠️  No user found with that email. Try a different email or create a test user in Outseta first.');
    }

  } catch (error) {
    console.error('❌ Error:', error.response?.data || error.message);
    console.log('\n💡 Common issues:');
    console.log('   - Check your OUTSETA_DOMAIN (should be like: yourcompany.outseta.com)');
    console.log('   - Verify API_KEY and SECRET_KEY are correct');
    console.log('   - Make sure the test email exists in your Outseta account');
  }
}

testOutseta();

