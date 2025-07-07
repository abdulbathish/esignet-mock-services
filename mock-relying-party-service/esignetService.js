const axios = require("axios");
const jose = require("jose");
const { ESIGNET_SERVICE_URL, ESIGNET_AUD_URL, CLIENT_ASSERTION_TYPE, CLIENT_PRIVATE_KEY, USERINFO_RESPONSE_TYPE, JWE_USERINFO_PRIVATE_KEY, JWT_WELL_KNOWN_URL, JWT_DEFAULT_ALGORITHM } = require("./config");

const baseUrl = ESIGNET_SERVICE_URL.trim();
const getTokenEndPoint = "/oauth/v2/token";
const getUserInfoEndPoint = "/oidc/userinfo";

const alg = "RS256";
const jweEncryAlgo = "RSA-OAEP-256";
const expirationTime = "1h";

// Cache for JWKS keys
let jwksCache = null;
let jwksCacheExpiry = null;

/**
 * Fetch JWKS from well-known URL
 * @returns {Promise<object>} JWKS keys
 */
const fetchJWKS = async () => {
  // Return cached keys if still valid (5 minutes cache)
  if (jwksCache && jwksCacheExpiry > Date.now()) {
    return jwksCache;
  }

  try {
    const response = await axios.get(JWT_WELL_KNOWN_URL);
    jwksCache = response.data;
    jwksCacheExpiry = Date.now() + (5 * 60 * 1000); // 5 minutes
    return jwksCache;
  } catch (error) {
    console.error("Error fetching JWKS:", error.message);
    throw new Error("Failed to fetch JWKS");
  }
};

/**
 * Verify JWT signature
 * @param {string} token JWT token to verify
 * @returns {Promise<object>} Verification result with status and payload
 */
const verifyJWTSignature = async (token) => {
  try {
    // Decode JWT header to get kid
    const header = jose.decodeProtectedHeader(token);
    const kid = header.kid;
    const algorithm = header.alg || JWT_DEFAULT_ALGORITHM;

    // Fetch JWKS
    const jwks = await fetchJWKS();
    
    // Find the key with matching kid
    const key = jwks.keys.find(k => k.kid === kid);
    if (!key) {
      return { verified: false, error: "Key not found for kid: " + kid };
    }

    // Import the public key
    const publicKey = await jose.importJWK(key, algorithm);

    // Verify the JWT
    const { payload, protectedHeader } = await jose.jwtVerify(token, publicKey);
    
    return { 
      verified: true, 
      payload, 
      header: protectedHeader,
      kid 
    };
  } catch (error) {
    console.error("JWT verification error:", error.message);
    return { verified: false, error: error.message };
  }
};

/**
 * Triggers /oauth/v2/token API on esignet service to fetch access token
 * @param {string} code auth code
 * @param {string} client_id registered client id
 * @param {string} redirect_uri validated redirect_uri
 * @param {string} grant_type grant_type
 * @returns access token with verification status
 */
const post_GetToken = async ({
  code,
  client_id,
  redirect_uri,
  grant_type
}) => {
  let request = new URLSearchParams({
    code: code,
    client_id: client_id,
    redirect_uri: redirect_uri,
    grant_type: grant_type,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await generateSignedJwt(client_id),
  });
  const endpoint = baseUrl + getTokenEndPoint;
  console.log(baseUrl)
  console.log(endpoint)
  const response = await axios.post(endpoint, request, {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });
  console.log(response.data)
  
  // Verify access token signature if it's a JWT
  let tokenVerification = { verified: false };
  if (response.data.access_token) {
    tokenVerification = await verifyJWTSignature(response.data.access_token);
  }

  return {
    ...response.data,
    tokenVerification
  };
};

/**
 * Triggers /oidc/userinfo API on esignet service to fetch userInformation
 * @param {string} access_token valid access token
 * @returns decrypted/decoded json user information with verification status
 */
const get_GetUserInfo = async (access_token) => {
  const endpoint = baseUrl + getUserInfoEndPoint;
  const response = await axios.get(endpoint, {
    headers: {
      Authorization: "Bearer " + access_token,
    },
  });

  const userInfo = await decodeUserInfoResponse(response.data);
  
  // Verify userinfo JWT signature
  let userInfoVerification = { verified: false };
  if (response.data) {
    userInfoVerification = await verifyJWTSignature(response.data);
  }

  return {
    userInfo,
    userInfoVerification
  };
};

/**
 * Generates client assertion signedJWT
 * @param {string} clientId registered client id
 * @returns client assertion signedJWT
 */
const generateSignedJwt = async (clientId) => {
  // Set headers for JWT
  var header = {
    alg: alg,
    typ: "JWT",
  };

  var payload = {
    iss: clientId,
    sub: clientId,
    aud: ESIGNET_AUD_URL,
  };

  var decodeKey = Buffer.from(CLIENT_PRIVATE_KEY, 'base64')?.toString();
  const jwkObject = JSON.parse(decodeKey);
  const privateKey = await jose.importJWK(jwkObject, alg);
  // var privateKey = await jose.importPKCS8(CLIENT_PRIVATE_KEY, alg);

  const jwt = new jose.SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .setExpirationTime(expirationTime)
    .sign(privateKey);

  return jwt;
};

/**
 * decrypts and decodes the user information fetched from esignet services
 * @param {string} userInfoResponse JWE encrypted or JWT encoded user information
 * @returns decrypted/decoded json user information
 */
const decodeUserInfoResponse = async (userInfoResponse) => {

  let response = userInfoResponse;

  if (USERINFO_RESPONSE_TYPE.toLowerCase() === "jwe") {
    var decodeKey = Buffer.from(JWE_USERINFO_PRIVATE_KEY, 'base64')?.toString();
    const jwkObject = JSON.parse(decodeKey);
    const privateKeyObj = await jose.importJWK(jwkObject, jweEncryAlgo);

    try {
      const { plaintext, protectedHeader } = await jose.compactDecrypt(response, privateKeyObj)
      response = new TextDecoder().decode(plaintext);
    } catch (error) {
      try {
        const { plaintext } = await jose.flattenedDecrypt(response, privateKeyObj)
        response = new TextDecoder().decode(plaintext);
      } catch (error) {
        const { plaintext } = await jose.generalDecrypt(response, privateKeyObj)
        response = new TextDecoder().decode(plaintext);
      }
    }
  }

  return await new jose.decodeJwt(response);
};

module.exports = {
  post_GetToken: post_GetToken,
  get_GetUserInfo: get_GetUserInfo,
};
