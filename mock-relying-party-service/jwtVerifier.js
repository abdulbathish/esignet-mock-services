const axios = require("axios");
const jose = require("jose");
const { 
  ESIGNET_JWKS_URL, 
  JWT_DEFAULT_ALG, 
  JWT_CACHE_DURATION, 
  JWT_DEBUG_MODE 
} = require("./config");

class JwtVerifier {
  constructor() {
    this.jwksCache = null;
    this.jwksCacheTime = null;
    this.JWKS_CACHE_DURATION = parseInt(JWT_CACHE_DURATION) * 1000; // Convert to milliseconds
  }

  /**
   * Debug logging function
   */
  debugLog(message, data = null) {
    if (!JWT_DEBUG_MODE) {
      return;
    }

    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] JWT Debug: ${message}`;
    
    if (data !== null) {
      console.log(logMessage, JSON.stringify(data, null, 2));
    } else {
      console.log(logMessage);
    }
  }

  /**
   * Normalize JWKS by ensuring all keys have required parameters
   */
  normalizeJwks(jwks) {
    this.debugLog("Normalizing JWKS", { original_key_count: jwks.keys.length });
    
    const normalizedKeys = jwks.keys.map(key => {
      const normalizedKey = { ...key };
      
      // Add default algorithm if missing
      if (!normalizedKey.alg || normalizedKey.alg === '') {
        normalizedKey.alg = JWT_DEFAULT_ALG;
        this.debugLog("Added default algorithm to key", {
          kid: key.kid || 'unknown',
          alg: normalizedKey.alg
        });
      }
      
      // Ensure use parameter is set (typically 'sig' for signature verification)
      if (!normalizedKey.use) {
        normalizedKey.use = 'sig';
      }
      
      // Ensure key type is set
      if (!normalizedKey.kty) {
        normalizedKey.kty = 'RSA'; // Default to RSA
      }
      
      return normalizedKey;
    });
    
    const normalizedJwks = { keys: normalizedKeys };
    this.debugLog("JWKS normalization completed", { normalized_key_count: normalizedKeys.length });
    
    return normalizedJwks;
  }

  /**
   * Fetch JWKS from the well-known URL with caching
   */
  async fetchJwks() {
    // Check cache first
    if (this.jwksCache !== null && 
        this.jwksCacheTime !== null && 
        (Date.now() - this.jwksCacheTime) < this.JWKS_CACHE_DURATION) {
      this.debugLog("Using cached JWKS");
      return this.jwksCache;
    }

    this.debugLog("Fetching JWKS from URL", { url: ESIGNET_JWKS_URL });

    try {
      const response = await axios.get(ESIGNET_JWKS_URL, {
        timeout: 30000,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Mock-Relying-Party-Service'
        }
      });

      if (response.status !== 200) {
        this.debugLog("HTTP error fetching JWKS", { 
          status_code: response.status, 
          response: response.data 
        });
        throw new Error(`Failed to fetch JWKS: HTTP ${response.status}`);
      }

      const jwks = response.data;
      if (!jwks.keys || !Array.isArray(jwks.keys)) {
        this.debugLog("Invalid JWKS structure", { jwks });
        throw new Error("Invalid JWKS structure: missing keys array");
      }

      // Normalize the JWKS before caching
      const normalizedJwks = this.normalizeJwks(jwks);

      // Cache the result
      this.jwksCache = normalizedJwks;
      this.jwksCacheTime = Date.now();

      this.debugLog("Successfully fetched and cached JWKS", { 
        key_count: normalizedJwks.keys.length 
      });
      return normalizedJwks;

    } catch (error) {
      this.debugLog("Error fetching JWKS", { error: error.message });
      throw new Error(`Failed to fetch JWKS: ${error.message}`);
    }
  }

  /**
   * Get JWT header without verification
   */
  getJwtHeader(jwt) {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format");
    }

    try {
      const headerBase64 = parts[0];
      const header = JSON.parse(Buffer.from(headerBase64, 'base64').toString());
      return header;
    } catch (error) {
      throw new Error(`Invalid JWT header: ${error.message}`);
    }
  }

  /**
   * Verify and decode JWT using JWKS
   */
  async verifyAndDecodeJwt(jwt, validateExpiration = true) {
    try {
      this.debugLog("Starting JWT verification", { jwt_preview: jwt.substring(0, 50) + '...' });

      // Get JWT header to find the key ID
      const header = this.getJwtHeader(jwt);
      this.debugLog("JWT header decoded", { header });

      const kid = header.kid || null;
      const alg = header.alg || JWT_DEFAULT_ALG;

      this.debugLog("JWT key info", { kid, algorithm: alg });

      // Fetch JWKS
      const jwks = await this.fetchJwks();

      // Find the matching key
      let matchingKey = null;
      for (const key of jwks.keys) {
        this.debugLog("Checking key", {
          key_kid: key.kid || 'N/A',
          key_alg: key.alg || 'N/A',
          target_kid: kid,
          target_alg: alg
        });

        // Match by kid if available, otherwise use the first suitable key
        if (kid === null || !key.kid || key.kid === kid) {
          // Check algorithm compatibility
          if (key.alg && key.alg === alg) {
            matchingKey = key;
            break;
          }
          // Fallback: if no specific algorithm requirement, use the key
          if (!key.alg || key.alg === JWT_DEFAULT_ALG) {
            matchingKey = key;
            break;
          }
        }
      }

      if (matchingKey === null) {
        this.debugLog("No matching key found", { 
          kid, 
          algorithm: alg, 
          available_keys: jwks.keys.length 
        });
        throw new Error(`No matching key found for kid: ${kid} and algorithm: ${alg}`);
      }

      this.debugLog("Found matching key", {
        key_id: matchingKey.kid || 'N/A',
        key_alg: matchingKey.alg || 'N/A'
      });

      // Convert JWKS key to KeyLike format using jose library
      const keyLike = await jose.importJWK(matchingKey, alg);
      
      // Verify the JWT
      const { payload } = await jose.jwtVerify(jwt, keyLike);
      
      this.debugLog("JWT verification successful", { 
        subject: payload.sub || 'unknown' 
      });

      // Additional validation
      if (validateExpiration && payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        this.debugLog("JWT expired", { 
          exp: payload.exp, 
          current_time: Math.floor(Date.now() / 1000) 
        });
        throw new Error("JWT has expired");
      }

      if (payload.iat && payload.iat > Math.floor(Date.now() / 1000) + 300) { // Allow 5 minutes clock skew
        this.debugLog("JWT issued in future", { 
          iat: payload.iat, 
          current_time: Math.floor(Date.now() / 1000) 
        });
        throw new Error("JWT issued in the future");
      }

      this.debugLog("JWT validation completed successfully");
      return {
        data: payload,
        error: null
      };

    } catch (error) {
      this.debugLog("JWT verification failed", { error: error.message });
      return {
        data: null,
        error: {
          message: error.message
        }
      };
    }
  }

  /**
   * Verify userinfo JWT response
   */
  async verifyUserInfoJwt(userInfoJwt) {
    this.debugLog("Verifying userinfo JWT");
    return this.verifyAndDecodeJwt(userInfoJwt);
  }
}

module.exports = new JwtVerifier(); 