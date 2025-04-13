const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
let isoUint8Array, isoBase64URL;

try {
  // Try to load from helpers (newer versions)
  const helpers = require("@simplewebauthn/server/helpers");
  isoUint8Array = helpers.isoUint8Array;
  isoBase64URL = helpers.isoBase64URL;
} catch (err) {
  // Fallback for older versions — helpers not available
  isoUint8Array = {
    fromUTF8String: (str) => Buffer.from(str, 'utf8'),
  };
  isoBase64URL = {
    fromBuffer: (buffer) => buffer.toString('base64url' in Buffer ? 'base64url' : 'base64'),
  };
}
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const axios = require("axios");

const app = express();
app.use(express.json());
app.use(cookieParser());

const CLIENT_URL = ["https://fingerprint-auther-frontend.onrender.com"];
const RP_ID = "fingerprint-auther-frontend.onrender.com"; // Match your Render frontend domain
const DJANGO_API_URL = "https://human-resource-management-ajfy.onrender.com/"; // Your Django server URL

app.use(cors({ origin: CLIENT_URL, credentials: true }));



// Helper function to base64 to buffer
function base64ToBuffer(base64) {
  return Buffer.from(base64, 'base64');
}


app.get("/init-register", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    // 1. Check if user exists in Django
    const djangoResponse = await axios.get(`${DJANGO_API_URL}/check-user?email=${email}`);
    if (djangoResponse.data.exists) {
      return res.status(400).json({ error: "User already exists" });
    }

    // 2. Generate a custom userID (using email as the base)
    const customUserID = `webauthn:${email}`; // Prefix helps identify WebAuthn users
    const userIDBuffer =
      typeof isoUint8Array !== 'undefined' && isoUint8Array.fromUTF8String
        ? isoUint8Array.fromUTF8String(customUserID)
        : Buffer.from(customUserID, 'utf8');


    // 3. Generate WebAuthn options
    const options = await generateRegistrationOptions({
      rpID: RP_ID,
      rpName: "My Local Dev App",
      userID: userIDBuffer, // Proper Uint8Array
      userName: email,
      attestationType: "none",
      excludeCredentials: [],
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
    });

    // 4. Store the registration info
    res.cookie(
      "regInfo",
      JSON.stringify({
        userHandle: isoBase64URL.fromBuffer(userIDBuffer), // Store as base64
        email,
        challenge: options.challenge,
      }),
      { 
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 60000 
      }
    );

    return res.json(options);
    
  } catch (error) {
    console.error("Registration init error:", error);
    return res.status(500).json({ 
      error: "Internal server error",
      details: error.message
    });
  }
});

app.post("/verify-register", async (req, res) => {
  try {
    const regInfo = JSON.parse(req.cookies.regInfo);
    if (!regInfo) {
      return res.status(400).json({ error: "Registration info not found" });
    }

    // Convert stored base64 userHandle back to Uint8Array
    const expectedUserID = isoBase64URL.toBuffer(regInfo.userHandle);

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: regInfo.challenge,
      expectedOrigin: CLIENT_URL,
      expectedRPID: RP_ID,
      expectedUserID: expectedUserID, // Verify against expected user ID
      requireUserVerification: false
    });

    if (verification.verified && verification.registrationInfo) {
      // Decode the userHandle to get our original customUserID
      const customUserID = isoUint8Array.toUTF8String(
        verification.registrationInfo.userID
      );

      // Save to Django
      await axios.post(`${DJANGO_API_URL}/register-credential`, {
        user_id: customUserID,
        email: regInfo.email,
        credential_id: isoBase64URL.fromBuffer(verification.registrationInfo.credentialID),
        public_key: isoBase64URL.fromBuffer(verification.registrationInfo.credentialPublicKey),
        counter: verification.registrationInfo.counter,
        device_type: verification.registrationInfo.credentialDeviceType,
        backed_up: verification.registrationInfo.credentialBackedUp,
        transports: req.body.response.transports || []
      });

      res.clearCookie("regInfo");
      return res.json({ verified: true });
    }
    
    return res.status(400).json({ verified: false, error: "Verification failed" });
  } catch (error) {
    console.error("Verification error:", error);
    return res.status(500).json({ error: error.message });
  }
});

app.get("/init-auth", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    // Check if user exists in Django
    const djangoCheck = await axios.get(`${DJANGO_API_URL}/check-user?email=${email}`);
    if (!djangoCheck.data.exists) {
      return res.status(400).json({ error: "No user for this email" });
    }

    // Get credentials from Django
    const djangoCreds = await axios.get(`${DJANGO_API_URL}/get-credentials?email=${email}`);
    if (!djangoCreds.data.credentials || djangoCreds.data.credentials.length === 0) {
      return res.status(400).json({ error: "No credentials registered for this user" });
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: djangoCreds.data.credentials.map(cred => ({
        id: base64ToBuffer(cred.id),
        type: "public-key",
        transports: cred.transports
      })),
    });

    res.cookie(
      "authInfo",
      JSON.stringify({
        email,
        challenge: options.challenge,
      }),
      { httpOnly: true, maxAge: 60000, secure: true }
    );

    res.json(options);
  } catch (error) {
    console.error("Error in /init-auth:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/verify-auth", async (req, res) => {
  const authInfo = JSON.parse(req.cookies.authInfo);

  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  try {
    // Get user credentials from Django
    const djangoCreds = await axios.get(`${DJANGO_API_URL}/get-credentials?email=${authInfo.email}`);
    if (!djangoCreds.data.credentials || djangoCreds.data.credentials.length === 0) {
      return res.status(400).json({ error: "No credentials found for this user" });
    }

    // Find the matching credential
    const credential = djangoCreds.data.credentials.find(cred => 
      bufferToBase64(req.body.id) === cred.id
    );

    if (!credential) {
      return res.status(400).json({ error: "Invalid credential" });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: authInfo.challenge,
      expectedOrigin: CLIENT_URL,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: base64ToBuffer(credential.id),
        credentialPublicKey: base64ToBuffer(credential.public_key),
        counter: credential.counter,
        transports: credential.transports,
      },
    });

    if (verification.verified) {
      // Update counter in Django
      await axios.post(`${DJANGO_API_URL}/update-counter`, {
        email: authInfo.email,
        credential_id: bufferToBase64(req.body.id),
        new_counter: verification.authenticationInfo.newCounter
      });

      res.clearCookie("authInfo");
      return res.json({ verified: verification.verified });
    } else {
      return res.status(400).json({ verified: false, error: "Verification failed" });
    }
  } catch (error) {
    console.error("Error in /verify-auth:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});