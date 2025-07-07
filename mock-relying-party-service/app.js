const express = require("express");
const { PORT } = require("./config");
const { post_GetToken, get_GetUserInfo } = require("./esignetService");
const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Welcome to Mock Relying Party REST APIs!!");
});

//Token Request Handler
app.post("/fetchUserInfo", async (req, res) => {
  try {
    const tokenResponse = await post_GetToken(req.body);
    const userInfoResponse = await get_GetUserInfo(tokenResponse.access_token);
    
    // Create verification badge
    const tokenVerified = tokenResponse.tokenVerification?.verified || false;
    const userInfoVerified = userInfoResponse.userInfoVerification?.verified || false;
    
    const verificationBadge = {
      status: tokenVerified && userInfoVerified ? "VERIFIED" : "VERIFICATION_FAILED",
      message: tokenVerified && userInfoVerified ? "Signature Verification Passed" : "Signature Verification Failed",
      details: {
        tokenVerification: tokenResponse.tokenVerification,
        userInfoVerification: userInfoResponse.userInfoVerification
      }
    };

    // Send response with user info and verification badge
    res.json({
      ...userInfoResponse.userInfo,
      _verificationBadge: verificationBadge
    });
  } catch (error) {
    console.log(error)
    res.status(500).send(error);
  }
});

//PORT ENVIRONMENT VARIABLE
const port = PORT;
app.listen(port, () => console.log(`Listening on port ${port}..`));
