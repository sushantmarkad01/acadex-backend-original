const express = require('express');
const router = express.Router();
const admin = require('firebase-admin'); 
const { 
  generateRegistrationOptions, 
  verifyRegistrationResponse, 
  generateAuthenticationOptions, 
  verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const db = admin.firestore();

// ------------------------------------------------------------------------
// ⚠️ CONFIGURATION: DOMAIN & ORIGIN
// ------------------------------------------------------------------------

// ✅ PRODUCTION SETTINGS (For acadexonline.in)
const RP_ID = 'acadexonline.in'; 
const ORIGIN = 'https://acadexonline.in'; 

// 🛠️ FOR LOCAL TESTING (Comment out production settings and use these for localhost)
// const RP_ID = 'localhost'; 
// const ORIGIN = 'http://localhost:3000'; 

// ------------------------------------------------------------------------

const challengeStore = {}; 

// 1. REGISTRATION (SETUP)
// 1. REGISTRATION (SETUP) - UPDATED FOR PRODUCTION
router.get('/register-start', async (req, res) => {
    const { userId } = req.query;
    if(!userId) return res.status(400).json({ error: "User ID required" });
    
    try {
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) return res.status(404).json({ error: "User not found" });
        const user = userDoc.data() || {};

        // ✅ Robust Options Generation
        const options = await generateRegistrationOptions({
            rpName: 'AcadeX',
            rpID: 'acadexonline.in', // Must be the domain only
            userID: userId,          // Simplewebauthn will handle string IDs
            userName: user.email || 'User',
            userDisplayName: `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Student',
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
                authenticatorAttachment: 'platform', // Forces phone biometric (TouchID/FaceID)
            },
        });

        // Store challenge temporarily
        challengeStore[userId] = options.challenge;
        res.json(options);

    } catch (error) {
        // ✅ Check your Render/Backend logs for this specific message
        console.error("❌ BACKEND CRASH DURING REGISTER-START:", error);
        res.status(500).json({ error: "Server failed to generate security challenge: " + error.message });
    }
});

// 2. VERIFY REGISTRATION
router.post('/register-finish', async (req, res) => {
    const { userId, data } = req.body;
    const expectedChallenge = challengeStore[userId];

    if (!expectedChallenge) return res.status(400).json({ error: 'Challenge expired. Try again.' });

    try {
        const verification = await verifyRegistrationResponse({
            response: data,
            expectedChallenge,
            expectedOrigin: ORIGIN, 
            expectedRPID: RP_ID,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;

            const newAuthenticator = {
                credentialID: registrationInfo.credentialID,
                credentialPublicKey: registrationInfo.credentialPublicKey.toString('base64'),
                counter: registrationInfo.counter,
                transports: registrationInfo.transports || [] 
            };

            await db.collection('users').doc(userId).update({
                authenticators: admin.firestore.FieldValue.arrayUnion(newAuthenticator)
            });

            delete challengeStore[userId];
            res.json({ verified: true });
        } else {
            console.error("🔒 VERIFICATION FAILED: Signature Invalid");
            res.status(400).json({ verified: false, error: "Signature Invalid" });
        }
    } catch (error) {
        console.error("🔒 VERIFY ERROR:", error);
        res.status(400).json({ error: error.message });
    }
});

// 3. LOGIN START
router.get('/login-start', async (req, res) => {
    const { userId } = req.query;
    try {
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) return res.status(404).json({ error: 'User not found' });
        const user = userDoc.data();

        if (!user.authenticators || user.authenticators.length === 0) {
            return res.status(400).json({ error: 'No passkeys registered' });
        }

        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: user.authenticators.map(auth => ({
                id: auth.credentialID,
                type: 'public-key',
                transports: auth.transports,
            })),
            userVerification: 'preferred',
        });

        challengeStore[userId] = options.challenge;
        res.json(options);
    } catch (error) {
        console.error("🔒 LOGIN START ERROR:", error);
        res.status(500).json({ error: error.message });
    }
});

// 4. LOGIN FINISH
router.post('/login-finish', async (req, res) => {
    const { userId, data } = req.body;
    try {
        const userDoc = await db.collection('users').doc(userId).get();
        const user = userDoc.data();
        const expectedChallenge = challengeStore[userId];
        
        const authData = user.authenticators.find(auth => auth.credentialID === data.id);
        if (!authData) return res.status(400).send('Authenticator not found');

        const authenticator = {
            ...authData,
            credentialPublicKey: Buffer.from(authData.credentialPublicKey, 'base64')
        };

        const verification = await verifyAuthenticationResponse({
            response: data,
            expectedChallenge,
            expectedOrigin: ORIGIN, 
            expectedRPID: RP_ID,
            authenticator,
        });

        if (verification.verified) {
            const updatedAuths = user.authenticators.map(auth => {
                if (auth.credentialID === data.id) {
                    return { ...auth, counter: verification.authenticationInfo.newCounter };
                }
                return auth;
            });
            await db.collection('users').doc(userId).update({ authenticators: updatedAuths });

            delete challengeStore[userId];
            res.json({ verified: true });
        } else {
            console.error("🔒 LOGIN FAILED: Signature Mismatch");
            res.status(400).json({ verified: false });
        }
    } catch (error) {
        console.error("🔒 LOGIN FINISH ERROR:", error);
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
