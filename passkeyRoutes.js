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

// ✅ FOR LOCAL TESTING (Use this when running on localhost:3000)
const RP_ID = 'localhost'; 
const ORIGIN = 'http://localhost:3000'; 

const RP_ID = 'acadexonline.in'; 
const ORIGIN = 'https://acadexonline.in';

// 🚀 FOR PRODUCTION (Uncomment and use this when you deploy to the web)
// const RP_ID = 'scheduplan-1b51d.web.app'; 
// const ORIGIN = 'https://scheduplan-1b51d.web.app'; 

// ------------------------------------------------------------------------

const challengeStore = {}; 

// 1. REGISTRATION (SETUP)
router.get('/register-start', async (req, res) => {
    const { userId } = req.query;
    if(!userId) return res.status(400).json({ error: "User ID required" });
    
    try {
        const userDoc = await db.collection('users').doc(userId).get();
        if (!userDoc.exists) return res.status(404).json({ error: "User not found" });
        const user = userDoc.data() || {};

        // Generate options
        const options = await generateRegistrationOptions({
            rpName: 'AcadeX App',
            rpID: RP_ID, // Must match browser domain
            userID: String(userId),
            userName: user.email || 'User',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
                authenticatorAttachment: 'platform', // Forces TouchID/FaceID
            },
        });

        challengeStore[userId] = options.challenge;
        res.json(options);

    } catch (error) {
        console.error("🔒 REGISTRATION START ERROR:", error);
        res.status(500).json({ error: error.message });
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
            expectedOrigin: ORIGIN, // Must match browser URL
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

            // Save to DB
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
        
        // Find the authenticator in DB
        const authData = user.authenticators.find(auth => auth.credentialID === data.id);
        if (!authData) return res.status(400).send('Authenticator not found');

        const authenticator = {
            ...authData,
            credentialPublicKey: Buffer.from(authData.credentialPublicKey, 'base64')
        };

        const verification = await verifyAuthenticationResponse({
            response: data,
            expectedChallenge,
            expectedOrigin: ORIGIN, // Strictly checks http://localhost:3000
            expectedRPID: RP_ID,
            authenticator,
        });

        if (verification.verified) {
            // Update counter to prevent replay attacks
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
