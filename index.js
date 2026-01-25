const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const multer = require('multer'); // 1. Import Multer
const cloudinary = require('cloudinary').v2; //  2. Import Cloudinary
const rateLimit = require('express-rate-limit'); //  3. Import Rate Limiter
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { callGroqAI, computeHash, isUnsafe, MODEL_ID } = require('./lib/groqClient'); 

require('dotenv').config(); 

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const taskLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, // 15 mins
    max: 20, 
    message: { error: "Too many tasks generated. Slow down!" } 
});

// --- Helper: Send Notification ---
const sendNotification = async (userId, title, body) => {
    try {
        const userDoc = await admin.firestore().collection('users').doc(userId).get();
        const fcmToken = userDoc.data()?.fcmToken;

        if (fcmToken) {
            await admin.messaging().send({
                token: fcmToken,
                notification: {
                    title: title,
                    body: body
                },
                // Android specific settings for priority
                android: {
                    priority: 'high',
                    notification: {
                        sound: 'default',
                        channelId: 'default'
                    }
                }
            });
            console.log(`Notification sent to ${userId}`);
        }
    } catch (error) {
        console.error("Notification Error:", error.message);
    }
};

// --- RATE LIMITER CONFIG ---
// Limit requests to 60 per minute per IP to prevent abuse
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 60,
  message: { error: "Too many requests, please try again later." }
});
app.use(limiter);

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10,
  message: { error: "Verification limit reached. Please wait 15 minutes." }
});

// --- 1. MULTER CONFIG (RAM Storage) ---
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB Limit
});

// --- 2. CLOUDINARY CONFIG ---
// Ensure these are in your Render Environment Variables
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

// --- 3. FIREBASE ADMIN SETUP ---
function initFirebaseAdmin() {
  const svcEnv = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (svcEnv) {
    try {
      const svcJson = (/^[A-Za-z0-9+/=]+\s*$/.test(svcEnv) && svcEnv.length > 1000)
        ? JSON.parse(Buffer.from(svcEnv, 'base64').toString('utf8'))
        : JSON.parse(svcEnv);
      admin.initializeApp({ credential: admin.credential.cert(svcJson) });
      console.log("Firebase Admin initialized.");
      return;
    } catch (err) { console.error(err); process.exit(1); }
  }
  try {
    const local = require('./serviceAccountKey.json');
    admin.initializeApp({ credential: admin.credential.cert(local) });
  } catch (err) { console.error(err); process.exit(1); }
}
initFirebaseAdmin();

const passkeyRoutes = require('./passkeyRoutes');
app.use('/auth/passkeys', passkeyRoutes);

// --- HELPER: Send Push Notification ---
async function sendNotification(userId, title, body) {
    try {
        const userDoc = await admin.firestore().collection('users').doc(userId).get();
        const fcmToken = userDoc.data()?.fcmToken;

        if (fcmToken) {
            await admin.messaging().send({
                token: fcmToken,
                notification: { title, body },
                android: { priority: 'high' }
            });
            console.log(`🔔 Notification sent to ${userId}`);
        }
    } catch (error) {
        console.error("Notification failed:", error.message);
    }
}

// --- UTILITIES & HELPERS ---

const DEMO_MODE = (process.env.DEMO_MODE || 'true') === 'true';
const ACCEPTABLE_RADIUS_METERS = Number(process.env.ACCEPTABLE_RADIUS_METERS || 200);
function getDistance(lat1, lon1, lat2, lon2) {
  const toRad = (x) => (x * Math.PI) / 180;
  const R = 6371000; 
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Helper: Upload to Cloudinary
async function uploadToCloudinary(fileBuffer) {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { folder: "acadex_docs", resource_type: "auto" }, // auto detects PDF/Img
            (error, result) => {
                if (error) reject(error);
                else resolve(result.secure_url);
            }
        );
        stream.end(fileBuffer);
    });
}

// Helper: Recursive Delete (For cleaning up Institutes)
async function deleteCollection(db, collectionPath, batchSize, queryField, queryValue) {
  const collectionRef = db.collection(collectionPath);
  const query = collectionRef.where(queryField, '==', queryValue).limit(batchSize);
  return new Promise((resolve, reject) => {
    deleteQueryBatch(db, query, resolve).catch(reject);
  });
}

async function deleteQueryBatch(db, query, resolve) {
  const snapshot = await query.get();
  if (snapshot.size === 0) { resolve(); return; }
  const batch = db.batch();
  snapshot.docs.forEach((doc) => { batch.delete(doc.ref); });
  await batch.commit();
  process.nextTick(() => { deleteQueryBatch(db, query, resolve); });
}

// Helper: Badge Logic
const BADGE_RULES = [
    { id: 'novice', threshold: 100 },
    { id: 'enthusiast', threshold: 500 },
    { id: 'expert', threshold: 1000 },
    { id: 'master', threshold: 2000 }
];

async function checkAndAwardBadges(userRef, currentXp, currentBadges = []) {
    let newBadges = [];
    BADGE_RULES.forEach(badge => {
        if (currentXp >= badge.threshold && !currentBadges.includes(badge.id)) {
            newBadges.push(badge.id);
        }
    });
    if (newBadges.length > 0) {
        await userRef.update({ badges: admin.firestore.FieldValue.arrayUnion(...newBadges) });
        return newBadges; 
    }
    return [];
}

// =======================
//   ROBUST STUDY ROUTES (NEW)
// =======================

// A. Topic Capture Flow
app.post('/storeTopic', async (req, res) => {
  try {
    const { userId, topic } = req.body;
    if (!userId || !topic) return res.status(400).json({ error: "Missing fields" });

    if (isUnsafe(topic)) return res.status(400).json({ error: "Topic violates safety guidelines." });

    const topicId = computeHash(topic.toLowerCase().trim());
    const userRef = admin.firestore().collection('users').doc(userId);
    
    // Update User's Latest Topic
    await userRef.update({
      latestTopic: {
        topicId,
        topicName: topic,
        storedAt: admin.firestore.FieldValue.serverTimestamp()
      }
    });

    // Store Topic in Sub-collection History
    await userRef.collection('topics').doc(topicId).set({
      topicName: topic,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      source: 'user_input'
    }, { merge: true });

    res.json({ ok: true, topicId });
  } catch (err) {
    console.error("StoreTopic Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// B. Generate or Return Cached Notes
app.get('/notes', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: "User ID required" });

    // 1. Get User's Latest Topic
    const userSnap = await admin.firestore().collection('users').doc(userId).get();
    const latestTopic = userSnap.data()?.latestTopic;

    if (!latestTopic || !latestTopic.topicName) {
      return res.status(400).json({ error: "No active topic found. Please set a topic first." });
    }

    const topicName = latestTopic.topicName;
    // Cache Key: Hash of topic + 'notes' + modelVersion
    const cacheKey = computeHash(`${topicName}_notes_${MODEL_ID}`);

    // 2. Check Cache
    const noteRef = admin.firestore().collection('notes').doc(cacheKey);
    const noteSnap = await noteRef.get();

    if (noteSnap.exists) {
      return res.json({ fromCache: true, note: noteSnap.data() });
    }

    // 3. Generate via Groq
    const systemPrompt = `You are an educational assistant for students aged 16-22. Produce concise, accurate study notes.`;
    const userPrompt = `Generate short study notes for the topic: "${topicName}".
    Constraints:
    - Length: 200-350 words.
    - Format: short intro, 3 bullet points (key ideas), 1 worked example, 2 practice questions.
    - End with one-line summary.
    Return ONLY the content string.`;

    const generatedContent = await callGroqAI(systemPrompt, userPrompt, false);

    // 4. Save to Firestore
    const noteData = {
      topicName,
      content: generatedContent,
      generatedAt: admin.firestore.FieldValue.serverTimestamp(),
      generatedForUserId: userId,
      prompt: userPrompt,
      modelVersion: MODEL_ID,
      hash: cacheKey
    };

    await noteRef.set(noteData);

    res.json({ fromCache: false, note: noteData });

  } catch (err) {
    console.error("GetNotes Error:", err);
    res.status(500).json({ error: "Failed to generate notes." });
  }
});



// Route: Start Session & Notify Students
app.post('/startSession', async (req, res) => {
    try {
        const { teacherId, teacherName, subject, department, year, location, instituteId } = req.body;

        // 1. Create Session in Firestore
        const sessionRef = await admin.firestore().collection('live_sessions').add({
            teacherId,
            teacherName,
            subject,
            department,
            targetYear: year,
            location, // { latitude, longitude }
            instituteId,
            isActive: true,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // 2. Notify Students (Background Process)
        // Find all students in this Dept + Year
        const studentsSnap = await admin.firestore().collection('users')
            .where('instituteId', '==', instituteId)
            .where('role', '==', 'student')
            .where('department', '==', department)
            .where('year', '==', year)
            .get();

        const tokens = [];
        studentsSnap.forEach(doc => {
            const data = doc.data();
            if (data.fcmToken) tokens.push(data.fcmToken);
        });

        if (tokens.length > 0) {
            // Send Batch Notification
            await admin.messaging().sendEachForMulticast({
                tokens: tokens,
                notification: {
                    title: `🔴 Class Started: ${subject}`,
                    body: `${teacherName} has started the class. Tap to mark attendance!`
                },
                android: { priority: 'high' }
            });
            console.log(`📢 Notified ${tokens.length} students about ${subject}`);
        }

        return res.json({ message: "Session started & students notified!", sessionId: sessionRef.id });

    } catch (err) {
        console.error("Start Session Error:", err);
        return res.status(500).json({ error: err.message });
    }
});

// D. Quiz Attempt Recording
app.post('/quizAttempt', async (req, res) => {
  try {
    const { userId, quizId, answers, score } = req.body;
    
    if (!userId || !quizId) return res.status(400).json({ error: "Invalid data" });

    const attemptData = {
      quizId,
      score,
      answers: answers || [], // [{ questionIndex: 0, selectedIndex: 1, correct: false }]
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await admin.firestore().collection('userProgress').doc(userId)
                  .collection('attempts').add(attemptData);

    // Optional: Update XP if score is good (Simple Gamification)
    if (score > 60) {
        const userRef = admin.firestore().collection('users').doc(userId);
        await userRef.update({ xp: admin.firestore.FieldValue.increment(20) });
    }

    res.json({ ok: true, attemptId: docRef.id });

  } catch (err) {
    console.error("QuizAttempt Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// =======================
//   LEGACY ROUTES
// =======================

app.get('/health', (req, res) => res.json({ status: 'ok', demoMode: DEMO_MODE }));

// 1. Create User (Updated to save assignedClasses)
app.post('/createUser', async (req, res) => {
  try {
    const { 
        email, 
        password, 
        firstName, 
        lastName, 
        role, 
        instituteId, 
        instituteName, 
        department, 
        subject, 
        rollNo, 
        qualification,
        assignedClasses, // ✅ EXTRACT THIS FROM REQUEST
        extras = {} 
    } = req.body;

    // Create user in Firebase Auth
    const userRecord = await admin.auth().createUser({ 
        email, 
        password, 
        displayName: `${firstName} ${lastName}` 
    });

    // Prepare Firestore Document
    const userDoc = { 
        uid: userRecord.uid, 
        email, 
        role, 
        firstName, 
        lastName, 
        instituteId, 
        instituteName, 
        department: department || null, 
        subject: subject || null, // Legacy fallback
        assignedClasses: assignedClasses || [], // ✅ SAVE THIS ARRAY TO FIRESTORE
        rollNo: rollNo || null, 
        qualification: qualification || null,
        xp: 0, 
        badges: [], 
        createdAt: admin.firestore.FieldValue.serverTimestamp(), 
        ...extras 
    };

    // Save to 'users' collection
    await admin.firestore().collection('users').doc(userRecord.uid).set(userDoc);
    
    // Set Custom Claims
    await admin.auth().setCustomUserClaims(userRecord.uid, { role, instituteId });

    return res.json({ message: 'User created successfully', uid: userRecord.uid });

  } catch (err) { 
    return res.status(500).json({ error: err.message }); 
  }
});

// New route for Bulk Student Creation
// --- Route: Bulk Create Students (Matches 'collegeId') ---
app.post('/bulkCreateStudents', async (req, res) => {
    try {
        const { students, instituteId, instituteName } = req.body;
        const results = { success: [], errors: [] };

        for (const student of students) {
            if (!student.email) continue; 

            try {
                const nameParts = student.name ? student.name.trim().split(" ") : ["Student"];
                const firstName = nameParts[0]; 
                const lastName = nameParts.length > 1 ? nameParts.slice(1).join(" ") : "";

                const tempPassword = Math.random().toString(36).slice(-10);
                const userRecord = await admin.auth().createUser({
                    email: student.email,
                    password: tempPassword,
                    displayName: student.name
                });

                await admin.firestore().collection('users').doc(userRecord.uid).set({
                    uid: userRecord.uid,
                    email: student.email,
                    firstName: firstName,
                    lastName: lastName,
                    
                    // ✅ Mapped correctly now
                    rollNo: student.rollNo || '',
                    collegeId: student.collegeId || '', // Saved as collegeId in Firestore
                    gender: student.gender || '',
                    category: student.category || '',
                    admissionType: student.admissionType || '',
                    
                    department: student.department || 'General',
                    year: student.year || 'FE',
                    
                    role: 'student',
                    instituteId,
                    instituteName,
                    attendanceCount: 0,
                    xp: 0,
                    badges: [],
                    createdAt: admin.firestore.FieldValue.serverTimestamp()
                });

                await admin.auth().setCustomUserClaims(userRecord.uid, { 
                    role: 'student', 
                    instituteId 
                });

                results.success.push(student.email);

            } catch (err) {
                console.error(`Failed: ${student.email}`, err.message);
                results.errors.push({ email: student.email, error: err.message });
            }
        }

        res.json(results);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Updated /markAttendance route for backend/index.js
app.post('/markAttendance', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    const decoded = await admin.auth().verifyIdToken(token);
    const studentUid = decoded.uid;
    
    // Extract deviceId from request body
    const { sessionId, studentLocation, deviceId } = req.body; 

    if (!deviceId) {
        return res.status(400).json({ error: 'Security Error: Device ID is missing.' });
    }

    // 1. Dynamic QR Check (Parsing session ID and timestamp)
    const [realSessionId, timestamp] = sessionId.split('|');
    if (!realSessionId) return res.status(400).json({ error: 'Invalid QR Code' });

    if (timestamp) {
        const qrTime = parseInt(timestamp);
        const timeDiff = (Date.now() - qrTime) / 1000;
        // Strict 15-second window to prevent photo sharing
        if (timeDiff > 15) return res.status(400).json({ error: 'QR Code Expired!' });
    }

    const sessionRef = admin.firestore().collection('live_sessions').doc(realSessionId);
    const sessionSnap = await sessionRef.get();
    if (!sessionSnap.exists || !sessionSnap.data().isActive) {
        return res.status(404).json({ error: 'Session not active' });
    }

    const session = sessionSnap.data();
    
    // 2. Geo-Location Check (Ensure student is in the classroom)
    if (!DEMO_MODE) {
        if (!session.location || !studentLocation) {
            return res.status(400).json({ error: 'Location data missing' });
        }
        const dist = getDistance(
            session.location.latitude, 
            session.location.longitude, 
            studentLocation.latitude, 
            studentLocation.longitude
        );
        if (dist > ACCEPTABLE_RADIUS_METERS) {
            return res.status(403).json({ error: `Too far! You are ${Math.round(dist)}m away.` });
        }
    }

    const userRef = admin.firestore().collection('users').doc(studentUid);
    const userDoc = await userRef.get();
    const studentData = userDoc.data();

    // 3. CRITICAL SECURITY: DEVICE LOCKING
    // Check if this physical device has already marked attendance for THIS session
    const deviceCheck = await admin.firestore().collection('attendance')
        .where('sessionId', '==', realSessionId)
        .where('deviceId', '==', deviceId)
        .limit(1).get();

    if (!deviceCheck.empty) {
        const existingRecord = deviceCheck.docs[0].data();
        // If the device was used by a DIFFERENT student ID, reject it
        if (existingRecord.studentId !== studentUid) {
            return res.status(403).json({ 
                error: "Security Violation: This device has already been used to mark attendance for another student in this session." 
            });
        }
    }

    // 4. (Optional) ACCOUNT BINDING: Lock student account to one device forever
    if (studentData.boundDeviceId && studentData.boundDeviceId !== deviceId) {
        return res.status(403).json({ 
            error: "Device Mismatch: You can only mark attendance from your registered device." 
        });
    } else if (!studentData.boundDeviceId) {
        // Bind the device to the account on the first successful use
        await userRef.update({ boundDeviceId: deviceId });
    }

    // 5. Create Attendance Receipt
    await admin.firestore().collection('attendance').doc(`${realSessionId}_${studentUid}`).set({
      sessionId: realSessionId,
      deviceId: deviceId, // Store the device ID in the receipt
      subject: session.subject || 'Class',
      studentId: studentUid,
      studentEmail: studentData.email,
      firstName: studentData.firstName,
      lastName: studentData.lastName,
      rollNo: studentData.rollNo,
      instituteId: studentData.instituteId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'Present'
    });

    // 6. Update Stats
    await userRef.update({
        attendanceCount: admin.firestore.FieldValue.increment(1)
    });

    return res.json({ message: 'Attendance Marked Successfully!' });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

// Route: Reset Device Lock (For Teachers/Admins to unlock a student)
app.post('/resetDevice', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    // Verify requester is authorized (Teacher or Admin)
    const decoded = await admin.auth().verifyIdToken(token);
    const requesterRef = await admin.firestore().collection('users').doc(decoded.uid).get();
    const requesterData = requesterRef.data();

    if (!requesterData || (requesterData.role !== 'teacher' && requesterData.role !== 'institute-admin' && requesterData.role !== 'super-admin')) {
        return res.status(403).json({ error: "Unauthorized: Only teachers/admins can reset devices." });
    }

    const { studentId } = req.body;
    if (!studentId) return res.status(400).json({ error: "Student ID required" });

    // Delete the device lock
    await admin.firestore().collection('users').doc(studentId).update({
        registeredDeviceId: admin.firestore.FieldValue.delete(),
        deviceRegisteredAt: admin.firestore.FieldValue.delete()
    });

    return res.json({ message: "Device lock reset successfully. Student can now link a new device." });

  } catch (err) {
    console.error("Reset Device Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 4. Generate Notes
app.post('/generateNotes', async (req, res) => {
  try {
    const { topic, department, level } = req.body;
    const apiKey = process.env.GROQ_API_KEY;
    const systemPrompt = `Create structured notes on: ${topic}. Level: ${level}. Use Markdown.`;
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST", headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "system", content: systemPrompt }], model: "llama-3.3-70b-versatile" })
    });
    const data = await response.json();
    res.json({ notes: data.choices?.[0]?.message?.content || "Failed." });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

// 5. Generate MCQs
app.post('/generateMCQs', async (req, res) => {
  try {
    const { topic, count, department } = req.body;
    const apiKey = process.env.GROQ_API_KEY;
    const systemPrompt = `Create ${count} MCQs on "${topic}". Output strict JSON format: { "mcqs": [{ "q": "...", "options": ["A", "B", "C", "D"], "answerIndex": 0, "explanation": "..." }] }`;
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST", headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ role: "system", content: systemPrompt }], model: "llama-3.3-70b-versatile", response_format: { type: "json_object" } })
    });
    const data = await response.json();
    const cleanJson = data.choices[0].message.content.replace(/```json|```/g, '').trim();
    res.json(JSON.parse(cleanJson));
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

// 6. Complete Task
app.post('/completeTask', async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return res.status(400).json({ error: 'UID missing' });
    const userRef = admin.firestore().collection('users').doc(uid);
    const userSnap = await userRef.get();
    const userData = userSnap.data();
    const now = admin.firestore.Timestamp.now();
    const lastTime = userData.lastTaskTime;
    if (lastTime && (now.toMillis() - lastTime.toMillis()) / (1000 * 60) < 15) return res.status(429).json({ error: `Wait a few minutes!` });
    const newXp = (userData.xp || 0) + 50;
    await userRef.update({ xp: newXp, lastTaskTime: now });
    const newBadges = await checkAndAwardBadges(userRef, newXp, userData.badges);
    return res.json({ message: 'Task Verified! +50 XP', newBadges });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 7. Generate Roadmap
app.post('/generateRoadmap', async (req, res) => {
    try {
        const { goal, department } = req.body;
        const apiKey = process.env.GROQ_API_KEY;
        const systemPrompt = `Create 4-Week Roadmap for ${goal}. Output JSON: { "weeks": [{ "week": 1, "theme": "...", "topics": ["..."] }] }`;
        const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
            method: "POST", headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
            body: JSON.stringify({ messages: [{ role: "system", content: systemPrompt }], model: "llama-3.3-70b-versatile", response_format: { type: "json_object" } })
        });
        const data = await response.json();
        const cleanJson = data.choices[0].message.content.replace(/```json|```/g, '').trim();
        res.json({ roadmap: JSON.parse(cleanJson) });
    } catch (error) { res.status(500).json({ error: "Failed" }); }
});

// 8. Submit Application ( HANDLES CLOUDINARY UPLOAD)
app.post('/submitApplication', upload.single('document'), async (req, res) => {
  try {
    const { instituteName, contactName, email, phone, message } = req.body;
    const file = req.file; 

    let documentUrl = null;

    // If a file exists, upload to Cloudinary
    if (file) {
        try {
            documentUrl = await uploadToCloudinary(file.buffer);
        } catch (uploadError) {
            console.error("Cloudinary Upload Failed:", uploadError);
            return res.status(500).json({ error: "Document upload failed" });
        }
    }

    // Save to Firestore
    await admin.firestore().collection('applications').add({
      instituteName,
      contactName,
      email,
      phone: phone || '',
      message: message || '',
      documentUrl: documentUrl, 
      status: 'pending',
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ message: 'Application submitted successfully!' });

  } catch (err) {
    console.error("Submission Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 9. Delete Users (Batch)
app.post('/deleteUsers', async (req, res) => {
  try {
    const { userIds } = req.body;
    if (!userIds || userIds.length === 0) return res.status(400).json({ error: 'No users selected' });
    try { await admin.auth().deleteUsers(userIds); } catch (e) { console.error(e); }
    const batch = admin.firestore().batch();
    userIds.forEach(uid => batch.delete(admin.firestore().collection('users').doc(uid)));
    await batch.commit();
    return res.json({ message: `Processed deletion.` });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 10. Delete Department
app.post('/deleteDepartment', async (req, res) => {
  try {
    const { deptId } = req.body;
    await admin.firestore().collection('departments').doc(deptId).delete();
    return res.json({ message: 'Deleted.' });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 11. Submit Student Request
// 11. Submit Student Request (Updated with Duplicate Checks)
app.post('/submitStudentRequest', async (req, res) => {
    try {
        const { firstName, lastName, email, rollNo, department, year, semester, collegeId, password, instituteId, instituteName } = req.body;
        
        // --- 1. Check for Duplicates in Active Users ---
        // A. Check College ID
        if (collegeId) {
            const activeColId = await admin.firestore().collection('users')
                .where('instituteId', '==', instituteId)
                .where('collegeId', '==', collegeId).get();
            if (!activeColId.empty) return res.status(400).json({ error: `College ID "${collegeId}" is already registered.` });
        }

        // B. Check Roll No (in same Department)
        if (rollNo && department) {
            const activeRoll = await admin.firestore().collection('users')
                .where('instituteId', '==', instituteId)
                .where('department', '==', department)
                .where('rollNo', '==', rollNo).get();
            if (!activeRoll.empty) return res.status(400).json({ error: `Roll No. ${rollNo} already exists in ${department}.` });
        }

        // --- 2. Check for Duplicates in Pending Requests ---
        // A. Check College ID in Requests
        const pendingColId = await admin.firestore().collection('student_requests')
            .where('instituteId', '==', instituteId)
            .where('collegeId', '==', collegeId)
            .where('status', '==', 'pending').get(); // Only check pending ones
        if (!pendingColId.empty) return res.status(400).json({ error: `A request with College ID "${collegeId}" is already pending.` });

        // B. Check Roll No in Requests
        const pendingRoll = await admin.firestore().collection('student_requests')
            .where('instituteId', '==', instituteId)
            .where('department', '==', department)
            .where('rollNo', '==', rollNo)
            .where('status', '==', 'pending').get();
        if (!pendingRoll.empty) return res.status(400).json({ error: `A request for Roll No. ${rollNo} is already pending.` });

        // --- 3. Proceed to Save Request ---
        const requestsRef = admin.firestore().collection('student_requests');
        await requestsRef.add({ 
            firstName, lastName, email, rollNo, department, year, semester, 
            collegeId, password, instituteId, instituteName, 
            status: 'pending', 
            createdAt: admin.firestore.FieldValue.serverTimestamp() 
        });
        
        return res.json({ message: 'Success' });

    } catch (err) { 
        return res.status(500).json({ error: err.message }); 
    }
});

// 13. Action Leave
app.post('/actionLeave', async (req, res) => {
  try {
    const { leaveId, status } = req.body; 
    await admin.firestore().collection('leave_requests').doc(leaveId).update({ status });
    return res.json({ message: `Leave request ${status}.` });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 14. End Session
app.post('/endSession', async (req, res) => {
  try {
    const { sessionId } = req.body;
    const sessionRef = admin.firestore().collection('live_sessions').doc(sessionId);
    const sessionSnap = await sessionRef.get();
    if (!sessionSnap.exists) return res.status(404).json({ error: "Session not found" });
    if (sessionSnap.data().isActive) {
        await sessionRef.update({ isActive: false });
        const { instituteId, department } = sessionSnap.data();
        if (instituteId && department) {
            const statsRef = admin.firestore().collection('department_stats').doc(`${instituteId}_${department}`);
            await statsRef.set({ totalClasses: admin.firestore.FieldValue.increment(1), instituteId, department }, { merge: true });
        }
    }
    return res.json({ message: "Session Ended." });
  } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 15. Get Analytics
app.post('/getAttendanceAnalytics', async (req, res) => {
    try {
        const { instituteId, subject } = req.body;
        const now = new Date();
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(now.getDate() - 7);
        const snapshot = await admin.firestore().collection('attendance')
            .where('instituteId', '==', instituteId).where('subject', '==', subject).where('timestamp', '>=', sevenDaysAgo).get();
        const counts = { 'Mon': 0, 'Tue': 0, 'Wed': 0, 'Thu': 0, 'Fri': 0, 'Sat': 0, 'Sun': 0 };
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        snapshot.forEach(doc => { counts[days[doc.data().timestamp.toDate().getDay()]]++; });
        return res.json({ chartData: Object.keys(counts).map(key => ({ name: key, present: counts[key] })) });
    } catch (err) { return res.status(500).json({ error: "Failed" }); }
});

// 16. DELETE INSTITUTE (Cascading - Super Admin Only)
app.post('/deleteInstitute', async (req, res) => {
  try {
    const { instituteId } = req.body;
    if (!instituteId) return res.status(400).json({ error: 'Missing Institute ID' });

    // A. Users
    const usersSnap = await admin.firestore().collection('users').where('instituteId', '==', instituteId).get();
    const uids = [];
    usersSnap.forEach(doc => uids.push(doc.id));

    // B. Auth Delete
    if (uids.length > 0) {
      const chunks = [];
      for (let i = 0; i < uids.length; i += 1000) chunks.push(uids.slice(i, i + 1000));
      for (const chunk of chunks) await admin.auth().deleteUsers(chunk).catch(e => console.error(e));
    }

    // C. Firestore Delete
    const db = admin.firestore();
    await deleteCollection(db, 'users', 500, 'instituteId', instituteId);
    await deleteCollection(db, 'attendance', 500, 'instituteId', instituteId);
    await deleteCollection(db, 'announcements', 500, 'instituteId', instituteId);
    await deleteCollection(db, 'live_sessions', 500, 'instituteId', instituteId);
    await deleteCollection(db, 'student_requests', 500, 'instituteId', instituteId);
    await deleteCollection(db, 'leave_requests', 500, 'instituteId', instituteId);
    await db.collection('institutes').doc(instituteId).delete();
    await db.collection('applications').doc(instituteId).delete();

    return res.json({ message: 'Institute deleted permanently.' });
  } catch (err) {
    console.error("Delete Institute Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 17. CHECK STATUS (Public Endpoint)
app.post('/checkStatus', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    let result = { found: false, message: "No record found." };

    // A. Check Student Requests
    const studentSnap = await admin.firestore().collection('student_requests')
      .where('email', '==', email).limit(1).get();

    if (!studentSnap.empty) {
        const data = studentSnap.docs[0].data();
        return res.json({ 
            found: true, 
            role: 'student',
            status: data.status, // 'pending', 'approved', 'denied'
            message: `Student Request Status: ${data.status.toUpperCase()}`
        });
    }

    // B. Check Institute Applications
    const instituteSnap = await admin.firestore().collection('applications')
      .where('email', '==', email).limit(1).get();

    if (!instituteSnap.empty) {
        const data = instituteSnap.docs[0].data();
        return res.json({ 
            found: true, 
            role: 'institute',
            status: data.status, 
            message: `Institute Application Status: ${data.status.toUpperCase()}`
        });
    }

    // C. Check Existing Users (Already Approved)
    const userSnap = await admin.firestore().collection('users')
      .where('email', '==', email).limit(1).get();

    if (!userSnap.empty) {
        return res.json({ 
            found: true, 
            status: 'approved', 
            message: "Account already active. Please Login."
        });
    }

    return res.json(result);

  } catch (err) {
    console.error("Check Status Error:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 19. Generate Full Quiz (Fixed)
app.post('/generateQuiz', async (req, res) => {
    try {
        const { department, semester, careerGoal } = req.body;
        
        const systemPrompt = "You are a university professor creating a quick-fire quiz.";
        
        const userPrompt = `
            Generate 10 Multiple Choice Questions (MCQs) for a ${department} student in Semester ${semester}.
            Focus on topics relevant to: "${careerGoal}".
            
            Return STRICT JSON format:
            {
              "questions": [
                {
                  "question": "Question text here?",
                  "options": ["Detailed Option 1", "Detailed Option 2", "Detailed Option 3", "Detailed Option 4"],
                  "answer": "Detailed Option 1",
                  "explanation": "Short explanation of why this option is correct."
                }
              ]
            }

            CRITICAL RULES:
            1. The "answer" field MUST be an EXACT string copy of the correct option from the "options" array.
            2. Do NOT use prefixes like "A.", "B." or "1." in the options strings unless they are part of the answer text.
            3. Do NOT return the index or the letter (e.g., do NOT return "A" or "0"). Return the full text string.
        `;

        // Use the helper function for robust parsing
        const quizData = await callGroqAI(systemPrompt, userPrompt, true);
        res.json(quizData);

    } catch (error) {
        console.error("Quiz Gen Error:", error);
        res.status(500).json({ error: "Failed to generate quiz." });
    }
});

// Route 20: Update Resume & Claim XP
app.post('/updateResume', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.split('Bearer ')[1];
        if (!token) return res.status(401).json({ error: 'Missing token' });

        const decoded = await admin.auth().verifyIdToken(token);
        const uid = decoded.uid;
        const { resumeData } = req.body; // Expects { skills: [], experience: '', projects: [] }

        if (!resumeData) return res.status(400).json({ error: "No data provided" });

        const userRef = admin.firestore().collection('users').doc(uid);

        // Update User Doc with new Resume Data + Increment XP
        await userRef.update({
            resumeData: resumeData,
            xp: admin.firestore.FieldValue.increment(50) // 🏆 Reward for productivity
        });

        return res.json({ message: 'Resume updated! +50 XP awarded 🏆' });

    } catch (error) {
        console.error("Resume Update Error:", error);
        return res.status(500).json({ error: error.message });
    }
});

// =======================
//   📝 ASSIGNMENT ROUTES
// =======================

// 20. Create Assignment (Teacher)
app.post('/createAssignment', async (req, res) => {
    try {
        const { teacherId, teacherName, department, targetYear, title, description, dueDate } = req.body;
        
        await admin.firestore().collection('assignments').add({
            teacherId,
            teacherName,
            department,
            targetYear,
            title,
            description,
            dueDate,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.json({ message: "Assignment created successfully!" });
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 21. Get Assignments (Student)
app.post('/getAssignments', async (req, res) => {
    try {
        const { department, year } = req.body;
        // Fetch assignments for student's Dept & Year OR 'All'
        const q = admin.firestore().collection('assignments')
            .where('department', '==', department)
            .where('targetYear', 'in', [year, 'All']);
            
        const snapshot = await q.get();
        const tasks = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        
        // Sort by Due Date locally (since mixed queries can be tricky in Firestore)
        tasks.sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate));
        
        return res.json({ tasks });
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 22. Submit Assignment (Student - Upload PDF)
app.post('/submitAssignment', upload.single('document'), async (req, res) => {
    try {
        const { studentId, studentName, rollNo, assignmentId } = req.body;
        const file = req.file;

        if (!file) return res.status(400).json({ error: "No file uploaded" });

        // Check if already submitted
        const existing = await admin.firestore().collection('submissions')
            .where('assignmentId', '==', assignmentId)
            .where('studentId', '==', studentId).get();
            
        if (!existing.empty) return res.status(400).json({ error: "Already submitted!" });

        // Upload to Cloudinary
        const documentUrl = await uploadToCloudinary(file.buffer);

        await admin.firestore().collection('submissions').add({
            assignmentId,
            studentId,
            studentName,
            rollNo,
            documentUrl,
            status: 'Pending', // Pending, Graded
            marks: null,
            submittedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.json({ message: "Assignment Submitted!" });
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 23. Get Submissions for a Task (Teacher)
app.post('/getSubmissions', async (req, res) => {
    try {
        const { assignmentId } = req.body;
        const snapshot = await admin.firestore().collection('submissions')
            .where('assignmentId', '==', assignmentId).get();
            
        const submissions = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        return res.json({ submissions });
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 24. Grade Submission (Teacher)
app.post('/gradeSubmission', async (req, res) => {
    try {
        const { submissionId, marks, feedback } = req.body;
        
        await admin.firestore().collection('submissions').doc(submissionId).update({
            status: 'Graded',
            marks,
            feedback
        });

        return res.json({ message: "Graded successfully!" });
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

// 25. Generate Deep Contextual Task (The "Syllabus Architect")
app.post('/generateDeepTask', async (req, res) => {
    try {
        const { userProfile } = req.body; 
        // userProfile expects: { firstName, department, year, domain, subDomain, specificSkills }
        
        if (!userProfile) return res.status(400).json({ error: "Missing Profile Data" });

        const { domain, subDomain, specificSkills, year, department } = userProfile;

        // 1. Construct the "Deep Context" Prompt
        const systemPrompt = `
            You are an expert Academic Mentor and Curriculum Architect for university students.
            Your goal is to create a single, highly practical, short-duration (15-30 min) micro-task that bridges the gap between a student's academic syllabus and their career interest.
            
            OUTPUT RULES:
            - Return STRICT JSON only.
            - No markdown, no conversation.
        `;

        const userPrompt = `
            Student Profile:
            - Year/Dept: ${year} Year, ${department} Engineering.
            - Interest Domain: ${domain} -> ${subDomain}.
            - Specific Focus/Weakness: ${specificSkills || 'General Foundations'}.
            
            Task Requirements:
            1. Create a "Mini-Project" or "Skill Challenge" that takes 20-30 minutes.
            2. It must be specific (e.g., don't say "Code something", say "Create a REST API for...").
            3. It should relate to their specific skills if mentioned.
            
            JSON Schema:
            {
              "taskTitle": "Catchy Title",
              "difficulty": "Easy" | "Medium" | "Hard",
              "estimatedTime": "20 min",
              "xpReward": 100,
              "skillsTargeted": ["Skill 1", "Skill 2"],
              "instructions": [
                "Step 1: ...",
                "Step 2: ...",
                "Step 3: ..."
              ],
              "deliverableType": "code_snippet" | "text_summary" | "file_upload" 
            }
        `;

        // 2. Call Groq with JSON Enforcement
        const taskJson = await callGroqAI(systemPrompt, userPrompt, true);

        return res.json({ task: taskJson });

    } catch (err) {
        console.error("Deep Task Error:", err);
        return res.status(500).json({ error: "Failed to generate task." });
    }
});

app.post('/verifyQuickTask', verifyLimiter, async (req, res) => {
  try {
    const { uid, taskTitle, proofText, taskType, xpReward } = req.body;
    
    if (!uid || !taskTitle || !proofText) return res.status(400).json({ error: "Missing Proof Data" });
    
    // 1. Minimum Effort Check
    if (proofText.length < 15) return res.status(400).json({ error: "Submission too short. Please provide a real summary/code." });

    const userRef = admin.firestore().collection('users').doc(uid);
    const userSnap = await userRef.get();
    const userData = userSnap.data();

    // 2. TIME COOLDOWN (15 Minutes)
    const now = admin.firestore.Timestamp.now();
    const lastTime = userData.lastQuickTaskTime;
    if (lastTime && (now.toMillis() - lastTime.toMillis()) / (1000 * 60) < 15) {
        const minsLeft = 15 - Math.floor((now.toMillis() - lastTime.toMillis()) / (1000 * 60));
        return res.status(429).json({ error: `⏳ Cooldown active! Wait ${minsLeft} mins.` });
    }

    // 3. DAILY CAP (Max 200 Credits/Day)
    const todayStr = new Date().toDateString();
    let dailyCredits = 0;
    if (userData.dailyCreditsDate === todayStr) {
        dailyCredits = userData.dailyCreditsCount || 0;
    }
    if (dailyCredits >= 200) {
        return res.status(403).json({ error: "🛑 Daily Limit Reached! Come back tomorrow." });
    }

    // 4. AI VERIFICATION (The "Spam Filter")
    const systemPrompt = `You are a strict teacher verifying student work. Reply 'VALID' or 'INVALID' only.`;
    const userPrompt = `
      Task: "${taskTitle}" (${taskType}).
      Student Proof: "${proofText}"
      
      Rules:
      - If it's gibberish, random keys, or irrelevant: INVALID.
      - If it looks like a genuine attempt: VALID.
    `;

    const aiVerdict = await callGroqAI(systemPrompt, userPrompt, false);

    if (aiVerdict.includes("INVALID")) {
        return res.status(400).json({ error: "⚠️ AI Verification Failed. Content seems irrelevant or spam." });
    }

    // 5. SUCCESS: Award Credits
    const points = xpReward || 30;
    await userRef.update({ 
        xp: admin.firestore.FieldValue.increment(points), 
        lastQuickTaskTime: now,
        dailyCreditsDate: todayStr,
        dailyCreditsCount: (userData.dailyCreditsDate === todayStr ? dailyCredits : 0) + points
    });
    
    const newBadges = await checkAndAwardBadges(userRef, (userData.xp || 0) + points, userData.badges);

    return res.json({ 
        success: true, 
        message: `✅ Verified! +${points} Credits Earned.`, 
        newBadges 
    });

  } catch (err) {
    console.error("Verification Error:", err);
    return res.status(500).json({ error: "Verification failed. Try again." });
  }
});

app.post('/startInteractiveTask', taskLimiter, async (req, res) => {
    try {
        const { taskType, userInterest, difficulty } = req.body; 
        
        let systemPrompt = "";
        let userPrompt = "";

        // 🔥 MODE 1: SIMULATION
        if (taskType === 'Simulation') {
            systemPrompt = "You are a Career Simulator. Output strictly valid JSON.";
            userPrompt = `Create a high-stakes scenario for a "${userInterest}" professional.
            Situation: A critical problem (server crash, angry client, etc).
            JSON Format: { "title": "...", "scenario": "...", "role": "...", "options": ["A", "B", "C", "D"], "correctIndex": 1, "consequence": "..." }`;
        }
        // 🕵️ MODE 2: MYSTERY
        else if (taskType === 'Mystery') {
            systemPrompt = "You are a Logic Master. Output strictly valid JSON.";
            userPrompt = `Create a logic puzzle related to "${userInterest}".
            JSON Format: { "title": "...", "scenario": "...", "role": "...", "options": ["...", "...", "...", "..."], "correctIndex": 2, "consequence": "..." }`;
        } 
        // 💻 MODE 3: CODING
        else if (taskType === 'Coding') {
            const level = difficulty || 'Easy';
            systemPrompt = "You are a Senior Tech Lead. Output strictly valid JSON.";
            userPrompt = `Generate a ${level} level coding challenge related to "${userInterest}".
            
            Difficulty Guidelines:
            - Easy: Basic syntax, loops, string manipulation, or simple if-else logic.
            - Medium: Arrays, functions, object manipulation, or basic algorithms (sorting/search).
            - Hard: Optimization, recursion, complex data structures, or edge case handling.

            JSON Format: { "title": "...", "scenario": "Your goal is to...", "starterCode": "...", "expectedOutput": "..." }`;
        }
        // ⌨️ MODE 4: TYPING
        else if (taskType === 'Typing') {
            systemPrompt = "Output strictly valid JSON.";
            userPrompt = `Generate a fact about "${userInterest}" (max 30 words). JSON Format: { "textToType": "..." }`;
        }
        // 📚 MODE 5: FLASHCARD (✅ IMPROVED PROMPT)
        else if (taskType === 'FlashCard') {
            // Stronger system prompt to force JSON
            systemPrompt = "You are a precise Flashcard Generator API. Return ONLY valid JSON. No conversational text or markdown.";
            
            // Explicit schema in user prompt
            userPrompt = `Generate exactly 8 conceptual flashcards about "${userInterest}".
            
            Strict JSON Output Schema:
            {
              "cards": [
                { "front": "Concept or Question", "back": "Definition or Short Answer" },
                { "front": "Concept or Question", "back": "Definition or Short Answer" }
              ]
            }
            
            Ensure the "cards" array exists and contains objects with "front" and "back" keys.`;
        }

        const data = await callGroqAI(systemPrompt, userPrompt, true);
        
        // Safety Check: If AI returns raw array, wrap it
        if (taskType === 'FlashCard' && Array.isArray(data)) {
             return res.json({ cards: data });
        }
        
        // Safety Check: If AI returns empty object or error, handle gracefully
        if (!data || (taskType === 'FlashCard' && !data.cards)) {
            console.error("Invalid AI Response for Flashcards:", data);
            return res.status(500).json({ error: "AI generation failed structure check." });
        }

        res.json(data);

    } catch (err) {
        console.error("Task Gen Error:", err);
        res.status(500).json({ error: "Failed to generate task. Please try again." });
    }
});

// 2. SUBMIT & GRADE
app.post('/submitInteractiveTask', async (req, res) => {
    try {
        const { uid, taskType, submission, context } = req.body;
        const userRef = admin.firestore().collection('users').doc(uid);

        let passed = false;
        let feedback = "";
        let hint = null; // New "Smart Hint" feature
        let creditsEarned = 0;

        // --- A. CODING CHALLENGE (Smart Tutor Mode) ---
        if (taskType === 'Coding') {
            const systemPrompt = `
                You are a Code Reviewer. 
                Task: ${context.problemStatement}
                Student Code: ${submission.code}
                
                Rules:
                1. If logic is correct, return JSON: { "passed": true, "feedback": "Great job!" }
                2. If WRONG, return JSON: { "passed": false, "hint": "Give a specific clue (e.g. 'Check your variable scope'), do NOT give the full answer." }
            `;
            
            const aiCheck = await callGroqAI("Code Mentor", systemPrompt, true);
            
            passed = aiCheck.passed;
            if (passed) {
                feedback = aiCheck.feedback || "Code Verified! Excellent logic.";
                creditsEarned = 50;
            } else {
                hint = aiCheck.hint || "Something is off. Check your syntax.";
                feedback = "Keep trying! See the hint below.";
            }
        }

        // --- B. TYPING TEST (Speed & Accuracy) ---
        else if (taskType === 'Typing') {
            // Context.targetText is the original paragraph
            const { wpm, accuracy } = submission;
            
            // Hard Rules: >30 WPM and >90% Accuracy
            if (wpm >= 30 && accuracy >= 90) {
                passed = true;
                creditsEarned = 30;
                feedback = `🔥 Fast Fingers! ${wpm} WPM & ${accuracy}% Accuracy.`;
            } else {
                passed = false;
                feedback = `Too slow or inaccurate. You need >30 WPM and >90% Accuracy. (You: ${wpm} WPM, ${accuracy}%)`;
            }
        }

        // --- C. QUIZ (Instant Check) ---
        else if (taskType === 'Quiz') {
            if (submission.answerIndex === context.answerIndex) {
                passed = true;
                creditsEarned = 20;
                feedback = "Correct! Well done.";
            } else {
                passed = false;
                feedback = "Incorrect. Try again next time.";
            }
        }

        // 3. Final Database Update (If Passed)
        if (passed) {
            await userRef.update({ xp: admin.firestore.FieldValue.increment(creditsEarned) });
            return res.json({ success: true, passed: true, credits: creditsEarned, feedback });
        } else {
            return res.json({ success: true, passed: false, feedback, hint }); // Return hint if failed
        }

    } catch (err) {
        console.error("Submission Error:", err);
        res.status(500).json({ error: "Error processing submission." }); 
    }
});

app.post('/generatePersonalizedTasks', async (req, res) => {
    try {
        const { userProfile } = req.body;
        
        if (!userProfile || !userProfile.domain) {
            return res.json({ tasks: [] }); 
        }

        const prompt = `
            Generate exactly 3 short, gamified tasks for a student to do in 5 minutes.
            Student Profile:
            - Interest: ${userProfile.domain} (${userProfile.subDomain})
            - Target Skill: ${userProfile.specificSkills || 'General Essentials'}
            
            REQUIRED TASKS (Return strictly valid JSON Array):
            1. "Coding": A small coding bug or challenge related to ${userProfile.specificSkills}.
            2. "Quiz": A conceptual multiple-choice question.
            3. "Typing": A 40-50 word paragraph about ${userProfile.subDomain} history or facts.

            JSON Structure:
            [
                {
                    "id": "task_1",
                    "title": "Fix the Bug / Create Comp",
                    "type": "Coding",
                    "xp": 50,
                    "content": {
                        "problemStatement": "Describe the coding task...",
                        "starterCode": "const x = 0; // Fix this..."
                    }
                },
                {
                    "id": "task_2",
                    "title": "Quick Trivia",
                    "type": "Quiz",
                    "xp": 20,
                    "content": {
                        "question": "What does...?",
                        "options": ["A", "B", "C", "D"],
                        "answerIndex": 0
                    }
                },
                {
                    "id": "task_3",
                    "title": "Speed Typing: ${userProfile.subDomain}",
                    "type": "Typing",
                    "xp": 30,
                    "content": {
                        "targetText": "React is a library... (approx 40 words)"
                    }
                }
            ]
        `;

        const aiResponse = await callGroqAI("Curriculum Architect", prompt, true); 
        const tasks = Array.isArray(aiResponse) ? aiResponse : [];
        res.json({ tasks });

    } catch (error) {
        console.error("AI Gen Error:", error);
        res.status(500).json({ error: "Failed to generate tasks" });
    }
});

app.post('/verifyAiTask', async (req, res) => {
    try {
        const { taskType, originalTask, userSubmission } = req.body;

        const prompt = `
            Act as a strict teacher.
            Task Type: ${taskType}
            Problem: ${JSON.stringify(originalTask)}
            Student Submission: ${userSubmission}

            Verify if the submission is correct/relevant. 
            Return strictly JSON: 
            { 
                "passed": boolean, 
                "feedback": "1 sentence constructive feedback" 
            }
        `;

        const result = await callGroqAI("Grader", prompt, true);
        res.json(result);
    } catch (error) {
        console.error("Verification Error:", error);
        res.status(500).json({ error: "Verification failed" });
    }
});

app.post('/setup2FA', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    const secret = speakeasy.generateSecret({ name: `AcadeX (${decoded.email})` });
    const qrImage = await QRCode.toDataURL(secret.otpauth_url);

    // Save temporary secret
    await admin.firestore().collection('secrets').doc(uid).set({
      tempSecret: secret.base32,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ qrImage, manualEntry: secret.base32 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. Verify: Enable 2FA
app.post('/verify2FA', async (req, res) => {
  try {
    const { token: userCode, isLogin } = req.body;
    const authHeader = req.headers.authorization || '';
    const token = authHeader.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;

    const secretDoc = await admin.firestore().collection('secrets').doc(uid).get();
    if (!secretDoc.exists) return res.status(400).json({ error: 'Setup not started' });
    
    const data = secretDoc.data();
    const secretKey = isLogin ? data.secret : data.tempSecret;

    const verified = speakeasy.totp.verify({
      secret: secretKey,
      encoding: 'base32',
      token: userCode,
      window: 1 
    });

    if (verified) {
      if (!isLogin) {
        // Activate 2FA permanently
        await admin.firestore().collection('secrets').doc(uid).update({
          secret: secretKey,
          tempSecret: admin.firestore.FieldValue.delete()
        });
        await admin.firestore().collection('users').doc(uid).update({ is2FAEnabled: true });
      }
      res.json({ success: true });
    } else {
      res.status(400).json({ error: "Invalid Code" });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/verifyCode', async (req, res) => {
    try {
        const { code, language, problemStatement } = req.body;
        const apiKey = process.env.GROQ_API_KEY;

        const prompt = `
            Act as a Code Compiler & Mentor.
            Problem: "${problemStatement}"
            Language: ${language}
            Student Code: 
            ${code}

            Check if the code solves the problem correctly.
            Return STRICT JSON:
            {
                "correct": boolean,
                "output": "Simulated output of the code",
                "hint": "If wrong, give a small hint. If right, say 'Great job!'"
            }
        `;

        const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
            method: "POST",
            headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
            body: JSON.stringify({ messages: [{ role: "user", content: prompt }], model: "llama-3.3-70b-versatile", response_format: { type: "json_object" } })
        });

        const data = await response.json();
        res.json(JSON.parse(data.choices[0].message.content));
    } catch (err) { res.status(500).json({ error: "Compiler Error" }); }
});

// --- UPDATE 3: TEACHER ANALYTICS (Task Stats) ---
app.post('/getTaskAnalytics', async (req, res) => {
    try {
        const { instituteId } = req.body;
        // Fetch aggregated stats from 'userProgress' collection or calculate from 'users'
        // This is a simplified aggregation
        const usersSnap = await admin.firestore().collection('users').where('instituteId', '==', instituteId).get();
        
        let stats = { quiz: 0, coding: 0, typing: 0, totalXP: 0 };
        
        usersSnap.forEach(doc => {
            const d = doc.data();
            stats.totalXP += (d.xp || 0);
            // Assuming you track specific counts in user doc, or we query subcollections
            // For now, let's simulate based on XP distribution or mock
        });

        // Mocking distribution for chart visualization (Replace with real subcollection queries if needed)
        const chartData = [
            { name: 'Quizzes', value: Math.floor(stats.totalXP * 0.4) },
            { name: 'Coding', value: Math.floor(stats.totalXP * 0.3) },
            { name: 'Typing', value: Math.floor(stats.totalXP * 0.2) },
            { name: 'Reading', value: Math.floor(stats.totalXP * 0.1) }
        ];

        res.json({ chartData });
    } catch (err) { res.status(500).json({ error: "Stats failed" }); }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
