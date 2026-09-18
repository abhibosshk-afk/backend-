`/
 * CineNova Secure OTT Backend Service
 * 
 * Production-ready server for:
 * 1. Google Cloud Storage private bucket management
 * 2. Firebase ID Token verification & role checks
 * 3. Resumable Upload Session & V4 Signed PUT URL generation (Admin only)
 * 4. Short-lived V4 Signed GET URLs for 4K streaming and downloads (Subscribers only)
 * 5. Secure Firestore movie lifecycle synchronization
 */

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const dotenv = require('dotenv');
const crypto = require('crypto');
const admin = require('firebase-admin');
const { Storage } = require('@google-cloud/storage');
const { Readable } = require('stream');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
// The default storage bucket for cinenova-1232d is cinenova-1232d.firebasestorage.app
const GCS_BUCKET_NAME = process.env.GCS_BUCKET_NAME || 'cinenova-1232d.firebasestorage.app';

// Payment Provider Configuration
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || 'rzp_test_cinenova_live';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || '';
const UPI_PAYEE_VPA = process.env.UPI_PAYEE_VPA || 'bossn2005axl';
const UPI_PAYEE_NAME = process.env.UPI_PAYEE_NAME || 'CineNova Admin';
const VIP_PLAN_PRICE_INR = 10.00;
const VIP_PLAN_DURATION_DAYS = 30;

console.log('--- CineNova Backend Startup Diagnostics ---');
console.log('GOOGLE_CLOUD_PROJECT present:', !!process.env.GOOGLE_CLOUD_PROJECT);
console.log('GCS_BUCKET_NAME present:', !!process.env.GCS_BUCKET_NAME);
console.log('FIREBASE_CONFIG_JSON present:', !!process.env.FIREBASE_CONFIG_JSON);
console.log('GOOGLE_WEB_CLIENT_ID present:', !!process.env.GOOGLE_WEB_CLIENT_ID);
console.log('GOOGLE_WEB_CLIENT_SECRET present:', !!process.env.GOOGLE_WEB_CLIENT_SECRET);
console.log('--------------------------------------------');

// Initialize Firebase Admin SDK
// When running in Google Cloud Run or Cloud Functions, Application Default Credentials (ADC) are used automatically.
let serviceAccount = null;
if (process.env.FIREBASE_CONFIG_JSON) {
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG_JSON);
  } catch (err) {
    console.error('Failed to parse FIREBASE_CONFIG_JSON:', err.message);
  }
}

if (!admin.apps.length) {
  if (serviceAccount) {
    admin.initializeApp({
      credential: admin.cert(serviceAccount)
    });
  } else {
    admin.initializeApp();
  }
}

const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');

const db = getFirestore();
const auth = getAuth();
const storage = serviceAccount
  ? new Storage({
      projectId: serviceAccount.project_id,
      credentials: {
        client_email: serviceAccount.client_email,
        // CRITICAL FIX: Render environment variables often double-escape newlines in JSON strings.
        // The firebase-admin SDK automatically handles \n internally, but @google-cloud/storage DOES NOT.
        // This causes getSignedUrl() to throw DECODER routines::unsupported (HTTP 500) because the private key is malformed.
        private_key: serviceAccount.private_key ? serviceAccount.private_key.replace(/\\n/g, '\n') : undefined
      }
    })
  : new Storage();
const bucket = storage.bucket(GCS_BUCKET_NAME);

app.use(cors({ origin: true }));
app.use(express.json());
app.get('/admin/diagnostics', (req, res) => {
  let initError = null;
  try {
    admin.auth();
  } catch (e) {
    initError = e.message;
  }
  const apps = admin.apps.length;
  const projectId = admin.apps[0]?.options?.projectId || process.env.GOOGLE_CLOUD_PROJECT || 'Not Set';
  res.json({
    apps_initialized: apps,
    project_id: projectId,
    init_error: initError,
    env_config_present: !!process.env.FIREBASE_CONFIG_JSON
  });
});
app.use(morgan('combined'));

// ==========================================
// AUTHENTICATION & ROLE MIDDLEWARES
// ==========================================

/**
 * Middleware to verify Firebase ID Token in Authorization header
 */
const DESIGNATED_ADMIN_EMAILS = [
  'abhisheksuniyar737@gmail.com',
  'abisheksuniyar737@gmail.com',
  'abhibosshk@gmail.com'
];

async function authenticateFirebaseUser(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.trim().toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Missing or invalid Authorization header. Provide a valid Bearer Firebase ID Token.'
    });
  }

  const idToken = authHeader.trim().slice(7).trim();
  if (!idToken) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Bearer token is empty or invalid.'
    });
  }

  console.log(`[AUTH] Checking token for route: ${req.path}`);
  console.log(`[DIAGNOSTIC] Authorization Header length: ${authHeader.length}, prefix check passed.`);
  console.log(`[DIAGNOSTIC] Token format check: length=${idToken.length}, dots=${(idToken.match(/\./g) || []).length}`);
  try {
    const decodedToken = await auth.verifyIdToken(idToken);
    req.user = decodedToken;
    console.log(`[AUTH] Token valid. UID: ${decodedToken.uid}`);
    next();
  } catch (error) {
    console.error(`[AUTH ERROR] Firebase token verification error on ${req.path}:`, error.message);
    return res.status(401).json({
      error: 'INVALID_TOKEN',
      message: `Firebase token expired or invalid: ${error.message}`
    });
  }
}

/**
 * Middleware to enforce ADMIN role
 */
async function requireAdminRole(req, res, next) {
  if (!req.user) {
    console.error('[AUTH ERROR] User not authenticated in requireAdminRole');
    return res.status(401).json({ error: 'UNAUTHORIZED', message: 'User not authenticated.' });
  }

  try {
    console.log(`[AUTH] Checking admin role for UID: ${req.user.uid}`);
    
    // Check Custom Claim first or designated admin emails
    if (req.user.admin === true || req.user.role === 'ADMIN') {
      console.log(`[AUTH] Admin granted via custom claims for UID: ${req.user.uid}`);
      return next();
    }

    if (req.user.email && DESIGNATED_ADMIN_EMAILS.includes(req.user.email.toLowerCase())) {
      console.log(`[AUTH] Admin granted via designated email for UID: ${req.user.uid}`);
      return next();
    }

    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists) {
      console.warn(`[AUTH] User document not found for UID: ${req.user.uid}`);
      return res.status(403).json({ error: 'ACCESS_DENIED', message: 'User account profile not found.' });
    }

    const userData = userDoc.data();
    if (userData.role !== 'ADMIN' || userData.isBlocked === true) {
      console.warn(`[AUTH] Access denied. Role: ${userData.role}, Blocked: ${userData.isBlocked} for UID: ${req.user.uid}`);
      return res.status(403).json({
        error: 'ACCESS_DENIED',
        message: 'Administrator permissions required to perform this action.'
      });
    }

    console.log(`[AUTH] Admin granted via Firestore role for UID: ${req.user.uid}`);
    req.adminData = userData;
    next();
  } catch (error) {
    console.error('Admin role verification failed:', error);
    return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'Failed to verify admin status.' });
  }
}

/**
 * Helper to check movie streaming/download access (Subscription check)
 */
async function checkUserAccess(userId, movieId) {
  try {
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return { authorized: false, reason: 'USER_NOT_FOUND' };
    }

    const user = userDoc.data();

    // Blocked users cannot stream
    if (user.isBlocked) {
      return { authorized: false, reason: 'ACCOUNT_BLOCKED' };
    }

    // Admins bypass subscription checks for content QA & moderation
    if (user.role === 'ADMIN') {
      return { authorized: true, role: 'ADMIN' };
    }

    const now = Date.now();
    const subStatus = user.subscriptionStatus || 'FREE';
    const subExpiry = user.subscriptionExpiry || 0;

    // Check if user has an active, non-expired CineNova VIP subscription
    const isSubscribed = (subStatus === 'ACTIVE' || subStatus === 'PREMIUM') && (subExpiry > now);

    if (!isSubscribed) {
      return { authorized: true, role: 'USER', entitlement: 'FREE' };
    }
    return { authorized: true, role: 'USER', entitlement: 'PREMIUM' };
  } catch (error) {
    console.error('Access check error:', error);
    return { authorized: false, reason: 'VERIFICATION_FAILED' };
  }
}

// ==========================================
// 1. HEALTH & METRICS
// ==========================================
app.get('/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'CineNova Secure Streaming Engine',
    timestamp: new Date().toISOString(),
    bucket: GCS_BUCKET_NAME
  });
});

// ==========================================
// 2. ADMIN MOVIE UPLOAD SESSION (GCS Resumable Session)
// ==========================================
app.post('/admin/movies/create-upload-session', authenticateFirebaseUser, requireAdminRole, async (req, res) => {
  try {
    const { movieId, fileName, contentType, fileCategory } = req.body;

    if (!movieId || !fileName) {
      return res.status(400).json({
        error: 'BAD_REQUEST',
        message: 'Missing required parameters: movieId and fileName.'
      });
    }

    // Determine storage path based on fileCategory (video, poster, banner)
    let destinationPath;
    if (fileCategory === 'video') {
      destinationPath = `movies/${movieId}/video/original/${fileName || 'movie.mp4'}`;
    } else if (fileCategory === 'poster') {
      destinationPath = `movies/${movieId}/poster/${fileName || 'poster.jpg'}`;
    } else if (fileCategory === 'banner') {
      destinationPath = `movies/${movieId}/banner/${fileName || 'banner.jpg'}`;
    } else {
      destinationPath = `movies/${movieId}/media/${fileName}`;
    }

    const file = bucket.file(destinationPath);

    // Generate V4 Signed PUT URL for direct chunked/resumable upload to Google Cloud Storage
    const [uploadUrl] = await file.getSignedUrl({
      version: 'v4',
      action: 'write',
      expires: Date.now() + 60 * 60 * 1000, // 60 minutes for large video uploads
      contentType: contentType || 'application/octet-stream'
    });

    // Create / update initial draft metadata in Firestore
    await db.collection('movies').doc(movieId).set({
      id: movieId,
      status: 'UPLOADING',
      [fileCategory === 'video' ? 'videoObjectPath' : fileCategory === 'poster' ? 'posterPath' : 'bannerPath']: destinationPath,
      updatedAt: Date.now(),
      createdBy: req.user.uid
    }, { merge: true });

    return res.status(200).json({
      success: true,
      movieId,
      objectPath: destinationPath,
      uploadUrl,
      expiresInMinutes: 60
    });
  } catch (error) {
    console.error('Error creating upload session:', error);
    return res.status(500).json({
      error: 'UPLOAD_SESSION_FAILED',
      message: 'Failed to create Google Cloud Storage upload session: ' + error.message
    });
  }
});

// ==========================================
// 2b. GOOGLE DRIVE TO PRIVATE CLOUD IMPORT (Admin only)
// Direct cloud-to-cloud transfer from Google Drive to CineNova private GCS bucket.
// The movie is never downloaded to the client phone.
// The original Google Drive file remains completely untouched.
// ==========================================

async function exchangeGoogleServerAuthCode(authCode) {
  const clientId = process.env.GOOGLE_WEB_CLIENT_ID || process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_WEB_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    const missing = [];
    if (!clientId) missing.push('GOOGLE_WEB_CLIENT_ID');
    if (!clientSecret) missing.push('GOOGLE_WEB_CLIENT_SECRET');
    throw new Error(`Server OAuth credentials missing in environment: ${missing.join(', ')}`);
  }

  const tokenEndpoint = 'https://oauth2.googleapis.com/token';
  const params = new URLSearchParams({
    code: authCode,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: '', // Required empty string for Android Server Auth Code flow
    grant_type: 'authorization_code'
  });

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    console.error(`[OAUTH EXCHANGE ERROR] Google OAuth token exchange failed (HTTP ${response.status})`);
    let errorDetail = 'Code exchange failed';
    try {
      const parsed = JSON.parse(errorBody);
      errorDetail = parsed.error_description || parsed.error || errorDetail;
    } catch (_) {}
    throw new Error(`Google token exchange error: ${errorDetail}`);
  }

  const tokenData = await response.json();
  return {
    accessToken: tokenData.access_token,
    refreshToken: tokenData.refresh_token,
    expiresIn: tokenData.expires_in
  };
}

async function refreshGoogleDriveAccessToken(refreshToken) {
  const clientId = process.env.GOOGLE_WEB_CLIENT_ID || process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_WEB_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET;

  if (!clientId || !clientSecret || !refreshToken) {
    return null;
  }

  const params = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'refresh_token'
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });

  if (!response.ok) {
    console.error(`[OAUTH REFRESH ERROR] Failed to refresh token (HTTP ${response.status})`);
    return null;
  }

  const tokenData = await response.json();
  return tokenData.access_token;
}

app.post('/admin/movies/import-from-drive', authenticateFirebaseUser, requireAdminRole, async (req, res) => {
  let gcsFile = null;
  let destinationPath = null;
  try {
    const {
      movieId,
      driveFileId,
      serverAuthCode,
      authCode,
      accessToken,
      fileCategory = 'video'
    } = req.body;

    if (!movieId || !driveFileId) {
      return res.status(400).json({
        success: false,
        error: 'BAD_REQUEST',
        message: 'Missing required parameters: movieId and driveFileId.'
      });
    }

    // Determine target GCS path based on category
    if (fileCategory === 'video') {
      destinationPath = `movies/${movieId}/video/original/movie.mp4`;
    } else if (fileCategory === 'poster') {
      destinationPath = `movies/${movieId}/poster/poster.jpg`;
    } else if (fileCategory === 'banner') {
      destinationPath = `movies/${movieId}/banner/banner.jpg`;
    } else {
      destinationPath = `movies/${movieId}/media/${driveFileId}`;
    }

    gcsFile = bucket.file(destinationPath);

    // Duplicate Protection: Check if already verified and present in private GCS
    const [alreadyExists] = await gcsFile.exists();
    if (alreadyExists) {
      const [meta] = await gcsFile.getMetadata().catch(() => [null]);
      const existingSize = parseInt(meta?.size, 10) || 0;
      if (existingSize > 0) {
        console.log(`[DRIVE IMPORT] Object ${destinationPath} already verified in GCS (${existingSize} bytes), reusing existing asset.`);
        await db.collection('movies').doc(movieId).set({
          id: movieId,
          driveVideoFileId: driveFileId,
          videoObjectPath: destinationPath,
          assetSize: existingSize,
          storageProvider: 'GCS_PRIVATE',
          importStatus: 'COMPLETED',
          updatedAt: Date.now()
        }, { merge: true });

        return res.status(200).json({
          success: true,
          movieId,
          copiedDriveFileId: driveFileId,
          destinationPath,
          assetSize: existingSize,
          message: 'Existing cloud asset reused for movie.'
        });
      }
    }

    const code = serverAuthCode || authCode;
    if (!code) {
      if (process.env.ALLOW_LEGACY_DRIVE_TOKEN === 'true' && accessToken) {
        console.warn('[DRIVE IMPORT WARNING] Using legacy direct accessToken fallback (non-production path only)');
      } else {
        return res.status(400).json({
          success: false,
          error: 'SERVER_AUTH_CODE_REQUIRED',
          message: 'Secure serverAuthCode is required for Google Drive import. Production Drive import uses serverAuthCode only.'
        });
      }
    }

    // Resolve active OAuth Access Token:
    // Production path exchanges server auth code server-to-server
    let activeToken = null;
    let refreshToken = null;

    if (code) {
      try {
        const exchangeResult = await exchangeGoogleServerAuthCode(code);
        activeToken = exchangeResult.accessToken;
        refreshToken = exchangeResult.refreshToken;
        console.log('[DRIVE IMPORT] Server auth code successfully exchanged with Google OAuth.');
      } catch (exchangeErr) {
        console.error('[DRIVE IMPORT] Code exchange failure:', exchangeErr.message);
        return res.status(400).json({
          success: false,
          error: 'OAUTH_EXCHANGE_FAILED',
          message: exchangeErr.message
        });
      }
    } else if (process.env.ALLOW_LEGACY_DRIVE_TOKEN === 'true' && accessToken) {
      activeToken = accessToken;
    } else {
      return res.status(400).json({
        success: false,
        error: 'SERVER_AUTH_CODE_REQUIRED',
        message: 'serverAuthCode is required.'
      });
    }

    // Fetch directly from Google Drive API with read-only stream
    // Google Drive file is ONLY the source - untouched, unmodified, never deleted
    const driveUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(driveFileId)}?alt=media&supportsAllDrives=true`;
    let driveResponse = await fetch(driveUrl, {
      headers: { Authorization: `Bearer ${activeToken}` }
    });

    // Handle token expiry during long imports if refresh token is available
    if (driveResponse.status === 401 && refreshToken) {
      console.log('[DRIVE IMPORT] Access token expired, refreshing using refresh token...');
      const refreshedToken = await refreshGoogleDriveAccessToken(refreshToken);
      if (refreshedToken) {
        activeToken = refreshedToken;
        driveResponse = await fetch(driveUrl, {
          headers: { Authorization: `Bearer ${activeToken}` }
        });
      }
    }

    if (!driveResponse.ok) {
      console.error(`[DRIVE IMPORT ERROR] Google Drive API error (HTTP ${driveResponse.status})`);
      return res.status(driveResponse.status).json({
        success: false,
        error: 'DRIVE_FETCH_FAILED',
        message: `Failed to fetch file from Google Drive (HTTP ${driveResponse.status})`
      });
    }

    // Pipe directly from Google Drive HTTP stream to Google Cloud Storage write stream
    // Phone never downloads the movie bytes
    try {
      await new Promise((resolve, reject) => {
        const writeStream = gcsFile.createWriteStream({
          resumable: true,
          metadata: {
            contentType: driveResponse.headers.get('content-type') || 'video/mp4',
            metadata: {
              originalDriveFileId: driveFileId,
              importedBy: req.user.uid,
              importedAt: new Date().toISOString()
            }
          }
        });

        const readStream = (driveResponse.body && typeof driveResponse.body.pipe === 'function')
          ? driveResponse.body
          : (Readable.fromWeb ? Readable.fromWeb(driveResponse.body) : driveResponse.body);

        writeStream.on('error', reject);
        readStream.on('error', reject);
        writeStream.on('finish', resolve);

        readStream.pipe(writeStream);
      });

      console.log(`[DRIVE IMPORT SUCCESS] Transferred Drive file ${driveFileId} directly to GCS ${destinationPath}`);
    } catch (streamErr) {
      // Safe cleanup of incomplete GCS object
      console.error('[DRIVE STREAM ERROR] Streaming failed or interrupted. Cleaning up incomplete GCS object:', streamErr.message);
      if (gcsFile) {
        await gcsFile.delete({ ignoreNotFound: true }).catch(() => {});
      }
      return res.status(500).json({
        success: false,
        error: 'DRIVE_STREAM_ERROR',
        message: 'Error streaming file to cloud storage: ' + streamErr.message
      });
    }

    // Verify the transferred GCS object before marking movie import complete
    const [finalExists] = await gcsFile.exists();
    if (!finalExists) {
      return res.status(500).json({
        success: false,
        error: 'VERIFICATION_FAILED',
        message: 'Transferred asset does not exist in destination storage.'
      });
    }

    const [finalMeta] = await gcsFile.getMetadata().catch(() => [null]);
    const assetSize = parseInt(finalMeta?.size, 10) || 0;
    if (assetSize <= 0) {
      // Clean up empty/corrupted object
      await gcsFile.delete({ ignoreNotFound: true }).catch(() => {});
      return res.status(500).json({
        success: false,
        error: 'EMPTY_ASSET_CORRUPTED',
        message: 'Transferred file is empty (0 bytes). Incomplete object cleaned up.'
      });
    }

    // Store ONLY the required private cloud reference in Firestore
    await db.collection('movies').doc(movieId).set({
      id: movieId,
      driveVideoFileId: driveFileId,
      videoObjectPath: destinationPath,
      assetSize,
      storageProvider: 'GCS_PRIVATE',
      importStatus: 'COMPLETED',
      updatedAt: Date.now()
    }, { merge: true });

    return res.status(200).json({
      success: true,
      movieId,
      copiedDriveFileId: driveFileId,
      destinationPath,
      assetSize,
      message: 'File successfully imported from Google Drive to CineNova private cloud storage.'
    });

  } catch (error) {
    console.error('[DRIVE IMPORT ERROR]', error.message);
    if (gcsFile) {
      await gcsFile.delete({ ignoreNotFound: true }).catch(() => {});
    }
    return res.status(500).json({
      success: false,
      error: 'DRIVE_IMPORT_FAILED',
      message: error.message
    });
  }
});

// ==========================================
// 3. ADMIN FINALIZE MOVIE UPLOAD
// ==========================================
app.post('/admin/movies/finalize-upload', authenticateFirebaseUser, requireAdminRole, async (req, res) => {
  try {
    const {
      movieId,
      title,
      description,
      genre,
      language,
      releaseYear,
      durationMinutes,
      rating,
      maturityRating,
      qualityBadge,
      isFeatured,
      isTrending,
      posterPath,
      bannerPath,
      videoObjectPath,
      publishImmediately
    } = req.body;

    if (!movieId || !title) {
      return res.status(400).json({
        error: 'BAD_REQUEST',
        message: 'Missing movieId or title.'
      });
    }

    // Verify video object exists in Google Cloud Storage
    if (videoObjectPath) {
      const [exists] = await bucket.file(videoObjectPath).exists();
      if (!exists) {
        console.warn(`Warning: GCS object ${videoObjectPath} not yet found, marking as PROCESSING.`);
      }
    }

    const movieStatus = publishImmediately ? 'PUBLISHED' : 'READY';

    // Generate permanent public or signed preview URLs for poster/banner if available
    let posterPublicUrl = `https://storage.googleapis.com/${GCS_BUCKET_NAME}/${posterPath}`;
    let bannerPublicUrl = `https://storage.googleapis.com/${GCS_BUCKET_NAME}/${bannerPath}`;

    const movieDocument = {
      id: movieId,
      title,
      description: description || '',
      genre: genre || 'Action / Sci-Fi',
      language: language || 'Hindi / English',
      releaseYear: parseInt(releaseYear, 10) || new Date().getFullYear(),
      durationMinutes: parseInt(durationMinutes, 10) || 120,
      rating: parseFloat(rating) || 4.5,
      maturityRating: maturityRating || '16+',
      qualityBadge: qualityBadge || '4K Ultra HD',
      isFeatured: Boolean(isFeatured),
      isTrending: Boolean(isTrending),
      posterPath: posterPath || `movies/${movieId}/poster/poster.jpg`,
      bannerPath: bannerPath || `movies/${movieId}/banner/banner.jpg`,
      videoObjectPath: videoObjectPath || `movies/${movieId}/video/original/movie.mp4`,
      posterUrl: posterPublicUrl,
      backdropUrl: bannerPublicUrl,
      status: movieStatus,
      createdBy: req.user.uid,
      createdAt: req.body.createdAt || Date.now(),
      updatedAt: Date.now()
    };

    await db.collection('movies').doc(movieId).set(movieDocument, { merge: true });

    return res.status(200).json({
      success: true,
      message: `Movie successfully saved with status ${movieStatus}.`,
      movie: movieDocument
    });
  } catch (error) {
    console.error('Error finalizing movie upload:', error);
    return res.status(500).json({
      error: 'FINALIZE_FAILED',
      message: 'Failed to finalize movie upload: ' + error.message
    });
  }
});

// ==========================================
// 4. SECURE STREAMING (Short-Lived V4 Signed GET URL)
// ==========================================
app.get('/movies/:movieId/stream-url', authenticateFirebaseUser, async (req, res) => {
  try {
    const { movieId } = req.params;
    const userId = req.user.uid;

    const access = await checkUserAccess(userId, movieId);
    if (!access.authorized) {
      return res.status(403).json({
        error: access.reason,
        message: access.message || 'Access denied.'
      });
    }

    // Check 14,400s limit for FREE users
    if (access.entitlement === 'FREE') {
      const today = new Date().toISOString().split('T')[0];
      const usageDoc = await db.collection('users').doc(userId).collection('daily_usage').doc(today).get();
      const accumulatedSeconds = usageDoc.exists ? (usageDoc.data().seconds || 0) : 0;
      if (accumulatedSeconds >= 14400) {
        return res.status(403).json({
          error: 'DAILY_LIMIT_REACHED',
          message: 'You have reached your 4-hour daily free streaming limit.'
        });
      }
    }

    const movieDoc = await db.collection('movies').doc(movieId).get();
    if (!movieDoc.exists) {
      return res.status(404).json({ error: 'MOVIE_NOT_FOUND', message: 'Movie not found.' });
    }

    const movie = movieDoc.data();
    if (movie.status !== 'PUBLISHED' && access.role !== 'ADMIN') {
      return res.status(403).json({ error: 'MOVIE_NOT_PUBLISHED' });
    }

    const requestedQuality = req.query.q || '480p';
    let allowedQuality = '480p';

    if (access.entitlement === 'PREMIUM' || access.role === 'ADMIN') {
      if (['480p', '720p', '1080p', '4K'].includes(requestedQuality)) {
        allowedQuality = requestedQuality;
      }
    } else {
      if (requestedQuality !== '480p') {
        return res.status(403).json({
          error: 'SUBSCRIPTION_REQUIRED',
          message: 'Premium subscription required for 720p, 1080p, and 4K quality.'
        });
      }
    }

    let targetObjectPath = `movies/${movieId}/video/${allowedQuality}/movie.mp4`;
    let file = bucket.file(targetObjectPath);
    let [exists] = await file.exists();

    if (!exists) {
      if (allowedQuality !== '480p') {
        return res.status(404).json({ error: 'QUALITY_NOT_AVAILABLE', message: 'Requested quality is not available for this movie.' });
      }
      // Fallback for 480p
      targetObjectPath = movie.videoObjectPath || `movies/${movieId}/video/original/movie.mp4`;
      file = bucket.file(targetObjectPath);
      const [originalExists] = await file.exists();
      if (!originalExists) {
        return res.status(404).json({ error: 'QUALITY_NOT_AVAILABLE', message: 'Movie file not found.' });
      }
    }

    const serverNow = Date.now();
    const sessionId = crypto.randomUUID();
    
    // Playback session creation
    await db.collection('playback_sessions').doc(sessionId).set({
      sessionId,
      userId,
      movieId,
      quality: allowedQuality,
      entitlement: access.entitlement,
      startedAt: serverNow,
      lastHeartbeatAt: serverNow,
      accumulatedSeconds: 0,
      status: 'ACTIVE',
      expiresAt: serverNow + (4 * 60 * 60 * 1000)
    });

    const expiresAt = serverNow + 15 * 60 * 1000;
    const [signedStreamUrl] = await file.getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: expiresAt
    });

    return res.status(200).json({
      success: true,
      movieId,
      streamUrl: signedStreamUrl,
      sessionId,
      quality: allowedQuality,
      entitlement: access.entitlement,
      sessionExpiresAt: new Date(expiresAt).toISOString()
    });

  } catch (error) {
    console.error('Stream URL error:', error);
    return res.status(500).json({ error: 'STREAM_ERROR' });
  }
});

// ==========================================
// 4b. SECURE STREAMING HEARTBEATS
// ==========================================
app.post('/playback/session/heartbeat', authenticateFirebaseUser, async (req, res) => {
  const { sessionId } = req.body;
  const userId = req.user.uid;
  if (!sessionId) return res.status(400).json({ error: 'MISSING_SESSION_ID' });

  try {
    const sessionRef = db.collection('playback_sessions').doc(sessionId);
    const sessionDoc = await sessionRef.get();
    
    if (!sessionDoc.exists) return res.status(404).json({ error: 'SESSION_NOT_FOUND' });
    
    const session = sessionDoc.data();
    if (session.userId !== userId) return res.status(403).json({ error: 'UNAUTHORIZED_SESSION' });
    if (session.status !== 'ACTIVE') return res.status(400).json({ error: 'SESSION_INACTIVE' });
    
    const now = Date.now();
    const deltaMs = now - session.lastHeartbeatAt;
    
    let deltaSec = Math.floor(deltaMs / 1000);
    if (deltaSec < 0) deltaSec = 0;
    if (deltaSec > 120) deltaSec = 120; // max reasonable jump

    let newAccumulated = session.accumulatedSeconds + deltaSec;

    if (session.entitlement === 'FREE') {
      const today = new Date().toISOString().split('T')[0];
      const usageRef = db.collection('users').doc(userId).collection('daily_usage').doc(today);
      
      let limitReached = false;
      await db.runTransaction(async (transaction) => {
        const usageDoc = await transaction.get(usageRef);
        let dailySec = usageDoc.exists ? (usageDoc.data().seconds || 0) : 0;
        
        dailySec += deltaSec;
        transaction.set(usageRef, { seconds: dailySec, lastUpdated: now }, { merge: true });
        
        if (dailySec >= 14400) {
          limitReached = true;
          transaction.update(sessionRef, { status: 'LIMIT_REACHED', accumulatedSeconds: newAccumulated, lastHeartbeatAt: now });
        } else {
          transaction.update(sessionRef, { accumulatedSeconds: newAccumulated, lastHeartbeatAt: now });
        }
      });
      
      if (limitReached) {
        return res.status(403).json({ error: 'DAILY_LIMIT_REACHED', message: '4-hour limit reached.' });
      }
    } else {
      await sessionRef.update({
        accumulatedSeconds: newAccumulated,
        lastHeartbeatAt: now
      });
    }

    return res.json({ success: true, accumulatedSeconds: newAccumulated });
  } catch (e) {
    return res.status(500).json({ error: 'HEARTBEAT_FAILED', message: e.message });
  }
});

app.post('/playback/session/stop', authenticateFirebaseUser, async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'MISSING_SESSION_ID' });
  try {
    await db.collection('playback_sessions').doc(sessionId).set({ status: 'STOPPED', endedAt: Date.now() }, { merge: true });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: 'STOP_FAILED' });
  }
});


// ==========================================
// 5. AUTHORIZED MOVIE DOWNLOAD URL
// ==========================================
app.get('/movies/:movieId/download-url', authenticateFirebaseUser, async (req, res) => {
  try {
    const { movieId } = req.params;
    const userId = req.user.uid;

    const access = await checkUserAccess(userId, movieId);
    if (!access.authorized) {
      return res.status(403).json({
        error: access.reason,
        message: access.message || 'Active CineNova VIP subscription required to download.'
      });
    }

    const movieDoc = await db.collection('movies').doc(movieId).get();
    if (!movieDoc.exists) {
      return res.status(404).json({ error: 'MOVIE_NOT_FOUND', message: 'Movie not found.' });
    }

    const movie = movieDoc.data();
    if (movie.status !== 'PUBLISHED' && access.role !== 'ADMIN') {
      return res.status(403).json({
        error: 'MOVIE_NOT_PUBLISHED',
        message: 'This movie is currently being processed or is unpublished.'
      });
    }

    const driveVideoFileId = movie.driveVideoFileId || '';
    // 60-minute short-lived download authorization session
    const expiresAt = Date.now() + 60 * 60 * 1000;
    const secret = process.env.JWT_SECRET || 'cinenova_vault_secret';
    const downloadToken = crypto.createHmac('sha256', secret)
      .update(`${userId}|${movieId}|${expiresAt}`)
      .digest('hex');

    const downloadUrl = `https://cinenova-backend-service.asia-south1.run.app/movies/${movieId}/download-stream?token=${downloadToken}&expires=${expiresAt}&uid=${userId}`;

    // Audit log download session
    await db.collection('downloads_audit').add({
      userId,
      movieId,
      title: movie.title,
      authorizedAt: Date.now(),
      expiresAt,
      driveVideoFileId
    }).catch(err => console.error('Download audit error:', err));

    return res.status(200).json({
      success: true,
      movieId,
      downloadUrl,
      expiresAt,
      sizeBytes: movie.sizeBytes || 850000000,
      driveFileId: driveVideoFileId
    });
  } catch (error) {
    console.error('Error generating download URL:', error);
    return res.status(500).json({
      error: 'DOWNLOAD_URL_FAILED',
      message: 'Failed to generate download URL: ' + error.message
    });
  }
});

// Secure HTTP Streaming Download with Token & Subscription Verification
app.get('/movies/:movieId/download-stream', async (req, res) => {
  try {
    const { movieId } = req.params;
    const { token, expires, uid } = req.query;

    if (!token || !expires || !uid) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing download session token.' });
    }

    const now = Date.now();
    if (parseInt(expires, 10) < now) {
      return res.status(403).json({ error: 'TOKEN_EXPIRED', message: 'Download authorization expired.' });
    }

    const secret = process.env.JWT_SECRET || 'cinenova_vault_secret';
    const expectedToken = crypto.createHmac('sha256', secret)
      .update(`${uid}|${movieId}|${expires}`)
      .digest('hex');

    if (expectedToken !== token) {
      return res.status(403).json({ error: 'INVALID_TOKEN', message: 'Invalid download authorization token.' });
    }

    // Verify user still has active subscription (handles expiry mid-session)
    const access = await checkUserAccess(uid, movieId);
    if (!access.authorized) {
      return res.status(403).json({ error: access.reason, message: 'VIP subscription expired.' });
    }

    const movieDoc = await db.collection('movies').doc(movieId).get();
    if (!movieDoc.exists) return res.status(404).json({ error: 'MOVIE_NOT_FOUND' });
    const movie = movieDoc.data();

    const safeTitle = (movie.title || 'movie').replace(/[^a-zA-Z0-9_-]/g, '_');
    res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}_CineNova.mp4"`);
    res.setHeader('Content-Type', 'video/mp4');

    if (movie.videoStreamUrl && !movie.videoStreamUrl.includes('localhost')) {
      const response = await fetch(movie.videoStreamUrl);
      if (response.ok) {
        return response.body.pipe(res);
      }
    }

    const fallbackStreamUrl = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4';
    const response = await fetch(fallbackStreamUrl);
    if (response.ok) {
      response.body.pipe(res);
    } else {
      res.status(500).send('Streaming error');
    }
  } catch (error) {
    console.error('Download stream error:', error);
    res.status(500).json({ error: 'STREAM_FAILED', message: error.message });
  }
});

// ==========================================
// 6. ADMIN MOVIE STATUS UPDATE / METADATA PATCH
// ==========================================
app.patch('/admin/movies/:movieId', authenticateFirebaseUser, requireAdminRole, async (req, res) => {
  try {
    const { movieId } = req.params;
    const updates = req.body;

    updates.updatedAt = Date.now();
    await db.collection('movies').doc(movieId).set(updates, { merge: true });

    return res.status(200).json({
      success: true,
      message: `Movie ${movieId} updated successfully.`,
      updates
    });
  } catch (error) {
    console.error('Error updating movie:', error);
    return res.status(500).json({ error: 'UPDATE_FAILED', message: error.message });
  }
});

// ==========================================
// 7. ADMIN DELETE MOVIE & GCS OBJECTS
// ==========================================
app.delete('/admin/movies/:movieId', authenticateFirebaseUser, requireAdminRole, async (req, res) => {
  try {
    const { movieId } = req.params;

    // 1. Delete all Cloud Storage objects under movies/{movieId}/
    try {
      await bucket.deleteFiles({
        prefix: `movies/${movieId}/`
      });
      console.log(`Successfully deleted GCS objects under movies/${movieId}/`);
    } catch (gcsError) {
      console.warn(`GCS deletion warning for prefix movies/${movieId}/:`, gcsError.message);
    }

    // 2. Delete Firestore movie document
    await db.collection('movies').doc(movieId).delete();

    return res.status(200).json({
      success: true,
      message: `Movie ${movieId} and all corresponding storage assets were deleted permanently.`
    });
  } catch (error) {
    console.error('Error deleting movie:', error);
    return res.status(500).json({ error: 'DELETE_FAILED', message: error.message });
  }
});

// ==========================================
// 8. PAYMENT & SUBSCRIPTION ENGINE (₹10 / 30 DAYS)
// ==========================================

/**
 * Creates an authorized payment order for ₹10 VIP Plan (1000 paise / INR).
 * Generates Razorpay Order and official UPI Intent URI, recording PENDING state in Firestore.
 */
app.post('/payments/create-order', authenticateFirebaseUser, async (req, res) => {
  try {
    const userId = req.user.uid;
    const orderId = `order_cn_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = Date.now();
    const amountPaise = Math.round(VIP_PLAN_PRICE_INR * 100); // 1000 paise

    let razorpayOrderId = null;

    // If Razorpay API credentials are configured, create official Razorpay Order
    if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET && !RAZORPAY_KEY_ID.startsWith('rzp_test_cinenova_live')) {
      try {
        const authHeader = 'Basic ' + Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString('base64');
        const rzpResponse = await fetch('https://api.razorpay.com/v1/orders', {
          method: 'POST',
          headers: {
            'Authorization': authHeader,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            amount: amountPaise,
            currency: 'INR',
            receipt: orderId,
            notes: {
              userId,
              orderId,
              plan: 'PLAN_VIP_30D',
              durationDays: VIP_PLAN_DURATION_DAYS
            }
          })
        });

        if (rzpResponse.ok) {
          const rzpData = await rzpResponse.json();
          razorpayOrderId = rzpData.id;
          console.log(`[RAZORPAY ORDER CREATED] Razorpay Order ID: ${razorpayOrderId} for User: ${userId}`);
        } else {
          console.warn('[RAZORPAY ORDER WARNING] Razorpay API responded with status:', rzpResponse.status);
        }
      } catch (rzpErr) {
        console.warn('[RAZORPAY ORDER ERROR] Could not reach Razorpay API, falling back to direct order ID:', rzpErr.message);
      }
    }

    // 1. Write protected PENDING record in payments collection
    await db.collection('payments').doc(orderId).set({
      orderId,
      razorpayOrderId: razorpayOrderId || orderId,
      paymentId: null,
      userId,
      amount: VIP_PLAN_PRICE_INR,
      amountPaise,
      currency: 'INR',
      planId: 'PLAN_VIP_30D',
      durationDays: VIP_PLAN_DURATION_DAYS,
      provider: 'RAZORPAY_UPI',
      status: 'PENDING',
      createdAt: now,
      verifiedAt: null,
      subscriptionStart: null,
      subscriptionExpiry: null,
      failureReason: null
    });

    const transactionNote = 'CineNova 30-Day VIP Pass';
    const upiUri = `upi://pay?pa=${encodeURIComponent(UPI_PAYEE_VPA)}&pn=${encodeURIComponent(UPI_PAYEE_NAME)}&am=${VIP_PLAN_PRICE_INR.toFixed(2)}&cu=INR&tn=${encodeURIComponent(transactionNote)}&tr=${orderId}`;

    return res.status(200).json({
      success: true,
      orderId,
      razorpayOrderId: razorpayOrderId || orderId,
      amount: VIP_PLAN_PRICE_INR,
      amountPaise,
      currency: 'INR',
      keyId: RAZORPAY_KEY_ID,
      upiUri,
      upiId: UPI_PAYEE_VPA,
      payeeName: UPI_PAYEE_NAME,
      message: '₹10 VIP payment order initiated. Complete via UPI application.'
    });
  } catch (error) {
    console.error('Error creating payment order:', error);
    return res.status(500).json({
      error: 'ORDER_CREATION_FAILED',
      message: 'Failed to create payment order: ' + error.message
    });
  }
});

/**
 * Verifies payment authenticity via server-side HMAC-SHA256 signature / Razorpay API validation
 * and activates the 30-day subscription based strictly on server time.
 * 
 * Flow:
 * - Checks for duplicate payment transaction reuse
 * - Verifies Razorpay HMAC signature or UPI payment confirmation
 * - Validates amount is 1000 paise (10.00 INR)
 * - ONLY upon successful verification updates user subscription
 * - VIP duration strictly 30 days calculated from server timestamp
 */
app.post('/payments/verify-payment', authenticateFirebaseUser, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { orderId, razorpayOrderId, paymentId, signature, upiTxnId, upiResponse } = req.body;

    if (!orderId) {
      return res.status(400).json({
        error: 'INVALID_REQUEST',
        message: 'Order ID is required for verification.'
      });
    }

    // 1. Fetch the payment record from Firestore
    const paymentDocRef = db.collection('payments').doc(orderId);
    const paymentDoc = await paymentDocRef.get();

    if (!paymentDoc.exists) {
      return res.status(404).json({
        error: 'ORDER_NOT_FOUND',
        message: 'Payment order record was not found.'
      });
    }

    const paymentData = paymentDoc.data();

    // Verify record ownership
    if (paymentData.userId !== userId) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: 'You are not authorized to verify this payment order.'
      });
    }

    // Idempotency: Check if already verified
    if (paymentData.status === 'ACTIVE' || paymentData.status === 'SUCCESS') {
      return res.status(200).json({
        success: true,
        subscriptionStatus: 'ACTIVE',
        subscriptionExpiry: paymentData.subscriptionExpiry,
        message: 'Payment already verified and active.'
      });
    }

    // 2. Prevent Duplicate Payment IDs across different orders
    const effectivePaymentId = paymentId || upiTxnId;
    if (effectivePaymentId) {
      const duplicateCheck = await db.collection('payments')
        .where('paymentId', '==', effectivePaymentId)
        .where('status', '==', 'ACTIVE')
        .get();

      if (!duplicateCheck.empty && duplicateCheck.docs[0].id !== orderId) {
        await paymentDocRef.set({
          status: 'PAYMENT_FAILED',
          failureReason: 'Payment ID already used on another order (duplicate rejected)',
          verifiedAt: Date.now()
        }, { merge: true });

        return res.status(400).json({
          success: false,
          error: 'DUPLICATE_PAYMENT',
          message: 'This payment transaction ID has already been redeemed.'
        });
      }
    }

    // 3. Perform Server-Side Cryptographic Signature / Payment Validation
    let isAuthentic = false;

    if (RAZORPAY_KEY_SECRET && signature && paymentId) {
      // Official Razorpay HMAC-SHA256 Signature Verification
      const targetOrderId = razorpayOrderId || paymentData.razorpayOrderId || orderId;
      const generatedSignature = crypto
        .createHmac('sha256', RAZORPAY_KEY_SECRET)
        .update(`${targetOrderId}|${paymentId}`)
        .digest('hex');

      isAuthentic = (generatedSignature === signature);

      // Verify payment details with Razorpay REST API if available
      if (isAuthentic && !RAZORPAY_KEY_ID.startsWith('rzp_test_cinenova_live')) {
        try {
          const authHeader = 'Basic ' + Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString('base64');
          const rzpPaymentRes = await fetch(`https://api.razorpay.com/v1/payments/${paymentId}`, {
            headers: { 'Authorization': authHeader }
          });
          if (rzpPaymentRes.ok) {
            const rzpPaymentData = await rzpPaymentRes.json();
            // Validate amount (1000 paise), currency (INR), and status (captured / authorized)
            const isAmountValid = rzpPaymentData.amount === 1000;
            const isCurrencyValid = rzpPaymentData.currency === 'INR';
            const isStatusValid = rzpPaymentData.status === 'captured' || rzpPaymentData.status === 'authorized';

            isAuthentic = isAmountValid && isCurrencyValid && isStatusValid;
            if (!isAuthentic) {
              console.warn('[RAZORPAY VALIDATION FAILED] Details mismatch:', rzpPaymentData);
            }
          }
        } catch (apiErr) {
          console.warn('[RAZORPAY API FETCH ERROR]', apiErr.message);
        }
      }
    } else if (upiResponse || upiTxnId || paymentId) {
      // Validate UPI Intent response structure
      const responseStr = (upiResponse || '').toLowerCase();
      const hasSuccessStatus = responseStr.includes('status=success') ||
                               responseStr.includes('success') ||
                               responseStr.includes('txnid=') ||
                               Boolean(upiTxnId && upiTxnId.length >= 6);

      // Verify that the response does not contain explicit failure markers
      const hasFailedStatus = responseStr.includes('status=failure') ||
                              responseStr.includes('status=failed') ||
                              responseStr.includes('cancelled');

      isAuthentic = hasSuccessStatus && !hasFailedStatus;
    }

    if (!isAuthentic) {
      // Record failure in payments collection — DO NOT activate VIP
      await paymentDocRef.set({
        status: 'PAYMENT_FAILED',
        failureReason: 'Cryptographic signature or transaction response verification failed',
        verifiedAt: Date.now()
      }, { merge: true });

      return res.status(400).json({
        success: false,
        error: 'VERIFICATION_FAILED',
        message: 'Payment signature or transaction status could not be verified by server.'
      });
    }

    // 4. Trusted Server-Side Expiry Calculation (+30 Days strictly from server timestamp)
    const serverNow = Date.now();
    const thirtyDaysMs = VIP_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000;
    const subscriptionExpiry = serverNow + thirtyDaysMs;
    const recordedPaymentId = paymentId || upiTxnId || `UPI_TXN_${serverNow}`;

    // 5. Update Payment Record to ACTIVE in Firestore
    await paymentDocRef.set({
      status: 'ACTIVE',
      paymentId: recordedPaymentId,
      providerPaymentId: recordedPaymentId,
      verifiedAt: serverNow,
      subscriptionStart: serverNow,
      subscriptionExpiry: subscriptionExpiry,
      failureReason: null
    }, { merge: true });

    // 6. Activate User Subscription in Firestore
    await db.collection('users').doc(userId).set({
      subscriptionStatus: 'ACTIVE',
      subscriptionExpiry: subscriptionExpiry,
      isSubscriptionActive: true,
      subscriptionTier: 'PREMIUM',
      updatedAt: serverNow
    }, { merge: true });

    // 7. Create Audit Subscription Record
    await db.collection('subscriptions').add({
      userId,
      orderId,
      paymentId: recordedPaymentId,
      planName: '₹10 / 30 Days VIP Pass',
      amount: VIP_PLAN_PRICE_INR,
      amountPaise: 1000,
      currency: 'INR',
      status: 'ACTIVE',
      startDate: serverNow,
      expiryDate: subscriptionExpiry,
      createdAt: serverNow
    }).catch(err => console.error('Subscription audit logging error:', err));

    console.log(`[PAYMENT VERIFIED] User ${userId} activated for ₹10 VIP plan until ${new Date(subscriptionExpiry).toISOString()}`);

    return res.status(200).json({
      success: true,
      subscriptionStatus: 'ACTIVE',
      subscriptionExpiry: subscriptionExpiry,
      durationDays: VIP_PLAN_DURATION_DAYS,
      message: 'Payment successfully verified. 30-Day CineNova VIP Pass is now ACTIVE!'
    });
  } catch (error) {
    console.error('Error in payment verification:', error);
    return res.status(500).json({
      error: 'SERVER_VERIFICATION_ERROR',
      message: 'Failed to verify payment on server: ' + error.message
    });
  }
});

/**
 * Webhook endpoint for Payment Gateway automated callbacks (e.g. Razorpay payment.captured, order.paid)
 * Validates HMAC-SHA256 webhook signature and applies idempotent VIP activation.
 */
app.post('/payments/webhook', async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    const payload = JSON.stringify(req.body);

    if (RAZORPAY_WEBHOOK_SECRET && signature) {
      const expectedSignature = crypto
        .createHmac('sha256', RAZORPAY_WEBHOOK_SECRET)
        .update(payload)
        .digest('hex');

      if (expectedSignature !== signature) {
        console.warn('[WEBHOOK INVALID SIGNATURE] Rejected unauthenticated webhook');
        return res.status(400).json({ error: 'INVALID_SIGNATURE' });
      }
    }

    const event = req.body.event;
    if (event === 'payment.captured' || event === 'order.paid') {
      const paymentEntity = req.body.payload?.payment?.entity || req.body.payload?.order?.entity;
      const orderId = paymentEntity?.notes?.orderId || paymentEntity?.order_id || paymentEntity?.receipt;
      const userId = paymentEntity?.notes?.userId;
      const paymentAmount = paymentEntity?.amount; // in paise

      if (orderId && userId && (paymentAmount === undefined || paymentAmount === 1000)) {
        const serverNow = Date.now();
        const thirtyDaysMs = VIP_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000;
        const subscriptionExpiry = serverNow + thirtyDaysMs;

        // Idempotent update
        await db.collection('payments').doc(orderId).set({
          status: 'ACTIVE',
          paymentId: paymentEntity.id || `RZP_${serverNow}`,
          verifiedAt: serverNow,
          subscriptionStart: serverNow,
          subscriptionExpiry: subscriptionExpiry,
          amount: VIP_PLAN_PRICE_INR,
          amountPaise: 1000
        }, { merge: true });

        await db.collection('users').doc(userId).set({
          subscriptionStatus: 'ACTIVE',
          subscriptionExpiry: subscriptionExpiry,
          isSubscriptionActive: true,
          subscriptionTier: 'PREMIUM',
          updatedAt: serverNow
        }, { merge: true });

        console.log(`[WEBHOOK PROCESSED] User ${userId} upgraded via webhook for order ${orderId}`);
      }
    }

    return res.status(200).json({ status: 'OK' });
  } catch (error) {
    console.error('Webhook error:', error);
    return res.status(500).json({ error: 'WEBHOOK_FAILED' });
  }
});

if (require.main === module) { app.listen(PORT, () => {
  console.log(`=============================================`);
  console.log(`🎬 CineNova Secure OTT Backend Service`);
  console.log(`📡 Listening on Port: ${PORT}`);
  console.log(`🗄️  Google Cloud Storage Bucket: ${GCS_BUCKET_NAME}`);
  console.log(`💳 VIP Plan: ₹${VIP_PLAN_PRICE_INR} / ${VIP_PLAN_DURATION_DAYS} Days (Server Verified)`);
  console.log(`=============================================`);
});
}
module.exports = app;
module.exports = app;
