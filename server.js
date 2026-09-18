/**
 * CineNova Secure OTT Backend
 * Node.js / Express / Firebase Admin / Google Cloud Storage
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

const PORT = Number(process.env.PORT || 8080);

const PROJECT_ID =
  process.env.GOOGLE_CLOUD_PROJECT || 'cinenova-1232d';

const GCS_BUCKET_NAME =
  process.env.GCS_BUCKET_NAME ||
  'cinenova-1232d.firebasestorage.app';

const PUBLIC_BASE_URL =
  (process.env.PUBLIC_BASE_URL ||
    'https://cine-nova-bekend.onrender.com').replace(/\/$/, '');

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const RAZORPAY_WEBHOOK_SECRET =
  process.env.RAZORPAY_WEBHOOK_SECRET || '';

const UPI_PAYEE_VPA = process.env.UPI_PAYEE_VPA || '';
const UPI_PAYEE_NAME =
  process.env.UPI_PAYEE_NAME || 'CineNova';

const JWT_SECRET = process.env.JWT_SECRET || '';

const VIP_PLAN_PRICE_INR = 10;
const VIP_PLAN_DURATION_DAYS = 30;
const FREE_DAILY_LIMIT_SECONDS = 14400;

console.log('==============================================');
console.log('CineNova Backend Starting');
console.log('PROJECT_ID:', PROJECT_ID);
console.log('GCS_BUCKET_NAME:', GCS_BUCKET_NAME);
console.log('PUBLIC_BASE_URL:', PUBLIC_BASE_URL);
console.log(
  'FIREBASE_CONFIG_JSON:',
  process.env.FIREBASE_CONFIG_JSON ? 'PRESENT' : 'MISSING'
);
console.log(
  'RAZORPAY_KEY_ID:',
  RAZORPAY_KEY_ID ? 'PRESENT' : 'MISSING'
);
console.log(
  'RAZORPAY_KEY_SECRET:',
  RAZORPAY_KEY_SECRET ? 'PRESENT' : 'MISSING'
);
console.log(
  'RAZORPAY_WEBHOOK_SECRET:',
  RAZORPAY_WEBHOOK_SECRET ? 'PRESENT' : 'MISSING'
);
console.log('==============================================');

/* =========================================================
   FIREBASE ADMIN INITIALIZATION
========================================================= */

let serviceAccount = null;

if (process.env.FIREBASE_CONFIG_JSON) {
  try {
    serviceAccount = JSON.parse(
      process.env.FIREBASE_CONFIG_JSON
    );

    if (serviceAccount.private_key) {
      serviceAccount.private_key =
        serviceAccount.private_key.replace(/\\n/g, '\n');
    }

    console.log(
      '[FIREBASE] FIREBASE_CONFIG_JSON parsed successfully'
    );
  } catch (error) {
    console.error(
      '[FIREBASE] FIREBASE_CONFIG_JSON parse failed:',
      error.message
    );
    process.exit(1);
  }
}

try {
  if (!admin.apps.length) {
    if (serviceAccount) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id || PROJECT_ID
      });
    } else {
      admin.initializeApp({
        projectId: PROJECT_ID
      });
    }
  }

  console.log(
    '[FIREBASE] Admin SDK initialized successfully'
  );
} catch (error) {
  console.error(
    '[FIREBASE] Admin initialization failed:',
    error.message
  );
  process.exit(1);
}

const db = admin.firestore();
const auth = admin.auth();

/* =========================================================
   GOOGLE CLOUD STORAGE INITIALIZATION
========================================================= */

let storage;

try {
  if (serviceAccount) {
    storage = new Storage({
      projectId:
        serviceAccount.project_id || PROJECT_ID,
      credentials: {
        client_email: serviceAccount.client_email,
        private_key: serviceAccount.private_key
          ? serviceAccount.private_key.replace(/\\n/g, '\n')
          : undefined
      }
    });
  } else {
    storage = new Storage({
      projectId: PROJECT_ID
    });
  }

  console.log(
    '[GCS] Storage client initialized successfully'
  );
} catch (error) {
  console.error(
    '[GCS] Storage initialization failed:',
    error.message
  );
  process.exit(1);
}

const bucket = storage.bucket(GCS_BUCKET_NAME);

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

/* =========================================================
   ADMIN USERS
========================================================= */

const DESIGNATED_ADMIN_EMAILS = [
  'abhisheksuniyar737@gmail.com',
  'abisheksuniyar737@gmail.com',
  'abhibosshk@gmail.com'
];

/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticateFirebaseUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';

    if (
      !authHeader ||
      !authHeader.toLowerCase().startsWith('bearer ')
    ) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Valid Firebase Bearer token required.'
      });
    }

    const idToken = authHeader.slice(7).trim();

    if (!idToken) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Firebase ID token is empty.'
      });
    }

    const decodedToken =
      await auth.verifyIdToken(idToken);

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error(
      '[AUTH ERROR]',
      error.message
    );

    return res.status(401).json({
      error: 'INVALID_TOKEN',
      message:
        'Firebase ID token expired or invalid.'
    });
  }
}

/* =========================================================
   ADMIN ROLE
========================================================= */

async function requireAdminRole(req, res, next) {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required.'
      });
    }

    if (
      req.user.admin === true ||
      req.user.role === 'ADMIN'
    ) {
      return next();
    }

    const email =
      (req.user.email || '').toLowerCase();

    if (
      email &&
      DESIGNATED_ADMIN_EMAILS.includes(email)
    ) {
      return next();
    }

    const userDoc = await db
      .collection('users')
      .doc(req.user.uid)
      .get();

    if (!userDoc.exists) {
      return res.status(403).json({
        error: 'ACCESS_DENIED',
        message: 'User profile not found.'
      });
    }

    const userData = userDoc.data();

    if (
      userData.role !== 'ADMIN' ||
      userData.isBlocked === true
    ) {
      return res.status(403).json({
        error: 'ACCESS_DENIED',
        message: 'Administrator permissions required.'
      });
    }

    req.adminData = userData;

    next();
  } catch (error) {
    console.error(
      '[ADMIN ROLE ERROR]',
      error.message
    );

    return res.status(500).json({
      error: 'ADMIN_CHECK_FAILED',
      message: 'Failed to verify administrator role.'
    });
  }
}

/* =========================================================
   USER ACCESS
========================================================= */

async function checkUserAccess(userId, movieId) {
  try {
    const userDoc = await db
      .collection('users')
      .doc(userId)
      .get();

    if (!userDoc.exists) {
      return {
        authorized: false,
        reason: 'USER_NOT_FOUND'
      };
    }

    const user = userDoc.data();

    if (user.isBlocked === true) {
      return {
        authorized: false,
        reason: 'ACCOUNT_BLOCKED'
      };
    }

    if (user.role === 'ADMIN') {
      return {
        authorized: true,
        role: 'ADMIN',
        entitlement: 'PREMIUM'
      };
    }

    const now = Date.now();

    const status =
      user.subscriptionStatus || 'FREE';

    const expiry =
      Number(user.subscriptionExpiry || 0);

    const premium =
      (status === 'ACTIVE' ||
        status === 'PREMIUM') &&
      expiry > now;

    if (premium) {
      return {
        authorized: true,
        role: 'USER',
        entitlement: 'PREMIUM'
      };
    }

    return {
      authorized: true,
      role: 'USER',
      entitlement: 'FREE'
    };
  } catch (error) {
    console.error(
      '[ACCESS CHECK]',
      error.message
    );

    return {
      authorized: false,
      reason: 'VERIFICATION_FAILED'
    };
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'HEALTHY',
    service: 'CineNova Secure OTT Backend',
    projectId: PROJECT_ID,
    bucket: GCS_BUCKET_NAME,
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   DIAGNOSTICS
========================================================= */

app.get('/admin/diagnostics', (req, res) => {
  res.json({
    status: 'OK',
    firebaseInitialized: admin.apps.length > 0,
    projectId: PROJECT_ID,
    bucket: GCS_BUCKET_NAME,
    firebaseConfigPresent:
      !!process.env.FIREBASE_CONFIG_JSON,
    razorpayConfigured:
      !!(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET),
    publicBaseUrl: PUBLIC_BASE_URL
  });
});

/* =========================================================
   ADMIN CREATE GCS UPLOAD SESSION
========================================================= */

app.post(
  '/admin/movies/create-upload-session',
  authenticateFirebaseUser,
  requireAdminRole,
  async (req, res) => {
    try {
      const {
        movieId,
        fileName,
        contentType,
        fileCategory
      } = req.body;

      if (!movieId || !fileName) {
        return res.status(400).json({
          error: 'BAD_REQUEST',
          message:
            'movieId and fileName are required.'
        });
      }

      let destinationPath;

      if (fileCategory === 'video') {
        destinationPath =
          `movies/${movieId}/video/original/${fileName}`;
      } else if (fileCategory === 'poster') {
        destinationPath =
          `movies/${movieId}/poster/${fileName}`;
      } else if (fileCategory === 'banner') {
        destinationPath =
          `movies/${movieId}/banner/${fileName}`;
      } else {
        destinationPath =
          `movies/${movieId}/media/${fileName}`;
      }

      const file =
        bucket.file(destinationPath);

      console.log(
        `[GCS] Creating signed upload URL: ${destinationPath}`
      );

      const [uploadUrl] =
        await file.getSignedUrl({
          version: 'v4',
          action: 'write',
          expires:
            Date.now() + 60 * 60 * 1000,
          contentType:
            contentType ||
            'application/octet-stream'
        });

      await db
        .collection('movies')
        .doc(movieId)
        .set(
          {
            id: movieId,
            status: 'UPLOADING',
            updatedAt: Date.now(),
            createdBy: req.user.uid,

            ...(fileCategory === 'video'
              ? {
                  videoObjectPath:
                    destinationPath
                }
              : {}),

            ...(fileCategory === 'poster'
              ? {
                  posterPath:
                    destinationPath
                }
              : {}),

            ...(fileCategory === 'banner'
              ? {
                  bannerPath:
                    destinationPath
                }
              : {})
          },
          { merge: true }
        );

      return res.status(200).json({
        success: true,
        movieId,
        objectPath: destinationPath,
        uploadUrl,
        expiresInMinutes: 60
      });
    } catch (error) {
      console.error(
        '[GCS UPLOAD SESSION ERROR]',
        error
      );

      return res.status(500).json({
        error: 'UPLOAD_SESSION_FAILED',
        message:
          error.message ||
          'Failed to create GCS upload session.'
      });
    }
  }
);

/* =========================================================
   GOOGLE DRIVE OAUTH
========================================================= */

async function exchangeGoogleServerAuthCode(
  authCode
) {
  const clientId =
    process.env.GOOGLE_WEB_CLIENT_ID || '';

  const clientSecret =
    process.env.GOOGLE_WEB_CLIENT_SECRET || '';

  if (!clientId || !clientSecret) {
    throw new Error(
      'Google OAuth server credentials are missing.'
    );
  }

  const params = new URLSearchParams({
    code: authCode,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: '',
    grant_type: 'authorization_code'
  });

  const response = await fetch(
    'https://oauth2.googleapis.com/token',
    {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },
      body: params.toString()
    }
  );

  const body =
    await response.text();

  if (!response.ok) {
    let detail = body;

    try {
      const parsed =
        JSON.parse(body);

      detail =
        parsed.error_description ||
        parsed.error ||
        body;
    } catch (_) {}

    throw new Error(
      `Google OAuth exchange failed: ${detail}`
    );
  }

  const data =
    JSON.parse(body);

  if (!data.access_token) {
    throw new Error(
      'Google did not return an access token.'
    );
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || null
  };
}

async function refreshGoogleDriveAccessToken(
  refreshToken
) {
  const clientId =
    process.env.GOOGLE_WEB_CLIENT_ID || '';

  const clientSecret =
    process.env.GOOGLE_WEB_CLIENT_SECRET || '';

  if (
    !clientId ||
    !clientSecret ||
    !refreshToken
  ) {
    return null;
  }

  const params = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'refresh_token'
  });

  const response = await fetch(
    'https://oauth2.googleapis.com/token',
    {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },
      body: params.toString()
    }
  );

  if (!response.ok) {
    return null;
  }

  const data =
    await response.json();

  return data.access_token || null;
}

/* =========================================================
   GOOGLE DRIVE -> GCS
========================================================= */

app.post(
  '/admin/movies/import-from-drive',
  authenticateFirebaseUser,
  requireAdminRole,
  async (req, res) => {
    let gcsFile = null;

    try {
      const {
        movieId,
        driveFileId,
        serverAuthCode,
        authCode,
        fileCategory = 'video'
      } = req.body;

      if (!movieId || !driveFileId) {
        return res.status(400).json({
          success: false,
          error: 'BAD_REQUEST',
          message:
            'movieId and driveFileId are required.'
        });
      }

      let destinationPath;

      if (fileCategory === 'video') {
        destinationPath =
          `movies/${movieId}/video/original/movie.mp4`;
      } else if (fileCategory === 'poster') {
        destinationPath =
          `movies/${movieId}/poster/poster.jpg`;
      } else if (fileCategory === 'banner') {
        destinationPath =
          `movies/${movieId}/banner/banner.jpg`;
      } else {
        destinationPath =
          `movies/${movieId}/media/${driveFileId}`;
      }

      gcsFile =
        bucket.file(destinationPath);

      const [existing] =
        await gcsFile.exists();

      if (existing) {
        const [metadata] =
          await gcsFile.getMetadata();

        const size =
          Number(metadata.size || 0);

        if (size > 0) {
          await db
            .collection('movies')
            .doc(movieId)
            .set(
              {
                id: movieId,
                driveVideoFileId:
                  driveFileId,
                videoObjectPath:
                  destinationPath,
                assetSize: size,
                storageProvider:
                  'GCS_PRIVATE',
                importStatus:
                  'COMPLETED',
                updatedAt: Date.now()
              },
              { merge: true }
            );

          return res.json({
            success: true,
            movieId,
            destinationPath,
            assetSize: size,
            message:
              'Existing cloud asset reused.'
          });
        }
      }

      const code =
        serverAuthCode || authCode;

      if (!code) {
        return res.status(400).json({
          success: false,
          error:
            'SERVER_AUTH_CODE_REQUIRED',
          message:
            'Secure Google serverAuthCode is required.'
        });
      }

      let tokenData;

      try {
        tokenData =
          await exchangeGoogleServerAuthCode(
            code
          );
      } catch (error) {
        console.error(
          '[DRIVE OAUTH]',
          error.message
        );

        return res.status(400).json({
          success: false,
          error:
            'OAUTH_EXCHANGE_FAILED',
          message:
            error.message
        });
      }

      let accessToken =
        tokenData.accessToken;

      const driveUrl =
        `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(
          driveFileId
        )}?alt=media&supportsAllDrives=true`;

      let driveResponse =
        await fetch(driveUrl, {
          headers: {
            Authorization:
              `Bearer ${accessToken}`
          }
        });

      if (
        driveResponse.status === 401 &&
        tokenData.refreshToken
      ) {
        const refreshed =
          await refreshGoogleDriveAccessToken(
            tokenData.refreshToken
          );

        if (refreshed) {
          accessToken = refreshed;

          driveResponse =
            await fetch(driveUrl, {
              headers: {
                Authorization:
                  `Bearer ${accessToken}`
              }
            });
        }
      }

      if (!driveResponse.ok) {
        return res.status(
          driveResponse.status
        ).json({
          success: false,
          error:
            'DRIVE_FETCH_FAILED',
          message:
            `Google Drive returned HTTP ${driveResponse.status}.`
        });
      }

      await new Promise(
        (resolve, reject) => {
          const writeStream =
            gcsFile.createWriteStream({
              resumable: true,
              metadata: {
                contentType:
                  driveResponse.headers.get(
                    'content-type'
                  ) || 'video/mp4',
                metadata: {
                  originalDriveFileId:
                    driveFileId,
                  importedBy:
                    req.user.uid,
                  importedAt:
                    new Date().toISOString()
                }
              }
            });

          let readStream =
            driveResponse.body;

          if (
            Readable.fromWeb &&
            driveResponse.body &&
            typeof driveResponse.body.pipe !==
              'function'
          ) {
            readStream =
              Readable.fromWeb(
                driveResponse.body
              );
          }

          if (
            !readStream ||
            typeof readStream.pipe !==
              'function'
          ) {
            return reject(
              new Error(
                'Google Drive response stream is unavailable.'
              )
            );
          }

          writeStream.on(
            'error',
            reject
          );

          readStream.on(
            'error',
            reject
          );

          writeStream.on(
            'finish',
            resolve
          );

          readStream.pipe(
            writeStream
          );
        }
      );

      const [exists] =
        await gcsFile.exists();

      if (!exists) {
        return res.status(500).json({
          success: false,
          error:
            'VERIFICATION_FAILED',
          message:
            'GCS object was not created.'
        });
      }

      const [metadata] =
        await gcsFile.getMetadata();

      const assetSize =
        Number(metadata.size || 0);

      if (assetSize <= 0) {
        await gcsFile.delete({
          ignoreNotFound: true
        });

        return res.status(500).json({
          success: false,
          error:
            'EMPTY_ASSET_CORRUPTED',
          message:
            'Imported file is empty.'
        });
      }

      await db
        .collection('movies')
        .doc(movieId)
        .set(
          {
            id: movieId,
            driveVideoFileId:
              driveFileId,
            videoObjectPath:
              destinationPath,
            assetSize,
            storageProvider:
              'GCS_PRIVATE',
            importStatus:
              'COMPLETED',
            updatedAt: Date.now()
          },
          { merge: true }
        );

      return res.json({
        success: true,
        movieId,
        copiedDriveFileId:
          driveFileId,
        destinationPath,
        assetSize,
        message:
          'Google Drive file imported successfully.'
      });
    } catch (error) {
      console.error(
        '[DRIVE IMPORT ERROR]',
        error
      );

      if (gcsFile) {
        await gcsFile
          .delete({
            ignoreNotFound: true
          })
          .catch(() => {});
      }

      return res.status(500).json({
        success: false,
        error:
          'DRIVE_IMPORT_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   FINALIZE MOVIE
========================================================= */

app.post(
  '/admin/movies/finalize-upload',
  authenticateFirebaseUser,
  requireAdminRole,
  async (req, res) => {
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
          message:
            'movieId and title are required.'
        });
      }

      const finalVideoPath =
        videoObjectPath ||
        `movies/${movieId}/video/original/movie.mp4`;

      const [videoExists] =
        await bucket
          .file(finalVideoPath)
          .exists();

      if (!videoExists) {
        return res.status(400).json({
          error:
            'VIDEO_NOT_FOUND',
          message:
            'Movie video is not present in private GCS storage.'
        });
      }

      const status =
        publishImmediately
          ? 'PUBLISHED'
          : 'READY';

      const movieDocument = {
        id: movieId,
        title: String(title),
        description:
          description || '',
        genre:
          genre || '',
        language:
          language || '',
        releaseYear:
          Number(releaseYear) ||
          new Date().getFullYear(),
        durationMinutes:
          Number(durationMinutes) || 0,
        rating:
          Number(rating) || 0,
        maturityRating:
          maturityRating || '',
        qualityBadge:
          qualityBadge || '',
        isFeatured:
          Boolean(isFeatured),
        isTrending:
          Boolean(isTrending),
        posterPath:
          posterPath || null,
        bannerPath:
          bannerPath || null,
        videoObjectPath:
          finalVideoPath,
        status,
        createdBy:
          req.user.uid,
        createdAt:
          req.body.createdAt ||
          Date.now(),
        updatedAt:
          Date.now(),
        storageProvider:
          'GCS_PRIVATE'
      };

      await db
        .collection('movies')
        .doc(movieId)
        .set(
          movieDocument,
          { merge: true }
        );

      return res.json({
        success: true,
        message:
          `Movie saved with status ${status}.`,
        movie: movieDocument
      });
    } catch (error) {
      console.error(
        '[FINALIZE ERROR]',
        error
      );

      return res.status(500).json({
        error:
          'FINALIZE_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   SECURE STREAM URL
========================================================= */

app.get(
  '/movies/:movieId/stream-url',
  authenticateFirebaseUser,
  async (req, res) => {
    try {
      const {
        movieId
      } = req.params;

      const access =
        await checkUserAccess(
          req.user.uid,
          movieId
        );

      if (!access.authorized) {
        return res.status(403).json({
          error:
            access.reason
        });
      }

      const movieDoc =
        await db
          .collection('movies')
          .doc(movieId)
          .get();

      if (!movieDoc.exists) {
        return res.status(404).json({
          error:
            'MOVIE_NOT_FOUND'
        });
      }

      const movie =
        movieDoc.data();

      if (
        movie.status !== 'PUBLISHED' &&
        access.role !== 'ADMIN'
      ) {
        return res.status(403).json({
          error:
            'MOVIE_NOT_PUBLISHED'
        });
      }

      if (
        access.entitlement === 'FREE'
      ) {
        const today =
          new Date()
            .toISOString()
            .split('T')[0];

        const usageDoc =
          await db
            .collection('users')
            .doc(req.user.uid)
            .collection('daily_usage')
            .doc(today)
            .get();

        const seconds =
          Number(
            usageDoc.data()?.seconds || 0
          );

        if (
          seconds >=
          FREE_DAILY_LIMIT_SECONDS
        ) {
          return res.status(403).json({
            error:
              'DAILY_LIMIT_REACHED',
            message:
              '4-hour daily free limit reached.'
          });
        }
      }

      const requestedQuality =
        String(
          req.query.q || '480p'
        );

      let allowedQuality =
        '480p';

      if (
        access.entitlement ===
          'PREMIUM' ||
        access.role === 'ADMIN'
      ) {
        if (
          [
            '480p',
            '720p',
            '1080p',
            '4K'
          ].includes(
            requestedQuality
          )
        ) {
          allowedQuality =
            requestedQuality;
        }
      } else if (
        requestedQuality !== '480p'
      ) {
        return res.status(403).json({
          error:
            'SUBSCRIPTION_REQUIRED',
          message:
            'Premium subscription required.'
        });
      }

      let targetPath =
        `movies/${movieId}/video/${allowedQuality}/movie.mp4`;

      let file =
        bucket.file(targetPath);

      let [exists] =
        await file.exists();

      if (!exists) {
        if (
          allowedQuality !==
          '480p'
        ) {
          return res.status(404).json({
            error:
              'QUALITY_NOT_AVAILABLE',
            message:
              'Requested quality is not available.'
          });
        }

        targetPath =
          movie.videoObjectPath;

        if (!targetPath) {
          return res.status(404).json({
            error:
              'MOVIE_FILE_NOT_FOUND'
          });
        }

        file =
          bucket.file(targetPath);

        [exists] =
          await file.exists();

        if (!exists) {
          return res.status(404).json({
            error:
              'MOVIE_FILE_NOT_FOUND'
          });
        }
      }

      const now =
        Date.now();

      const sessionId =
        crypto.randomUUID();

      await db
        .collection(
          'playback_sessions'
        )
        .doc(sessionId)
        .set({
          sessionId,
          userId:
            req.user.uid,
          movieId,
          quality:
            allowedQuality,
          entitlement:
            access.entitlement,
          startedAt:
            now,
          lastHeartbeatAt:
            now,
          accumulatedSeconds:
            0,
          status:
            'ACTIVE',
          expiresAt:
            now +
            4 * 60 * 60 * 1000
        });

      const expiresAt =
        now +
        15 * 60 * 1000;

      const [
        signedStreamUrl
      ] =
        await file.getSignedUrl({
          version: 'v4',
          action: 'read',
          expires: expiresAt
        });

      return res.json({
        success: true,
        movieId,
        streamUrl:
          signedStreamUrl,
        sessionId,
        quality:
          allowedQuality,
        entitlement:
          access.entitlement,
        sessionExpiresAt:
          new Date(
            expiresAt
          ).toISOString()
      });
    } catch (error) {
      console.error(
        '[STREAM URL ERROR]',
        error
      );

      return res.status(500).json({
        error:
          'STREAM_ERROR',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   PLAYBACK HEARTBEAT
========================================================= */

app.post(
  '/playback/session/heartbeat',
  authenticateFirebaseUser,
  async (req, res) => {
    try {
      const {
        sessionId
      } = req.body;

      if (!sessionId) {
        return res.status(400).json({
          error:
            'MISSING_SESSION_ID'
        });
      }

      const sessionRef =
        db
          .collection(
            'playback_sessions'
          )
          .doc(sessionId);

      const sessionDoc =
        await sessionRef.get();

      if (!sessionDoc.exists) {
        return res.status(404).json({
          error:
            'SESSION_NOT_FOUND'
        });
      }

      const session =
        sessionDoc.data();

      if (
        session.userId !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            'UNAUTHORIZED_SESSION'
        });
      }

      if (
        session.status !==
        'ACTIVE'
      ) {
        return res.status(400).json({
          error:
            'SESSION_INACTIVE'
        });
      }

      const now =
        Date.now();

      let delta =
        Math.floor(
          (now -
            Number(
              session.lastHeartbeatAt ||
                now
            )) /
            1000
        );

      if (delta < 0) {
        delta = 0;
      }

      if (delta > 120) {
        delta = 120;
      }

      const accumulated =
        Number(
          session.accumulatedSeconds ||
            0
        ) + delta;

      if (
        session.entitlement ===
        'FREE'
      ) {
        const today =
          new Date()
            .toISOString()
            .split('T')[0];

        const usageRef =
          db
            .collection('users')
            .doc(req.user.uid)
            .collection(
              'daily_usage'
            )
            .doc(today);

        let limitReached =
          false;

        await db.runTransaction(
          async transaction => {
            const usageDoc =
              await transaction.get(
                usageRef
              );

            const daily =
              Number(
                usageDoc.data()?.seconds ||
                  0
              );

            const newDaily =
              daily + delta;

            transaction.set(
              usageRef,
              {
                seconds:
                  newDaily,
                lastUpdated:
                  now
              },
              { merge: true }
            );

            if (
              newDaily >=
              FREE_DAILY_LIMIT_SECONDS
            ) {
              limitReached =
                true;
            }

            transaction.update(
              sessionRef,
              {
                accumulatedSeconds:
                  accumulated,
                lastHeartbeatAt:
                  now,
                ...(limitReached
                  ? {
                      status:
                        'LIMIT_REACHED'
                    }
                  : {})
              }
            );
          }
        );

        if (limitReached) {
          return res.status(403).json({
            error:
              'DAILY_LIMIT_REACHED'
          });
        }
      } else {
        await sessionRef.update({
          accumulatedSeconds:
            accumulated,
          lastHeartbeatAt:
            now
        });
      }

      return res.json({
        success: true,
        accumulatedSeconds:
          accumulated
      });
    } catch (error) {
      console.error(
        '[HEARTBEAT ERROR]',
        error
      );

      return res.status(500).json({
        error:
          'HEARTBEAT_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   PLAYBACK STOP
========================================================= */

app.post(
  '/playback/session/stop',
  authenticateFirebaseUser,
  async (req, res) => {
    try {
      const {
        sessionId
      } = req.body;

      if (!sessionId) {
        return res.status(400).json({
          error:
            'MISSING_SESSION_ID'
        });
      }

      const ref =
        db
          .collection(
            'playback_sessions'
          )
          .doc(sessionId);

      const doc =
        await ref.get();

      if (
        !doc.exists
      ) {
        return res.status(404).json({
          error:
            'SESSION_NOT_FOUND'
        });
      }

      if (
        doc.data().userId !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            'UNAUTHORIZED_SESSION'
        });
      }

      await ref.set(
        {
          status:
            'STOPPED',
          endedAt:
            Date.now()
        },
        { merge: true }
      );

      return res.json({
        success: true
      });
    } catch (error) {
      return res.status(500).json({
        error:
          'STOP_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   DOWNLOAD URL
========================================================= */

app.get(
  '/movies/:movieId/download-url',
  authenticateFirebaseUser,
  async (req, res) => {
    try {
      const {
        movieId
      } = req.params;

      const access =
        await checkUserAccess(
          req.user.uid,
          movieId
        );

      if (
        !access.authorized ||
        access.entitlement !==
          'PREMIUM'
      ) {
        return res.status(403).json({
          error:
            'PREMIUM_REQUIRED',
          message:
            'Active Premium subscription required.'
        });
      }

      const movieDoc =
        await db
          .collection('movies')
          .doc(movieId)
          .get();

      if (!movieDoc.exists) {
        return res.status(404).json({
          error:
            'MOVIE_NOT_FOUND'
        });
      }

      const movie =
        movieDoc.data();

      if (
        movie.status !==
          'PUBLISHED' &&
        access.role !==
          'ADMIN'
      ) {
        return res.status(403).json({
          error:
            'MOVIE_NOT_PUBLISHED'
        });
      }

      const path =
        movie.videoObjectPath;

      if (!path) {
        return res.status(404).json({
          error:
            'VIDEO_NOT_FOUND'
        });
      }

      const file =
        bucket.file(path);

      const [exists] =
        await file.exists();

      if (!exists) {
        return res.status(404).json({
          error:
            'VIDEO_NOT_FOUND'
        });
      }

      const expiresAt =
        Date.now() +
        60 * 60 * 1000;

      const [
        downloadUrl
      ] =
        await file.getSignedUrl({
          version: 'v4',
          action: 'read',
          expires: expiresAt
        });

      await db
        .collection(
          'downloads_audit'
        )
        .add({
          userId:
            req.user.uid,
          movieId,
          title:
            movie.title || '',
          authorizedAt:
            Date.now(),
          expiresAt
        });

      return res.json({
        success: true,
        movieId,
        downloadUrl,
        expiresAt
      });
    } catch (error) {
      console.error(
        '[DOWNLOAD URL ERROR]',
        error
      );

      return res.status(500).json({
        error:
          'DOWNLOAD_URL_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   ADMIN MOVIE PATCH
========================================================= */

app.patch(
  '/admin/movies/:movieId',
  authenticateFirebaseUser,
  requireAdminRole,
  async (req, res) => {
    try {
      const {
        movieId
      } = req.params;

      const updates = {
        ...req.body,
        updatedAt:
          Date.now()
      };

      delete updates.createdBy;
      delete updates.createdAt;

      await db
        .collection('movies')
        .doc(movieId)
        .set(
          updates,
          { merge: true }
        );

      return res.json({
        success: true,
        updates
      });
    } catch (error) {
      return res.status(500).json({
        error:
          'UPDATE_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   ADMIN DELETE MOVIE
========================================================= */

app.delete(
  '/admin/movies/:movieId',
  authenticateFirebaseUser,
  requireAdminRole,
  async (req, res) => {
    try {
      const {
        movieId
      } = req.params;

      await bucket.deleteFiles({
        prefix:
          `movies/${movieId}/`
      });

      await db
        .collection('movies')
        .doc(movieId)
        .delete();

      return res.json({
        success: true,
        message:
          'Movie and storage assets deleted.'
      });
    } catch (error) {
      console.error(
        '[DELETE MOVIE]',
        error
      );

      return res.status(500).json({
        error:
          'DELETE_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   PAYMENT ORDER
========================================================= */

app.post(
  '/payments/create-order',
  authenticateFirebaseUser,
  async (req, res) => {
    try {
      if (
        !RAZORPAY_KEY_ID ||
        !RAZORPAY_KEY_SECRET
      ) {
        return res.status(503).json({
          error:
            'PAYMENT_NOT_CONFIGURED',
          message:
            'Razorpay credentials are not configured on the server.'
        });
      }

      const userId =
        req.user.uid;

      const localOrderId =
        `cn_${Date.now()}_${crypto
          .randomBytes(4)
          .toString('hex')}`;

      const amountPaise =
        1000;

      const authHeader =
        'Basic ' +
        Buffer.from(
          `${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`
        ).toString('base64');

      const response =
        await fetch(
          'https://api.razorpay.com/v1/orders',
          {
            method: 'POST',
            headers: {
              Authorization:
                authHeader,
              'Content-Type':
                'application/json'
            },
            body:
              JSON.stringify({
                amount:
                  amountPaise,
                currency:
                  'INR',
                receipt:
                  localOrderId,
                notes: {
                  userId,
                  localOrderId,
                  plan:
                    'PLAN_VIP_30D'
                }
              })
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        console.error(
          '[RAZORPAY ORDER]',
          data
        );

        return res.status(502).json({
          error:
            'RAZORPAY_ORDER_FAILED',
          message:
            'Razorpay order creation failed.'
        });
      }

      await db
        .collection('payments')
        .doc(localOrderId)
        .set({
          orderId:
            localOrderId,
          razorpayOrderId:
            data.id,
          userId,
          amount:
            10,
          amountPaise:
            1000,
          currency:
            'INR',
          planId:
            'PLAN_VIP_30D',
          durationDays:
            30,
          provider:
            'RAZORPAY',
          status:
            'PENDING',
          createdAt:
            Date.now()
        });

      return res.json({
        success: true,
        orderId:
          localOrderId,
        razorpayOrderId:
          data.id,
        amount:
          10,
        amountPaise:
          1000,
        currency:
          'INR',
        keyId:
          RAZORPAY_KEY_ID
      });
    } catch (error) {
      console.error(
        '[CREATE ORDER]',
        error
      );

      return res.status(500).json({
        error:
          'ORDER_CREATION_FAILED',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   RAZORPAY PAYMENT VERIFY
========================================================= */

app.post(
  '/payments/verify-payment',
  authenticateFirebaseUser,
  async (req, res) => {
    try {
      const {
        orderId,
        razorpayOrderId,
        paymentId,
        signature
      } = req.body;

      if (
        !orderId ||
        !paymentId ||
        !signature
      ) {
        return res.status(400).json({
          error:
            'INVALID_REQUEST',
          message:
            'orderId, paymentId and signature are required.'
        });
      }

      if (!RAZORPAY_KEY_SECRET) {
        return res.status(503).json({
          error:
            'PAYMENT_NOT_CONFIGURED'
        });
      }

      const paymentRef =
        db
          .collection('payments')
          .doc(orderId);

      const paymentDoc =
        await paymentRef.get();

      if (!paymentDoc.exists) {
        return res.status(404).json({
          error:
            'ORDER_NOT_FOUND'
        });
      }

      const payment =
        paymentDoc.data();

      if (
        payment.userId !==
        req.user.uid
      ) {
        return res.status(403).json({
          error:
            'FORBIDDEN'
        });
      }

      if (
        payment.status ===
        'ACTIVE'
      ) {
        return res.json({
          success: true,
          subscriptionStatus:
            'ACTIVE',
          subscriptionExpiry:
            payment.subscriptionExpiry
        });
      }

      const targetOrderId =
        razorpayOrderId ||
        payment.razorpayOrderId;

      const expectedSignature =
        crypto
          .createHmac(
            'sha256',
            RAZORPAY_KEY_SECRET
          )
          .update(
            `${targetOrderId}|${paymentId}`
          )
          .digest('hex');

      const signatureValid =
        crypto.timingSafeEqual(
          Buffer.from(
            expectedSignature,
            'utf8'
          ),
          Buffer.from(
            signature,
            'utf8'
          )
        );

      if (!signatureValid) {
        return res.status(400).json({
          success: false,
          error:
            'VERIFICATION_FAILED'
        });
      }

      const basicAuth =
        'Basic ' +
        Buffer.from(
          `${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`
        ).toString('base64');

      const paymentResponse =
        await fetch(
          `https://api.razorpay.com/v1/payments/${encodeURIComponent(
            paymentId
          )}`,
          {
            headers: {
              Authorization:
                basicAuth
            }
          }
        );

      if (!paymentResponse.ok) {
        return res.status(400).json({
          success: false,
          error:
            'PAYMENT_LOOKUP_FAILED'
        });
      }

      const razorpayPayment =
        await paymentResponse.json();

      if (
        razorpayPayment.order_id !==
          targetOrderId ||
        Number(
          razorpayPayment.amount
        ) !== 1000 ||
        razorpayPayment.currency !==
          'INR' ||
        razorpayPayment.status !==
          'captured'
      ) {
        return res.status(400).json({
          success: false,
          error:
            'PAYMENT_VALIDATION_FAILED'
        });
      }

      const now =
        Date.now();

      const expiry =
        now +
        VIP_PLAN_DURATION_DAYS *
          24 *
          60 *
          60 *
          1000;

      await paymentRef.set(
        {
          status:
            'ACTIVE',
          paymentId,
          verifiedAt:
            now,
          subscriptionStart:
            now,
          subscriptionExpiry:
            expiry
        },
        { merge: true }
      );

      await db
        .collection('users')
        .doc(req.user.uid)
        .set(
          {
            subscriptionStatus:
              'ACTIVE',
            subscriptionTier:
              'PREMIUM',
            subscriptionExpiry:
              expiry,
            isSubscriptionActive:
              true,
            updatedAt:
              now
          },
          { merge: true }
        );

      await db
        .collection('subscriptions')
        .add({
          userId:
            req.user.uid,
          orderId,
          paymentId,
          planName:
            '₹10 / 30 Days VIP',
          amount:
            10,
          currency:
            'INR',
          status:
            'ACTIVE',
          startDate:
            now,
          expiryDate:
            expiry,
          createdAt:
            now
        });

      return res.json({
        success: true,
        subscriptionStatus:
          'ACTIVE',
        subscriptionExpiry:
          expiry,
        durationDays:
          30
      });
    } catch (error) {
      console.error(
        '[PAYMENT VERIFY]',
        error
      );

      return res.status(500).json({
        error:
          'SERVER_VERIFICATION_ERROR',
        message:
          error.message
      });
    }
  }
);

/* =========================================================
   RAZORPAY WEBHOOK
========================================================= */

app.post(
  '/payments/webhook',
  async (req, res) => {
    try {
      if (
        !RAZORPAY_WEBHOOK_SECRET
      ) {
        return res.status(503).json({
          error:
            'WEBHOOK_NOT_CONFIGURED'
        });
      }

      const signature =
        req.headers[
          'x-razorpay-signature'
        ];

      if (!signature) {
        return res.status(400).json({
          error:
            'INVALID_SIGNATURE'
        });
      }

      const payload =
        JSON.stringify(req.body);

      const expected =
        crypto
          .createHmac(
            'sha256',
            RAZORPAY_WEBHOOK_SECRET
          )
          .update(payload)
          .digest('hex');

      if (
        expected.length !==
        signature.length
      ) {
        return res.status(400).json({
          error:
            'INVALID_SIGNATURE'
        });
      }

      if (
        !crypto.timingSafeEqual(
          Buffer.from(
            expected,
            'utf8'
          ),
          Buffer.from(
            signature,
            'utf8'
          )
        )
      ) {
        return res.status(400).json({
          error:
            'INVALID_SIGNATURE'
        });
      }

      const event =
        req.body.event;

      if (
        event !==
          'payment.captured' &&
        event !==
          'order.paid'
      ) {
        return res.json({
          status:
            'IGNORED'
        });
      }

      const entity =
        req.body.payload?.payment
          ?.entity ||
        req.body.payload?.order
          ?.entity;

      if (!entity) {
        return res.json({
          status:
            'IGNORED'
        });
      }

      const orderId =
        entity.order_id ||
        entity.receipt ||
        entity.notes?.localOrderId;

      const userId =
        entity.notes?.userId;

      const amount =
        Number(entity.amount);

      if (
        !orderId ||
        !userId ||
        amount !== 1000
      ) {
        return res.status(400).json({
          error:
            'INVALID_WEBHOOK_DATA'
        });
      }

      const now =
        Date.now();

      const expiry =
        now +
        VIP_PLAN_DURATION_DAYS *
          24 *
          60 *
          60 *
          1000;

      const paymentRef =
        db
          .collection('payments')
          .doc(orderId);

      const existing =
        await paymentRef.get();

      if (
        existing.exists &&
        existing.data().status ===
          'ACTIVE'
      ) {
        return res.json({
          status:
            'ALREADY_PROCESSED'
        });
      }

      await paymentRef.set(
        {
          status:
            'ACTIVE',
          paymentId:
            entity.id || null,
          verifiedAt:
            now,
          subscriptionStart:
            now,
          subscriptionExpiry:
            expiry,
          amount:
            10,
          amountPaise:
            1000
        },
        { merge: true }
      );

      await db
        .collection('users')
        .doc(userId)
        .set(
          {
            subscriptionStatus:
              'ACTIVE',
            subscriptionTier:
              'PREMIUM',
            subscriptionExpiry:
              expiry,
            isSubscriptionActive:
              true,
            updatedAt:
              now
          },
          { merge: true }
        );

      return res.json({
        status:
          'PROCESSED'
      });
    } catch (error) {
      console.error(
        '[WEBHOOK ERROR]',
        error
      );

      return res.status(500).json({
        error:
          'WEBHOOK_FAILED'
      });
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      '=============================================='
    );
    console.log(
      'CineNova Backend is ONLINE'
    );
    console.log(
      `Port: ${PORT}`
    );
    console.log(
      `Project: ${PROJECT_ID}`
    );
    console.log(
      `Bucket: ${GCS_BUCKET_NAME}`
    );
    console.log(
      `Base URL: ${PUBLIC_BASE_URL}`
    );
    console.log(
      '=============================================='
    );
  }
);

module.exports = app;
