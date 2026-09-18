// ============================================================
// CINENOVA BACKEND - server.js
// PART 1/3
// Config + Firebase Admin + GCS + Auth + Admin + Upload
// ============================================================

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const admin = require("firebase-admin");
const { Storage } = require("@google-cloud/storage");

const app = express();

// ============================================================
// BASIC CONFIG
// ============================================================

const PORT = Number(process.env.PORT || 8080);

const PROJECT_ID =
  process.env.GOOGLE_CLOUD_PROJECT ||
  process.env.GCLOUD_PROJECT ||
  "cinenova-1232d";

const GCS_BUCKET_NAME =
  process.env.GCS_BUCKET_NAME ||
  "cinenova-1232d.firebasestorage.app";

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  "";

const JWT_SECRET = process.env.JWT_SECRET || "";

const RAZORPAY_KEY_ID =
  process.env.RAZORPAY_KEY_ID || "";

const RAZORPAY_KEY_SECRET =
  process.env.RAZORPAY_KEY_SECRET || "";

const RAZORPAY_WEBHOOK_SECRET =
  process.env.RAZORPAY_WEBHOOK_SECRET || "";

const GOOGLE_WEB_CLIENT_ID =
  process.env.GOOGLE_WEB_CLIENT_ID || "";

const GOOGLE_WEB_CLIENT_SECRET =
  process.env.GOOGLE_WEB_CLIENT_SECRET || "";

const ALLOW_LEGACY_DRIVE_TOKEN =
  process.env.ALLOW_LEGACY_DRIVE_TOKEN === "true";

const FREE_DAILY_LIMIT_SECONDS = 14400;

const PREMIUM_PRICE_INR = 10;

const PREMIUM_DURATION_DAYS = 30;

// ============================================================
// PRODUCTION ENV VALIDATION
// ============================================================

if (process.env.NODE_ENV === "production") {
  const requiredEnv = [
    "FIREBASE_CONFIG_JSON",
    "GCS_BUCKET_NAME",
    "GOOGLE_CLOUD_PROJECT",
    "JWT_SECRET",
  ];

  const missingEnv = requiredEnv.filter(
    (name) => !process.env[name]
  );

  if (missingEnv.length > 0) {
    console.error(
      "Missing required production environment variables:",
      missingEnv.join(", ")
    );
  }
}

// ============================================================
// FIREBASE SERVICE ACCOUNT CONFIG
// ============================================================

let serviceAccount = null;

try {
  if (!process.env.FIREBASE_CONFIG_JSON) {
    throw new Error(
      "FIREBASE_CONFIG_JSON environment variable is missing"
    );
  }

  serviceAccount = JSON.parse(
    process.env.FIREBASE_CONFIG_JSON
  );

  if (serviceAccount.private_key) {
    serviceAccount.private_key =
      serviceAccount.private_key.replace(/\\n/g, "\n");
  }

  if (
    !serviceAccount.project_id ||
    !serviceAccount.client_email ||
    !serviceAccount.private_key
  ) {
    throw new Error(
      "FIREBASE_CONFIG_JSON is missing project_id, client_email or private_key"
    );
  }

  console.log(
    "Firebase service account loaded for project:",
    serviceAccount.project_id
  );
} catch (error) {
  console.error(
    "Firebase service account configuration failed:",
    error.message
  );
}

// ============================================================
// FIREBASE ADMIN INITIALIZATION
// ============================================================

let firebaseApp = null;
let db = null;
let auth = null;

try {
  if (!admin.apps.length && serviceAccount) {
    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      storageBucket: GCS_BUCKET_NAME,
    });
  } else if (admin.apps.length) {
    firebaseApp = admin.app();
  }

  if (firebaseApp) {
    db = admin.firestore();
    auth = admin.auth();

    console.log(
      "Firebase Admin initialized successfully"
    );
  }
} catch (error) {
  console.error(
    "Firebase Admin initialization failed:",
    error.message
  );
}

// ============================================================
// GOOGLE CLOUD STORAGE INITIALIZATION
// ============================================================

let storage = null;
let bucket = null;

try {
  if (serviceAccount) {
    storage = new Storage({
      projectId: serviceAccount.project_id || PROJECT_ID,
      credentials: {
        client_email: serviceAccount.client_email,
        private_key: serviceAccount.private_key,
      },
    });

    bucket = storage.bucket(GCS_BUCKET_NAME);

    console.log(
      "Google Cloud Storage initialized:",
      GCS_BUCKET_NAME
    );
  }
} catch (error) {
  console.error(
    "Google Cloud Storage initialization failed:",
    error.message
  );
}

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

app.use(cors());

app.use(morgan("combined"));

/*
 * IMPORTANT:
 * rawBody is preserved because Razorpay webhook signature
 * verification requires the exact raw request body.
 */
app.use(
  express.json({
    limit: "25mb",

    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "25mb",
  })
);

// ============================================================
// BASIC HELPERS
// ============================================================

function isFirebaseReady() {
  return !!db && !!auth && !!firebaseApp;
}

function isStorageReady() {
  return !!storage && !!bucket;
}

function requireFirebaseReady(res) {
  if (!isFirebaseReady()) {
    res.status(503).json({
      error: "FIREBASE_NOT_CONFIGURED",
      message:
        "Firebase Admin is not initialized on the backend.",
    });

    return false;
  }

  return true;
}

function requireStorageReady(res) {
  if (!isStorageReady()) {
    res.status(503).json({
      error: "STORAGE_NOT_CONFIGURED",
      message:
        "Google Cloud Storage is not initialized on the backend.",
    });

    return false;
  }

  return true;
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7).trim() || null;
}

// ============================================================
// FIREBASE AUTH MIDDLEWARE
// ============================================================

async function authenticateFirebaseUser(
  req,
  res,
  next
) {
  try {
    if (!requireFirebaseReady(res)) {
      return;
    }

    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: "AUTH_REQUIRED",
        message: "Firebase ID token is required.",
      });
    }

    const decodedToken =
      await auth.verifyIdToken(token, true);

    req.firebaseUser = decodedToken;

    req.uid = decodedToken.uid;

    next();
  } catch (error) {
    console.error(
      "Firebase authentication failed:",
      error.message
    );

    return res.status(401).json({
      error: "AUTH_INVALID",
      message:
        "Your login session is invalid or expired. Please sign in again.",
    });
  }
}

// ============================================================
// FIRESTORE USER DOCUMENT
// ============================================================

async function getUserDocument(uid) {
  if (!db) {
    throw new Error("Firestore is not initialized");
  }

  const snap = await db
    .collection("users")
    .doc(uid)
    .get();

  if (!snap.exists) {
    return null;
  }

  return {
    id: snap.id,
    ...snap.data(),
  };
}

// ============================================================
// ADMIN AUTHORIZATION
// ============================================================

async function requireAdmin(
  req,
  res,
  next
) {
  try {
    if (!requireFirebaseReady(res)) {
      return;
    }

    if (!req.uid) {
      return res.status(401).json({
        error: "AUTH_REQUIRED",
        message: "Authentication required.",
      });
    }

    const userDoc =
      await getUserDocument(req.uid);

    if (!userDoc) {
      return res.status(403).json({
        error: "USER_PROFILE_NOT_FOUND",
        message:
          "User profile was not found.",
      });
    }

    const role = String(
      userDoc.role || ""
    ).toUpperCase();

    if (role !== "ADMIN") {
      return res.status(403).json({
        error: "ADMIN_REQUIRED",
        message:
          "Administrator access is required.",
      });
    }

    req.userDocument = userDoc;

    next();
  } catch (error) {
    console.error(
      "Admin authorization failed:",
      error.message
    );

    return res.status(500).json({
      error: "ADMIN_AUTHORIZATION_FAILED",
      message:
        "Unable to verify administrator access.",
    });
  }
}

// ============================================================
// USER ACCESS
// ============================================================

async function requireUser(
  req,
  res,
  next
) {
  try {
    if (!req.uid) {
      return res.status(401).json({
        error: "AUTH_REQUIRED",
        message: "Authentication required.",
      });
    }

    const userDoc =
      await getUserDocument(req.uid);

    if (!userDoc) {
      return res.status(404).json({
        error: "USER_NOT_FOUND",
        message:
          "User profile was not found.",
      });
    }

    req.userDocument = userDoc;

    next();
  } catch (error) {
    console.error(
      "User authorization failed:",
      error.message
    );

    return res.status(500).json({
      error: "USER_AUTHORIZATION_FAILED",
      message:
        "Unable to verify user access.",
    });
  }
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get(
  "/health",
  async (req, res) => {
    const firebaseReady =
      isFirebaseReady();

    const storageReady =
      isStorageReady();

    return res.status(200).json({
      ok: true,
      service: "cine-nova-backend",
      projectId: PROJECT_ID,
      firebase: firebaseReady,
      storage: storageReady,
      bucket: GCS_BUCKET_NAME,
      timestamp: new Date().toISOString(),
    });
  }
);

// ============================================================
// ROOT
// ============================================================

app.get("/", (req, res) => {
  res.status(404).json({
    error: "NOT_FOUND",
    message:
      "CineNova backend is running. Use /health for health status.",
  });
});

// ============================================================
// DIAGNOSTICS
// ============================================================

app.get(
  "/diagnostics",
  authenticateFirebaseUser,
  async (req, res) => {
    let user = null;

    try {
      user = await getUserDocument(req.uid);
    } catch (error) {
      console.error(
        "Diagnostics user lookup failed:",
        error.message
      );
    }

    return res.status(200).json({
      ok: true,
      uid: req.uid,
      firebaseProject:
        serviceAccount?.project_id ||
        PROJECT_ID,
      firebaseAdmin:
        isFirebaseReady(),
      storage:
        isStorageReady(),
      bucket:
        GCS_BUCKET_NAME,
      role:
        user?.role || null,
      timestamp:
        new Date().toISOString(),
    });
  }
);

// ============================================================
// ADMIN - CREATE GCS RESUMABLE UPLOAD SESSION
// ============================================================

app.post(
  "/admin/movies/create-upload-session",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireStorageReady(res)) {
        return;
      }

      const {
        movieId,
        fileName,
        contentType,
        fileSize,
      } = req.body || {};

      if (!movieId) {
        return res.status(400).json({
          error: "MOVIE_ID_REQUIRED",
          message:
            "movieId is required.",
        });
      }

      if (!fileName) {
        return res.status(400).json({
          error: "FILE_NAME_REQUIRED",
          message:
            "fileName is required.",
        });
      }

      const safeMovieId =
        String(movieId)
          .replace(/[^a-zA-Z0-9_-]/g, "");

      const safeFileName =
        String(fileName)
          .replace(/[^a-zA-Z0-9._-]/g, "_");

      const objectPath =
        `movies/${safeMovieId}/video/original/${safeFileName}`;

      const file =
        bucket.file(objectPath);

      /*
       * GCS resumable upload session.
       *
       * The client uploads directly to GCS.
       * The full video does NOT pass through the Android phone
       * and does NOT need to be stored permanently on the phone.
       */
      const [uploadUrl] =
        await file.createResumableUpload({
          metadata: {
            contentType:
              contentType ||
              "video/mp4",

            metadata: {
              cineNovaMovieId:
                safeMovieId,

              cineNovaUploadedBy:
                req.uid,

              cineNovaOriginalFileName:
                safeFileName,

              cineNovaFileSize:
                fileSize
                  ? String(fileSize)
                  : "",
            },
          },

          origin:
            PUBLIC_BASE_URL || undefined,
        });

      return res.status(200).json({
        success: true,
        movieId: safeMovieId,
        objectPath,
        uploadUrl,
        storageProvider: "GCS_PRIVATE",
      });
    } catch (error) {
      console.error(
        "Create upload session failed:",
        error
      );

      return res.status(500).json({
        error:
          "UPLOAD_SESSION_CREATION_FAILED",
        message:
          error.message ||
          "Unable to create cloud storage upload session.",
      });
    }
  }
);

// ============================================================
// ADMIN - CREATE MOVIE DOCUMENT
// ============================================================

app.post(
  "/admin/movies",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const {
        title,
        description,
        genre,
        language,
        year,
        duration,
        rating,
        maturity,
        quality,
        featured,
        published,
        videoObjectPath,
        posterObjectPath,
        bannerObjectPath,
      } = req.body || {};

      if (!title) {
        return res.status(400).json({
          error: "TITLE_REQUIRED",
          message:
            "Movie title is required.",
        });
      }

      const movieRef =
        db.collection("movies").doc();

      const movie = {
        movieId: movieRef.id,

        title:
          String(title).trim(),

        description:
          String(description || "").trim(),

        genre:
          String(genre || "").trim(),

        language:
          String(language || "").trim(),

        year:
          year !== undefined &&
          year !== null
            ? Number(year)
            : null,

        duration:
          duration !== undefined &&
          duration !== null
            ? Number(duration)
            : null,

        rating:
          rating !== undefined &&
          rating !== null
            ? Number(rating)
            : null,

        maturity:
          String(maturity || "").trim(),

        quality:
          String(quality || "").trim(),

        featured:
          Boolean(featured),

        published:
          Boolean(published),

        videoObjectPath:
          videoObjectPath ||
          null,

        posterObjectPath:
          posterObjectPath ||
          null,

        bannerObjectPath:
          bannerObjectPath ||
          null,

        storageProvider:
          "GCS_PRIVATE",

        createdBy:
          req.uid,

        createdAt:
          admin.firestore.FieldValue.serverTimestamp(),

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      };

      await movieRef.set(movie);

      return res.status(201).json({
        success: true,
        movieId: movieRef.id,
        movie,
      });
    } catch (error) {
      console.error(
        "Create movie failed:",
        error
      );

      return res.status(500).json({
        error: "MOVIE_CREATE_FAILED",
        message:
          error.message ||
          "Unable to create movie.",
      });
    }
  }
);

// ============================================================
// ADMIN - FINALIZE UPLOAD
// ============================================================

app.post(
  "/admin/movies/finalize-upload",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      if (!requireStorageReady(res)) {
        return;
      }

      const {
        movieId,
        videoObjectPath,
        posterObjectPath,
        bannerObjectPath,
      } = req.body || {};

      if (!movieId) {
        return res.status(400).json({
          error: "MOVIE_ID_REQUIRED",
          message:
            "movieId is required.",
        });
      }

      const movieRef =
        db.collection("movies").doc(movieId);

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error: "MOVIE_NOT_FOUND",
          message:
            "Movie document was not found.",
        });
      }

      const updates = {
        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),

        storageProvider:
          "GCS_PRIVATE",
      };

      if (videoObjectPath) {
        updates.videoObjectPath =
          String(videoObjectPath);
      }

      if (posterObjectPath) {
        updates.posterObjectPath =
          String(posterObjectPath);
      }

      if (bannerObjectPath) {
        updates.bannerObjectPath =
          String(bannerObjectPath);
      }

      /*
       * Verify the video object exists before declaring
       * the upload complete.
       */
      if (videoObjectPath) {
        const videoFile =
          bucket.file(videoObjectPath);

        const [exists] =
          await videoFile.exists();

        if (!exists) {
          return res.status(400).json({
            error:
              "VIDEO_OBJECT_NOT_FOUND",
            message:
              "The uploaded video was not found in private cloud storage.",
          });
        }

        const [metadata] =
          await videoFile.getMetadata();

        updates.assetSize =
          Number(metadata.size || 0);

        updates.contentType =
          metadata.contentType ||
          "video/mp4";

        updates.importStatus =
          "COMPLETED";
      }

      await movieRef.update(updates);

      const finalSnap =
        await movieRef.get();

      return res.status(200).json({
        success: true,
        movieId,
        movie:
          finalSnap.data(),
      });
    } catch (error) {
      console.error(
        "Finalize upload failed:",
        error
      );

      return res.status(500).json({
        error:
          "UPLOAD_FINALIZATION_FAILED",
        message:
          error.message ||
          "Unable to finalize upload.",
      });
    }
  }
);

// ============================================================
// END OF PART 1
// ============================================================

// PART 2 continues from here.
// Do NOT create another server.js file.
// Paste PART 2 directly below this code.
// ============================================================
// CINENOVA BACKEND - server.js
// PART 2/3
// Google Drive Import + Movie Management
// + Secure Streaming + Playback Sessions
// ============================================================


// ============================================================
// GOOGLE DRIVE - SERVER AUTH CODE EXCHANGE
// ============================================================

async function exchangeGoogleServerAuthCode(
  serverAuthCode
) {
  if (!GOOGLE_WEB_CLIENT_ID) {
    throw new Error(
      "GOOGLE_WEB_CLIENT_ID is not configured"
    );
  }

  if (!GOOGLE_WEB_CLIENT_SECRET) {
    throw new Error(
      "GOOGLE_WEB_CLIENT_SECRET is not configured"
    );
  }

  if (!serverAuthCode) {
    throw new Error(
      "Google server authorization code is missing"
    );
  }

  const tokenResponse =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
        },

        body:
          new URLSearchParams({
            code:
              serverAuthCode,

            client_id:
              GOOGLE_WEB_CLIENT_ID,

            client_secret:
              GOOGLE_WEB_CLIENT_SECRET,

            grant_type:
              "authorization_code",
          }).toString(),
      }
    );

  const tokenText =
    await tokenResponse.text();

  let tokenData;

  try {
    tokenData =
      JSON.parse(tokenText);
  } catch {
    tokenData = {
      raw: tokenText,
    };
  }

  if (!tokenResponse.ok) {
    console.error(
      "Google OAuth token exchange failed:",
      tokenData
    );

    const error =
      new Error(
        tokenData.error_description ||
        tokenData.error ||
        "Google OAuth token exchange failed"
      );

    error.code =
      "OAUTH_EXCHANGE_FAILED";

    throw error;
  }

  if (!tokenData.access_token) {
    throw new Error(
      "Google OAuth exchange returned no access token"
    );
  }

  return tokenData;
}


// ============================================================
// GOOGLE DRIVE - IMPORT MOVIE DIRECTLY TO GCS
// ============================================================

app.post(
  "/admin/movies/import-from-drive",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      if (!requireStorageReady(res)) {
        return;
      }

      const {
        movieId,
        serverAuthCode,
        driveFileId,
        fileName,
        contentType,
      } = req.body || {};

      if (!movieId) {
        return res.status(400).json({
          error:
            "MOVIE_ID_REQUIRED",
          message:
            "movieId is required.",
        });
      }

      if (!driveFileId) {
        return res.status(400).json({
          error:
            "DRIVE_FILE_ID_REQUIRED",
          message:
            "Google Drive file ID is required.",
        });
      }

      if (
        !serverAuthCode &&
        !ALLOW_LEGACY_DRIVE_TOKEN
      ) {
        return res.status(400).json({
          error:
            "SERVER_AUTH_CODE_REQUIRED",
          message:
            "Google Drive server authorization code is required.",
        });
      }

      let accessToken = null;

      /*
       * Production path:
       * Android sends a one-time serverAuthCode.
       *
       * Backend exchanges it using the Web OAuth client
       * secret. The secret NEVER goes inside the APK.
       */
      if (serverAuthCode) {
        try {
          const tokenData =
            await exchangeGoogleServerAuthCode(
              serverAuthCode
            );

          accessToken =
            tokenData.access_token;
        } catch (oauthError) {
          console.error(
            "Google OAuth exchange error:",
            oauthError.message
          );

          return res.status(400).json({
            error:
              "OAUTH_EXCHANGE_FAILED",
            message:
              oauthError.message ||
              "Google Drive authorization could not be completed.",
          });
        }
      }

      /*
       * Legacy token path is intentionally disabled in production
       * unless explicitly enabled.
       */
      if (
        !accessToken &&
        ALLOW_LEGACY_DRIVE_TOKEN
      ) {
        accessToken =
          req.body.accessToken || null;
      }

      if (!accessToken) {
        return res.status(400).json({
          error:
            "DRIVE_AUTH_FAILED",
          message:
            "A valid Google Drive authorization token is required.",
        });
      }

      const drive =
        google.drive({
          version: "v3",

          auth: new google.auth.OAuth2(
            GOOGLE_WEB_CLIENT_ID ||
              undefined
          ),
        });

      drive.options = {
        ...drive.options,

        headers: {
          Authorization:
            `Bearer ${accessToken}`,
        },
      };

      /*
       * Read-only metadata request.
       */
      const metadataResponse =
        await fetch(
          `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(
            driveFileId
          )}?fields=id,name,mimeType,size,trashed&supportsAllDrives=true`,
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${accessToken}`,
            },
          }
        );

      const metadataText =
        await metadataResponse.text();

      let driveMetadata;

      try {
        driveMetadata =
          JSON.parse(metadataText);
      } catch {
        driveMetadata = null;
      }

      if (!metadataResponse.ok) {
        console.error(
          "Google Drive metadata failed:",
          metadataText
        );

        return res.status(400).json({
          error:
            "DRIVE_METADATA_FAILED",
          message:
            driveMetadata?.error?.message ||
            "Unable to read the selected Google Drive file.",
        });
      }

      if (driveMetadata.trashed) {
        return res.status(400).json({
          error:
            "DRIVE_FILE_TRASHED",
          message:
            "The selected Google Drive file is in trash.",
        });
      }

      /*
       * Only video files are accepted by this endpoint.
       */
      const mime =
        String(
          driveMetadata.mimeType ||
          contentType ||
          ""
        );

      if (!mime.startsWith("video/")) {
        return res.status(400).json({
          error:
            "INVALID_DRIVE_FILE_TYPE",
          message:
            "The selected Google Drive file is not a video.",
        });
      }

      const safeMovieId =
        String(movieId)
          .replace(
            /[^a-zA-Z0-9_-]/g,
            ""
          );

      const originalName =
        fileName ||
        driveMetadata.name ||
        "movie.mp4";

      const safeFileName =
        String(originalName)
          .replace(
            /[^a-zA-Z0-9._-]/g,
            "_"
          );

      const objectPath =
        `movies/${safeMovieId}/video/original/${safeFileName}`;

      const destinationFile =
        bucket.file(objectPath);

      /*
       * Cloud-to-cloud transfer:
       *
       * Google Drive -> backend stream -> private GCS
       *
       * The complete movie is NOT downloaded to the
       * administrator's Android device.
       */
      const driveResponse =
        await fetch(
          `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(
            driveFileId
          )}?alt=media&supportsAllDrives=true`,
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${accessToken}`,
            },
          }
        );

      if (!driveResponse.ok) {
        const errorText =
          await driveResponse.text();

        console.error(
          "Google Drive media download failed:",
          errorText
        );

        return res.status(400).json({
          error:
            "DRIVE_MEDIA_DOWNLOAD_FAILED",
          message:
            "Unable to read video data from Google Drive.",
        });
      }

      if (!driveResponse.body) {
        return res.status(400).json({
          error:
            "DRIVE_EMPTY_RESPONSE",
          message:
            "Google Drive returned no video stream.",
        });
      }

      /*
       * Node fetch returns a Web ReadableStream.
       * Convert it to a Node stream for GCS.
       */
      const { Readable } =
        require("stream");

      const nodeStream =
        Readable.fromWeb(
          driveResponse.body
        );

      await new Promise(
        (resolve, reject) => {
          const writeStream =
            destinationFile.createWriteStream({
              resumable: true,

              metadata: {
                contentType:
                  mime ||
                  "video/mp4",

                metadata: {
                  cineNovaMovieId:
                    safeMovieId,

                  driveVideoFileId:
                    String(driveFileId),

                  importedBy:
                    req.uid,

                  storageProvider:
                    "GCS_PRIVATE",
                },
              },
            });

          nodeStream.on(
            "error",
            reject
          );

          writeStream.on(
            "error",
            reject
          );

          writeStream.on(
            "finish",
            resolve
          );

          nodeStream.pipe(
            writeStream
          );
        }
      );

      const [gcsMetadata] =
        await destinationFile.getMetadata();

      const movieRef =
        db.collection("movies")
          .doc(safeMovieId);

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie document was not found.",
        });
      }

      await movieRef.update({
        driveVideoFileId:
          String(driveFileId),

        videoObjectPath:
          objectPath,

        assetSize:
          Number(
            gcsMetadata.size || 0
          ),

        contentType:
          gcsMetadata.contentType ||
          mime ||
          "video/mp4",

        storageProvider:
          "GCS_PRIVATE",

        importStatus:
          "COMPLETED",

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({
        success: true,

        movieId:
          safeMovieId,

        driveVideoFileId:
          String(driveFileId),

        videoObjectPath:
          objectPath,

        assetSize:
          Number(
            gcsMetadata.size || 0
          ),

        storageProvider:
          "GCS_PRIVATE",

        importStatus:
          "COMPLETED",
      });
    } catch (error) {
      console.error(
        "Google Drive import failed:",
        error
      );

      return res.status(500).json({
        error:
          "DRIVE_IMPORT_FAILED",
        message:
          error.message ||
          "Google Drive import failed.",
      });
    }
  }
);


// ============================================================
// ADMIN - LIST MOVIES
// ============================================================

app.get(
  "/admin/movies",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const snapshot =
        await db
          .collection("movies")
          .orderBy(
            "updatedAt",
            "desc"
          )
          .get();

      const movies =
        snapshot.docs.map(
          (doc) => ({
            movieId:
              doc.id,
            ...doc.data(),
          })
        );

      return res.status(200).json({
        success: true,
        movies,
      });
    } catch (error) {
      console.error(
        "Admin movie list failed:",
        error
      );

      return res.status(500).json({
        error:
          "MOVIE_LIST_FAILED",
        message:
          error.message ||
          "Unable to load movies.",
      });
    }
  }
);


// ============================================================
// ADMIN - GET MOVIE DETAILS
// ============================================================

app.get(
  "/admin/movies/:movieId",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const snap =
        await db
          .collection("movies")
          .doc(movieId)
          .get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      return res.status(200).json({
        success: true,

        movie: {
          movieId:
            snap.id,
          ...snap.data(),
        },
      });
    } catch (error) {
      console.error(
        "Movie details failed:",
        error
      );

      return res.status(500).json({
        error:
          "MOVIE_DETAILS_FAILED",
        message:
          error.message ||
          "Unable to load movie details.",
      });
    }
  }
);


// ============================================================
// ADMIN - UPDATE MOVIE
// ============================================================

app.patch(
  "/admin/movies/:movieId",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const movieRef =
        db.collection("movies")
          .doc(movieId);

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      const allowedFields = [
        "title",
        "description",
        "genre",
        "language",
        "year",
        "duration",
        "rating",
        "maturity",
        "quality",
        "featured",
        "published",
        "posterObjectPath",
        "bannerObjectPath",
      ];

      const updates = {};

      for (
        const field of allowedFields
      ) {
        if (
          Object.prototype.hasOwnProperty.call(
            req.body || {},
            field
          )
        ) {
          updates[field] =
            req.body[field];
        }
      }

      if (
        Object.keys(updates).length === 0
      ) {
        return res.status(400).json({
          error:
            "NO_UPDATES",
          message:
            "No valid movie fields were supplied.",
        });
      }

      updates.updatedAt =
        admin.firestore.FieldValue.serverTimestamp();

      await movieRef.update(
        updates
      );

      const finalSnap =
        await movieRef.get();

      return res.status(200).json({
        success: true,

        movie: {
          movieId:
            finalSnap.id,
          ...finalSnap.data(),
        },
      });
    } catch (error) {
      console.error(
        "Movie update failed:",
        error
      );

      return res.status(500).json({
        error:
          "MOVIE_UPDATE_FAILED",
        message:
          error.message ||
          "Unable to update movie.",
      });
    }
  }
);


// ============================================================
// ADMIN - DELETE MOVIE
// ============================================================

app.delete(
  "/admin/movies/:movieId",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const movieRef =
        db.collection("movies")
          .doc(movieId);

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      const movie =
        movieSnap.data();

      /*
       * Delete private GCS assets belonging to this movie.
       */
      if (isStorageReady()) {
        const paths = [
          movie.videoObjectPath,
          movie.posterObjectPath,
          movie.bannerObjectPath,
        ].filter(Boolean);

        for (
          const objectPath of paths
        ) {
          try {
            await bucket
              .file(objectPath)
              .delete({
                ignoreNotFound: true,
              });
          } catch (storageError) {
            console.error(
              "Movie asset deletion failed:",
              objectPath,
              storageError.message
            );
          }
        }

        /*
         * Also remove quality-specific objects
         * under the movie folder.
         */
        try {
          const [files] =
            await bucket.getFiles({
              prefix:
                `movies/${movieId}/`,
            });

          if (files.length > 0) {
            await Promise.all(
              files.map(
                (file) =>
                  file.delete({
                    ignoreNotFound:
                      true,
                  })
              )
            );
          }
        } catch (storageError) {
          console.error(
            "Movie folder cleanup failed:",
            storageError.message
          );
        }
      }

      await movieRef.delete();

      return res.status(200).json({
        success: true,
        movieId,
        deleted: true,
      });
    } catch (error) {
      console.error(
        "Movie delete failed:",
        error
      );

      return res.status(500).json({
        error:
          "MOVIE_DELETE_FAILED",
        message:
          error.message ||
          "Unable to delete movie.",
      });
    }
  }
);


// ============================================================
// USER - GET MOVIE
// ============================================================

app.get(
  "/movies/:movieId",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const snap =
        await db
          .collection("movies")
          .doc(movieId)
          .get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      const movie =
        snap.data();

      /*
       * Users should only receive published movies.
       */
      if (
        movie.published !== true
      ) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_AVAILABLE",
          message:
            "This movie is not currently available.",
        });
      }

      return res.status(200).json({
        success: true,

        movie: {
          movieId:
            snap.id,
          ...movie,
        },
      });
    } catch (error) {
      console.error(
        "User movie lookup failed:",
        error
      );

      return res.status(500).json({
        error:
          "MOVIE_LOOKUP_FAILED",
        message:
          error.message ||
          "Unable to load movie.",
      });
    }
  }
);


// ============================================================
// ENTITLEMENT HELPER
// ============================================================

function isPremiumSubscriptionActive(
  userData
) {
  if (!userData) {
    return false;
  }

  const entitlement =
    String(
      userData.entitlement ||
      userData.subscriptionPlan ||
      userData.plan ||
      ""
    ).toUpperCase();

  if (
    entitlement !== "PREMIUM"
  ) {
    return false;
  }

  const expiryValue =
    userData.subscriptionExpiry ||
    userData.subscriptionExpiresAt ||
    userData.premiumUntil ||
    userData.expiryDate ||
    null;

  if (!expiryValue) {
    return false;
  }

  let expiryMillis = 0;

  if (
    typeof expiryValue.toMillis ===
    "function"
  ) {
    expiryMillis =
      expiryValue.toMillis();
  } else if (
    expiryValue._seconds
  ) {
    expiryMillis =
      Number(
        expiryValue._seconds
      ) * 1000;
  } else {
    expiryMillis =
      new Date(
        expiryValue
      ).getTime();
  }

  if (
    !Number.isFinite(
      expiryMillis
    )
  ) {
    return false;
  }

  return (
    expiryMillis >
    Date.now()
  );
}


// ============================================================
// STREAM QUALITY NORMALIZATION
// ============================================================

function normalizeQuality(
  quality
) {
  const value =
    String(
      quality || "480p"
    )
      .trim()
      .toLowerCase();

  const allowed = [
    "480p",
    "720p",
    "1080p",
    "4k",
  ];

  if (
    !allowed.includes(value)
  ) {
    return null;
  }

  return value;
}


// ============================================================
// SECURE STREAM URL
// ============================================================

app.get(
  "/movies/:movieId/stream-url",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      if (!requireStorageReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const requestedQuality =
        normalizeQuality(
          req.query.q
        );

      if (!requestedQuality) {
        return res.status(400).json({
          error:
            "INVALID_QUALITY",
          message:
            "Supported qualities are 480p, 720p, 1080p and 4k.",
        });
      }

      const movieSnap =
        await db
          .collection("movies")
          .doc(movieId)
          .get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      const movie =
        movieSnap.data();

      if (
        movie.published !== true
      ) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_AVAILABLE",
          message:
            "Movie is not published.",
        });
      }

      const premium =
        isPremiumSubscriptionActive(
          req.userDocument
        );

      /*
       * FREE users can only request 480p.
       */
      if (
        !premium &&
        requestedQuality !==
          "480p"
      ) {
        return res.status(403).json({
          error:
            "PREMIUM_REQUIRED",
          message:
            "This quality requires an active Premium subscription.",
        });
      }

      /*
       * Quality-specific private objects.
       *
       * IMPORTANT:
       * No fallback to a higher-quality original file.
       * This prevents a Free user from receiving 1080p/4K
       * through a mislabeled 480p response.
       */
      const qualityPath =
        `movies/${movieId}/video/${requestedQuality}/movie.mp4`;

      const qualityFile =
        bucket.file(
          qualityPath
        );

      const [exists] =
        await qualityFile.exists();

      if (!exists) {
        return res.status(404).json({
          error:
            "QUALITY_NOT_AVAILABLE",
          message:
            `${requestedQuality} version is not available for this movie.`,
        });
      }

      const expiresAt =
        Date.now() +
        15 * 60 * 1000;

      const [signedUrl] =
        await qualityFile.getSignedUrl({
          version: "v4",

          action: "read",

          expires:
            new Date(
              expiresAt
            ),
        });

      const sessionId =
        crypto.randomUUID();

      await db
        .collection(
          "playbackSessions"
        )
        .doc(sessionId)
        .set({
          sessionId,

          uid:
            req.uid,

          movieId,

          quality:
            requestedQuality,

          entitlement:
            premium
              ? "PREMIUM"
              : "FREE",

          startedAt:
            admin.firestore.FieldValue.serverTimestamp(),

          lastHeartbeatAt:
            admin.firestore.FieldValue.serverTimestamp(),

          stoppedAt:
            null,

          active:
            true,

          totalCountedSeconds:
            0,

          createdAt:
            admin.firestore.FieldValue.serverTimestamp(),
        });

      return res.status(200).json({
        success: true,

        streamUrl:
          signedUrl,

        sessionId,

        quality:
          requestedQuality,

        entitlement:
          premium
            ? "PREMIUM"
            : "FREE",

        expiresAt,
      });
    } catch (error) {
      console.error(
        "Stream URL generation failed:",
        error
      );

      return res.status(500).json({
        error:
          "STREAM_URL_FAILED",
        message:
          error.message ||
          "Unable to create secure stream URL.",
      });
    }
  }
);


// ============================================================
// PLAYBACK HEARTBEAT
// ============================================================

app.post(
  "/playback/session/heartbeat",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const {
        sessionId,
      } = req.body || {};

      if (!sessionId) {
        return res.status(400).json({
          error:
            "SESSION_ID_REQUIRED",
          message:
            "Playback session ID is required.",
        });
      }

      const sessionRef =
        db
          .collection(
            "playbackSessions"
          )
          .doc(
            String(sessionId)
          );

      const usageRef =
        db
          .collection(
            "dailyPlaybackUsage"
          )
          .doc(
            `${req.uid}_${new Date()
              .toISOString()
              .slice(0, 10)}`
          );

      const result =
        await db.runTransaction(
          async (transaction) => {
            const sessionSnap =
              await transaction.get(
                sessionRef
              );

            if (
              !sessionSnap.exists
            ) {
              throw new Error(
                "SESSION_NOT_FOUND"
              );
            }

            const session =
              sessionSnap.data();

            if (
              session.uid !==
              req.uid
            ) {
              throw new Error(
                "SESSION_FORBIDDEN"
              );
            }

            if (
              session.active !==
              true
            ) {
              return {
                active:
                  false,

                remainingSeconds:
                  0,

                countedSeconds:
                  0,
              };
            }

            const now =
              Date.now();

            let lastMillis =
              now;

            if (
              session.lastHeartbeatAt
            ) {
              if (
                typeof session
                  .lastHeartbeatAt
                  .toMillis ===
                "function"
              ) {
                lastMillis =
                  session
                    .lastHeartbeatAt
                    .toMillis();
              } else if (
                session
                  .lastHeartbeatAt
                  ._seconds
              ) {
                lastMillis =
                  Number(
                    session
                      .lastHeartbeatAt
                      ._seconds
                  ) *
                  1000;
              }
            }

            let deltaSeconds =
              Math.floor(
                (now -
                  lastMillis) /
                  1000
              );

            /*
             * Protect against clock anomalies and
             * huge client gaps.
             */
            if (
              deltaSeconds <
              0
            ) {
              deltaSeconds = 0;
            }

            if (
              deltaSeconds >
              30
            ) {
              deltaSeconds = 30;
            }

            const premium =
              isPremiumSubscriptionActive(
                req.userDocument
              );

            if (premium) {
              transaction.update(
                sessionRef,
                {
                  lastHeartbeatAt:
                    admin.firestore.FieldValue.serverTimestamp(),

                  totalCountedSeconds:
                    admin.firestore.FieldValue.increment(
                      deltaSeconds
                    ),
                }
              );

              return {
                active:
                  true,

                remainingSeconds:
                  null,

                countedSeconds:
                  deltaSeconds,

                entitlement:
                  "PREMIUM",
              };
            }

            const usageSnap =
              await transaction.get(
                usageRef
              );

            const currentUsage =
              usageSnap.exists
                ? Number(
                    usageSnap.data()
                      .seconds || 0
                  )
                : 0;

            const remaining =
              Math.max(
                0,
                FREE_DAILY_LIMIT_SECONDS -
                  currentUsage
              );

            if (
              remaining <= 0
            ) {
              transaction.update(
                sessionRef,
                {
                  active:
                    false,

                  stoppedAt:
                    admin.firestore.FieldValue.serverTimestamp(),
                }
              );

              return {
                active:
                  false,

                remainingSeconds:
                  0,

                countedSeconds:
                  0,

                entitlement:
                  "FREE",
              };
            }

            const counted =
              Math.min(
                deltaSeconds,
                remaining
              );

            if (
              usageSnap.exists
            ) {
              transaction.update(
                usageRef,
                {
                  seconds:
                    currentUsage +
                    counted,

                  updatedAt:
                    admin.firestore.FieldValue.serverTimestamp(),
                }
              );
            } else {
              transaction.set(
                usageRef,
                {
                  uid:
                    req.uid,

                  date:
                    new Date()
                      .toISOString()
                      .slice(
                        0,
                        10
                      ),

                  seconds:
                    counted,

                  createdAt:
                    admin.firestore.FieldValue.serverTimestamp(),

                  updatedAt:
                    admin.firestore.FieldValue.serverTimestamp(),
                }
              );
            }

            transaction.update(
              sessionRef,
              {
                lastHeartbeatAt:
                  admin.firestore.FieldValue.serverTimestamp(),

                totalCountedSeconds:
                  admin.firestore.FieldValue.increment(
                    counted
                  ),

                active:
                  counted > 0,
              }
            );

            return {
              active:
                counted > 0,

              remainingSeconds:
                Math.max(
                  0,
                  remaining -
                    counted
                ),

              countedSeconds:
                counted,

              entitlement:
                "FREE",
            };
          }
        );

      return res.status(200).json({
        success: true,
        ...result,
      });
    } catch (error) {
      console.error(
        "Playback heartbeat failed:",
        error
      );

      if (
        error.message ===
        "SESSION_NOT_FOUND"
      ) {
        return res.status(404).json({
          error:
            "SESSION_NOT_FOUND",
          message:
            "Playback session was not found.",
        });
      }

      if (
        error.message ===
        "SESSION_FORBIDDEN"
      ) {
        return res.status(403).json({
          error:
            "SESSION_FORBIDDEN",
          message:
            "This playback session does not belong to the current user.",
        });
      }

      return res.status(500).json({
        error:
          "HEARTBEAT_FAILED",
        message:
          error.message ||
          "Playback heartbeat failed.",
      });
    }
  }
);


// ============================================================
// PLAYBACK SESSION STOP
// ============================================================

app.post(
  "/playback/session/stop",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const {
        sessionId,
      } = req.body || {};

      if (!sessionId) {
        return res.status(400).json({
          error:
            "SESSION_ID_REQUIRED",
          message:
            "Playback session ID is required.",
        });
      }

      const sessionRef =
        db
          .collection(
            "playbackSessions"
          )
          .doc(
            String(sessionId)
          );

      const snap =
        await sessionRef.get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "SESSION_NOT_FOUND",
          message:
            "Playback session was not found.",
        });
      }

      const session =
        snap.data();

      if (
        session.uid !==
        req.uid
      ) {
        return res.status(403).json({
          error:
            "SESSION_FORBIDDEN",
          message:
            "This playback session does not belong to the current user.",
        });
      }

      await sessionRef.update({
        active:
          false,

        stoppedAt:
          admin.firestore.FieldValue.serverTimestamp(),

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({
        success: true,
        sessionId,
        stopped: true,
      });
    } catch (error) {
      console.error(
        "Playback session stop failed:",
        error
      );

      return res.status(500).json({
        error:
          "SESSION_STOP_FAILED",
        message:
          error.message ||
          "Unable to stop playback session.",
      });
    }
  }
);


// ============================================================
// USER - DAILY PLAYBACK USAGE
// ============================================================

app.get(
  "/playback/usage/today",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const date =
        new Date()
          .toISOString()
          .slice(
            0,
            10
          );

      const usageId =
        `${req.uid}_${date}`;

      const snap =
        await db
          .collection(
            "dailyPlaybackUsage"
          )
          .doc(usageId)
          .get();

      const seconds =
        snap.exists
          ? Number(
              snap.data()
                .seconds || 0
            )
          : 0;

      const premium =
        isPremiumSubscriptionActive(
          req.userDocument
        );

      return res.status(200).json({
        success: true,

        date,

        seconds,

        limitSeconds:
          premium
            ? null
            : FREE_DAILY_LIMIT_SECONDS,

        remainingSeconds:
          premium
            ? null
            : Math.max(
                0,
                FREE_DAILY_LIMIT_SECONDS -
                  seconds
              ),

        entitlement:
          premium
            ? "PREMIUM"
            : "FREE",
      });
    } catch (error) {
      console.error(
        "Daily usage lookup failed:",
        error
      );

      return res.status(500).json({
        error:
          "USAGE_LOOKUP_FAILED",
        message:
          error.message ||
          "Unable to load today's playback usage.",
      });
    }
  }
);


// ============================================================
// END OF PART 2
// ============================================================

// PART 3 continues directly below this code.
// Do NOT create another server.js file.
// ============================================================
// CINENOVA BACKEND - server.js
// PART 3/3
// Download + Razorpay + Webhook + Error Handler + Startup
// ============================================================


// ============================================================
// PREMIUM DOWNLOAD URL
// ============================================================

app.get(
  "/movies/:movieId/download-url",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      if (!requireStorageReady(res)) {
        return;
      }

      const movieId =
        String(req.params.movieId);

      // --------------------------------------------------------
      // DOWNLOAD IS PREMIUM ONLY
      // --------------------------------------------------------

      const premium =
        isPremiumSubscriptionActive(
          req.userDocument
        );

      if (!premium) {
        return res.status(403).json({
          error:
            "PREMIUM_REQUIRED",
          message:
            "Movie downloads are available only with an active Premium subscription.",
        });
      }

      const movieRef =
        db
          .collection("movies")
          .doc(movieId);

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      const movie =
        movieSnap.data();

      if (
        movie.published !== true
      ) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_AVAILABLE",
          message:
            "This movie is not currently available.",
        });
      }

      /*
       * Download only the actual private movie object.
       *
       * No fake/public fallback is used.
       */
      const objectPath =
        movie.videoObjectPath;

      if (!objectPath) {
        return res.status(404).json({
          error:
            "VIDEO_NOT_AVAILABLE",
          message:
            "A downloadable video asset is not available.",
        });
      }

      const file =
        bucket.file(objectPath);

      const [exists] =
        await file.exists();

      if (!exists) {
        return res.status(404).json({
          error:
            "VIDEO_OBJECT_NOT_FOUND",
          message:
            "The private video asset could not be found.",
        });
      }

      /*
       * Short-lived signed URL.
       * The URL itself does not grant permanent public access.
       */
      const expiresAt =
        Date.now() +
        15 * 60 * 1000;

      const [signedUrl] =
        await file.getSignedUrl({
          version: "v4",

          action: "read",

          expires:
            new Date(
              expiresAt
            ),

          responseDisposition:
            "attachment",
        });

      return res.status(200).json({
        success: true,

        movieId,

        downloadUrl:
          signedUrl,

        expiresAt,
      });
    } catch (error) {
      console.error(
        "Download URL generation failed:",
        error
      );

      return res.status(500).json({
        error:
          "DOWNLOAD_URL_FAILED",
        message:
          error.message ||
          "Unable to create secure download URL.",
      });
    }
  }
);


// ============================================================
// ADMIN - REPLACE MOVIE VIDEO
// ============================================================

app.post(
  "/admin/movies/:movieId/replace-video",
  authenticateFirebaseUser,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      if (!requireStorageReady(res)) {
        return;
      }

      const movieId =
        String(req.params.movieId);

      const {
        videoObjectPath,
      } = req.body || {};

      if (!videoObjectPath) {
        return res.status(400).json({
          error:
            "VIDEO_OBJECT_PATH_REQUIRED",
          message:
            "videoObjectPath is required.",
        });
      }

      const movieRef =
        db
          .collection("movies")
          .doc(movieId);

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",
          message:
            "Movie was not found.",
        });
      }

      const file =
        bucket.file(
          String(videoObjectPath)
        );

      const [exists] =
        await file.exists();

      if (!exists) {
        return res.status(400).json({
          error:
            "VIDEO_OBJECT_NOT_FOUND",
          message:
            "The replacement video was not found in private storage.",
        });
      }

      const [metadata] =
        await file.getMetadata();

      await movieRef.update({
        videoObjectPath:
          String(videoObjectPath),

        assetSize:
          Number(
            metadata.size || 0
          ),

        contentType:
          metadata.contentType ||
          "video/mp4",

        storageProvider:
          "GCS_PRIVATE",

        importStatus:
          "COMPLETED",

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({
        success: true,

        movieId,

        videoObjectPath:
          String(videoObjectPath),

        assetSize:
          Number(
            metadata.size || 0
          ),
      });
    } catch (error) {
      console.error(
        "Replace video failed:",
        error
      );

      return res.status(500).json({
        error:
          "REPLACE_VIDEO_FAILED",
        message:
          error.message ||
          "Unable to replace movie video.",
      });
    }
  }
);


// ============================================================
// RAZORPAY CONFIG CHECK
// ============================================================

function isRazorpayConfigured() {
  return Boolean(
    RAZORPAY_KEY_ID &&
    RAZORPAY_KEY_SECRET
  );
}


// ============================================================
// RAZORPAY API REQUEST HELPER
// ============================================================

async function razorpayRequest(
  path,
  options = {}
) {
  if (!isRazorpayConfigured()) {
    throw new Error(
      "Razorpay is not configured on the backend."
    );
  }

  const credentials =
    Buffer.from(
      `${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`
    ).toString(
      "base64"
    );

  const response =
    await fetch(
      `https://api.razorpay.com/v1${path}`,
      {
        ...options,

        headers: {
          Authorization:
            `Basic ${credentials}`,

          "Content-Type":
            "application/json",

          ...(options.headers || {}),
        },
      }
    );

  const text =
    await response.text();

  let data;

  try {
    data =
      JSON.parse(text);
  } catch {
    data = {
      raw: text,
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data?.error?.description ||
        data?.error?.reason ||
        data?.message ||
        "Razorpay API request failed"
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  return data;
}


// ============================================================
// CREATE RAZORPAY ORDER
// ============================================================

app.post(
  "/payment/create-order",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!isRazorpayConfigured()) {
        return res.status(503).json({
          error:
            "PAYMENT_NOT_CONFIGURED",
          message:
            "Razorpay payment service is not configured yet.",
        });
      }

      /*
       * Fixed server-controlled price.
       * Never trust price sent by Android.
       */
      const amountPaise =
        PREMIUM_PRICE_INR * 100;

      const receipt =
        `cn_${req.uid}_${Date.now()}`;

      const order =
        await razorpayRequest(
          "/orders",
          {
            method: "POST",

            body:
              JSON.stringify({
                amount:
                  amountPaise,

                currency:
                  "INR",

                receipt,

                notes: {
                  uid:
                    req.uid,

                  plan:
                    "PREMIUM_MONTHLY",
                },
              }),
          }
        );

      /*
       * Store payment/order metadata.
       * This does NOT activate Premium.
       */
      if (db) {
        await db
          .collection("payments")
          .doc(order.id)
          .set({
            paymentId:
              order.id,

            razorpayOrderId:
              order.id,

            uid:
              req.uid,

            amount:
              amountPaise,

            currency:
              "INR",

            plan:
              "PREMIUM_MONTHLY",

            status:
              "CREATED",

            createdAt:
              admin.firestore.FieldValue.serverTimestamp(),

            updatedAt:
              admin.firestore.FieldValue.serverTimestamp(),
          });
      }

      return res.status(200).json({
        success: true,

        orderId:
          order.id,

        amount:
          order.amount,

        currency:
          order.currency,

        keyId:
          RAZORPAY_KEY_ID,
      });
    } catch (error) {
      console.error(
        "Create Razorpay order failed:",
        error
      );

      return res.status(
        error.status || 500
      ).json({
        error:
          "PAYMENT_ORDER_FAILED",

        message:
          error.message ||
          "Unable to create payment order.",
      });
    }
  }
);


// ============================================================
// RAZORPAY PAYMENT SIGNATURE VERIFICATION
// ============================================================

function verifyRazorpayPaymentSignature({
  orderId,
  paymentId,
  signature,
}) {
  if (
    !orderId ||
    !paymentId ||
    !signature ||
    !RAZORPAY_KEY_SECRET
  ) {
    return false;
  }

  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        RAZORPAY_KEY_SECRET
      )
      .update(
        `${orderId}|${paymentId}`
      )
      .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(
      expectedSignature
    ),

    Buffer.from(
      String(signature)
    )
  );
}


// ============================================================
// VERIFY PAYMENT
// ============================================================

app.post(
  "/payment/verify",
  authenticateFirebaseUser,
  requireUser,
  async (req, res) => {
    try {
      if (!isRazorpayConfigured()) {
        return res.status(503).json({
          error:
            "PAYMENT_NOT_CONFIGURED",
          message:
            "Razorpay payment service is not configured.",
        });
      }

      const {
        razorpay_order_id:
          razorpayOrderId,

        razorpay_payment_id:
          razorpayPaymentId,

        razorpay_signature:
          razorpaySignature,
      } = req.body || {};

      if (
        !razorpayOrderId ||
        !razorpayPaymentId ||
        !razorpaySignature
      ) {
        return res.status(400).json({
          error:
            "PAYMENT_DETAILS_MISSING",
          message:
            "Razorpay payment verification details are incomplete.",
        });
      }

      /*
       * First verify the cryptographic signature.
       */
      const signatureValid =
        verifyRazorpayPaymentSignature({
          orderId:
            razorpayOrderId,

          paymentId:
            razorpayPaymentId,

          signature:
            razorpaySignature,
        });

      if (!signatureValid) {
        return res.status(400).json({
          error:
            "INVALID_PAYMENT_SIGNATURE",
          message:
            "Payment signature verification failed.",
        });
      }

      /*
       * Verify that the Razorpay order belongs to this
       * authenticated CineNova user.
       */
      const paymentRecordRef =
        db
          .collection("payments")
          .doc(
            String(razorpayOrderId)
          );

      const paymentRecordSnap =
        await paymentRecordRef.get();

      if (
        !paymentRecordSnap.exists
      ) {
        return res.status(400).json({
          error:
            "PAYMENT_ORDER_NOT_FOUND",
          message:
            "Payment order was not created for this account.",
        });
      }

      const paymentRecord =
        paymentRecordSnap.data();

      if (
        paymentRecord.uid !==
        req.uid
      ) {
        return res.status(403).json({
          error:
            "PAYMENT_ORDER_FORBIDDEN",
          message:
            "This payment order does not belong to the current user.",
        });
      }

      /*
       * Verify payment directly against Razorpay API.
       */
      const payment =
        await razorpayRequest(
          `/payments/${encodeURIComponent(
            razorpayPaymentId
          )}`,
          {
            method: "GET",
          }
        );

      const order =
        await razorpayRequest(
          `/orders/${encodeURIComponent(
            razorpayOrderId
          )}`,
          {
            method: "GET",
          }
        );

      /*
       * Amount and currency are controlled by the backend.
       */
      if (
        Number(payment.amount) !==
        PREMIUM_PRICE_INR * 100
      ) {
        return res.status(400).json({
          error:
            "INVALID_PAYMENT_AMOUNT",
          message:
            "Payment amount does not match the Premium plan price.",
        });
      }

      if (
        String(
          payment.currency
        ).toUpperCase() !==
        "INR"
      ) {
        return res.status(400).json({
          error:
            "INVALID_PAYMENT_CURRENCY",
          message:
            "Payment currency is invalid.",
        });
      }

      if (
        String(
          order.currency
        ).toUpperCase() !==
        "INR"
      ) {
        return res.status(400).json({
          error:
            "INVALID_ORDER_CURRENCY",
          message:
            "Payment order currency is invalid.",
        });
      }

      if (
        Number(order.amount) !==
        PREMIUM_PRICE_INR * 100
      ) {
        return res.status(400).json({
          error:
            "INVALID_ORDER_AMOUNT",
          message:
            "Payment order amount is invalid.",
        });
      }

      if (
        String(
          payment.order_id
        ) !==
        String(
          razorpayOrderId
        )
      ) {
        return res.status(400).json({
          error:
            "PAYMENT_ORDER_MISMATCH",
          message:
            "Payment and order do not match.",
        });
      }

      /*
       * Razorpay's successful captured payment is the
       * trusted activation boundary.
       */
      if (
        String(
          payment.status
        ).toLowerCase() !==
        "captured"
      ) {
        return res.status(400).json({
          error:
            "PAYMENT_NOT_CAPTURED",
          message:
            "Payment has not been captured successfully.",
        });
      }

      /*
       * Idempotency:
       * If this payment was already processed, return the
       * current subscription state instead of extending it again.
       */
      const existingPayment =
        await db
          .collection("payments")
          .where(
            "razorpayPaymentId",
            "==",
            String(
              razorpayPaymentId
            )
          )
          .limit(1)
          .get();

      if (
        !existingPayment.empty
      ) {
        const userSnap =
          await db
            .collection("users")
            .doc(req.uid)
            .get();

        const userData =
          userSnap.exists
            ? userSnap.data()
            : {};

        return res.status(200).json({
          success: true,

          alreadyProcessed:
            true,

          entitlement:
            userData.entitlement ||
            "FREE",

          subscriptionExpiry:
            userData.subscriptionExpiry ||
            null,
        });
      }

      const userRef =
        db
          .collection("users")
          .doc(req.uid);

      const now =
        new Date();

      /*
       * Extend from current active expiry when applicable.
       * Otherwise start from now.
       */
      let baseDate =
        now;

      const currentExpiry =
        req.userDocument
          ?.subscriptionExpiry;

      if (
        currentExpiry
      ) {
        let expiryMillis = 0;

        if (
          typeof currentExpiry.toMillis ===
          "function"
        ) {
          expiryMillis =
            currentExpiry.toMillis();
        } else if (
          currentExpiry._seconds
        ) {
          expiryMillis =
            Number(
              currentExpiry._seconds
            ) *
            1000;
        } else {
          expiryMillis =
            new Date(
              currentExpiry
            ).getTime();
        }

        if (
          Number.isFinite(
            expiryMillis
          ) &&
          expiryMillis >
            now.getTime()
        ) {
          baseDate =
            new Date(
              expiryMillis
            );
        }
      }

      const expiryDate =
        new Date(
          baseDate.getTime() +
            PREMIUM_DURATION_DAYS *
              24 *
              60 *
              60 *
              1000
        );

      const batch =
        db.batch();

      batch.update(
        userRef,
        {
          entitlement:
            "PREMIUM",

          subscriptionPlan:
            "PREMIUM_MONTHLY",

          subscriptionStatus:
            "ACTIVE",

          subscriptionExpiry:
            admin.firestore.Timestamp.fromDate(
              expiryDate
            ),

          updatedAt:
            admin.firestore.FieldValue.serverTimestamp(),
        }
      );

      batch.update(
        paymentRecordRef,
        {
          razorpayPaymentId:
            String(
              razorpayPaymentId
            ),

          status:
            "CAPTURED",

          amount:
            Number(
              payment.amount
            ),

          currency:
            String(
              payment.currency
            ),

          verifiedAt:
            admin.firestore.FieldValue.serverTimestamp(),

          updatedAt:
            admin.firestore.FieldValue.serverTimestamp(),
        }
      );

      await batch.commit();

      /*
       * Separate payment record indexed by payment ID.
       */
      await db
        .collection("payments")
        .doc(
          String(
            razorpayPaymentId
          )
        )
        .set({
          paymentId:
            String(
              razorpayPaymentId
            ),

          razorpayPaymentId:
            String(
              razorpayPaymentId
            ),

          razorpayOrderId:
            String(
              razorpayOrderId
            ),

          uid:
            req.uid,

          amount:
            Number(
              payment.amount
            ),

          currency:
            String(
              payment.currency
            ),

          status:
            "CAPTURED",

          plan:
            "PREMIUM_MONTHLY",

          verifiedAt:
            admin.firestore.FieldValue.serverTimestamp(),

          createdAt:
            admin.firestore.FieldValue.serverTimestamp(),
        });

      /*
       * Create a trusted notification after successful
       * server-side payment verification.
       */
      try {
        await db
          .collection("users")
          .doc(req.uid)
          .collection("notifications")
          .add({
            type:
              "SUBSCRIPTION_ACTIVATED",

            title:
              "Premium Activated",

            message:
              "Your CineNova Premium subscription is now active.",

            read:
              false,

            createdAt:
              admin.firestore.FieldValue.serverTimestamp(),

            paymentId:
              String(
                razorpayPaymentId
              ),
          });
      } catch (
        notificationError
      ) {
        console.error(
          "Payment notification creation failed:",
          notificationError.message
        );
      }

      return res.status(200).json({
        success: true,

        verified:
          true,

        entitlement:
          "PREMIUM",

        subscriptionPlan:
          "PREMIUM_MONTHLY",

        subscriptionExpiry:
          expiryDate.toISOString(),

        paymentId:
          String(
            razorpayPaymentId
          ),

        orderId:
          String(
            razorpayOrderId
          ),
      });
    } catch (error) {
      console.error(
        "Payment verification failed:",
        error
      );

      return res.status(
        error.status || 500
      ).json({
        error:
          "PAYMENT_VERIFICATION_FAILED",

        message:
          error.message ||
          "Unable to verify payment.",
      });
    }
  }
);


// ============================================================
// RAZORPAY WEBHOOK
// ============================================================

function verifyRazorpayWebhookSignature(
  rawBody,
  signature
) {
  if (
    !RAZORPAY_WEBHOOK_SECRET ||
    !signature ||
    !rawBody
  ) {
    return false;
  }

  const expected =
    crypto
      .createHmac(
        "sha256",
        RAZORPAY_WEBHOOK_SECRET
      )
      .update(rawBody)
      .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(
      expected
    ),

    Buffer.from(
      String(signature)
    )
  );
}


app.post(
  "/payment/webhook",
  async (req, res) => {
    try {
      if (
        !RAZORPAY_WEBHOOK_SECRET
      ) {
        return res.status(503).json({
          error:
            "WEBHOOK_NOT_CONFIGURED",
          message:
            "Razorpay webhook secret is not configured.",
        });
      }

      const signature =
        req.headers[
          "x-razorpay-signature"
        ];

      const rawBody =
        req.rawBody;

      if (!rawBody) {
        return res.status(400).json({
          error:
            "RAW_BODY_MISSING",
          message:
            "Raw webhook body is required for signature verification.",
        });
      }

      const valid =
        verifyRazorpayWebhookSignature(
          rawBody,
          signature
        );

      if (!valid) {
        return res.status(400).json({
          error:
            "INVALID_WEBHOOK_SIGNATURE",
          message:
            "Webhook signature verification failed.",
        });
      }

      let payload;

      try {
        payload =
          JSON.parse(
            rawBody.toString(
              "utf8"
            )
          );
      } catch {
        return res.status(400).json({
          error:
            "INVALID_WEBHOOK_JSON",
          message:
            "Webhook body is not valid JSON.",
        });
      }

      const event =
        String(
          payload.event || ""
        );

      /*
       * Webhook is intentionally treated as an additional
       * trusted payment signal. It does not accept arbitrary
       * client-provided success strings.
       */
      if (
        event ===
          "payment.captured" ||
        event ===
          "order.paid"
      ) {
        const paymentEntity =
          payload?.payload
            ?.payment
            ?.entity;

        if (
          paymentEntity?.id
        ) {
          const paymentId =
            String(
              paymentEntity.id
            );

          const existing =
            await db
              .collection(
                "payments"
              )
              .doc(paymentId)
              .get();

          /*
           * If the normal /payment/verify endpoint has already
           * processed it, webhook remains idempotent.
           */
          if (
            existing.exists &&
            existing.data()
              ?.status ===
              "CAPTURED"
          ) {
            return res.status(200).json({
              success: true,
              processed:
                false,
              reason:
                "ALREADY_PROCESSED",
            });
          }

          /*
           * Webhook alone should not guess the CineNova user
           * from arbitrary client data.
           *
           * The order created by CineNova contains the user ID
           * in notes, so retrieve the order from Razorpay.
           */
          const orderId =
            paymentEntity.order_id;

          if (!orderId) {
            return res.status(200).json({
              success: true,
              processed:
                false,
              reason:
                "ORDER_ID_MISSING",
            });
          }

          try {
            const order =
              await razorpayRequest(
                `/orders/${encodeURIComponent(
                  orderId
                )}`,
                {
                  method:
                    "GET",
                }
              );

            const uid =
              order?.notes?.uid;

            if (!uid) {
              return res.status(200).json({
                success: true,
                processed:
                  false,
                reason:
                  "USER_REFERENCE_MISSING",
              });
            }

            if (
              Number(
                paymentEntity.amount
              ) !==
              PREMIUM_PRICE_INR * 100
            ) {
              return res.status(200).json({
                success: true,
                processed:
                  false,
                reason:
                  "AMOUNT_MISMATCH",
              });
            }

            if (
              String(
                paymentEntity.currency
              ).toUpperCase() !==
              "INR"
            ) {
              return res.status(200).json({
                success: true,
                processed:
                  false,
                reason:
                  "CURRENCY_MISMATCH",
              });
            }

            if (
              String(
                paymentEntity.status
              ).toLowerCase() !==
              "captured"
            ) {
              return res.status(200).json({
                success: true,
                processed:
                  false,
                reason:
                  "PAYMENT_NOT_CAPTURED",
              });
            }

            /*
             * Fetch current user state so webhook can extend
             * an already-active subscription safely.
             */
            const userRef =
              db
                .collection("users")
                .doc(String(uid));

            const userSnap =
              await userRef.get();

            if (!userSnap.exists) {
              return res.status(200).json({
                success: true,
                processed:
                  false,
                reason:
                  "USER_NOT_FOUND",
              });
            }

            const user =
              userSnap.data();

            let baseDate =
              new Date();

            const currentExpiry =
              user.subscriptionExpiry;

            if (
              currentExpiry
            ) {
              let expiryMillis =
                0;

              if (
                typeof currentExpiry.toMillis ===
                "function"
              ) {
                expiryMillis =
                  currentExpiry.toMillis();
              } else if (
                currentExpiry._seconds
              ) {
                expiryMillis =
                  Number(
                    currentExpiry._seconds
                  ) *
                  1000;
              } else {
                expiryMillis =
                  new Date(
                    currentExpiry
                  ).getTime();
              }

              if (
                Number.isFinite(
                  expiryMillis
                ) &&
                expiryMillis >
                  Date.now()
              ) {
                baseDate =
                  new Date(
                    expiryMillis
                  );
              }
            }

            const expiryDate =
              new Date(
                baseDate.getTime() +
                  PREMIUM_DURATION_DAYS *
                    24 *
                    60 *
                    60 *
                    1000
              );

            await userRef.update({
              entitlement:
                "PREMIUM",

              subscriptionPlan:
                "PREMIUM_MONTHLY",

              subscriptionStatus:
                "ACTIVE",

              subscriptionExpiry:
                admin.firestore.Timestamp.fromDate(
                  expiryDate
                ),

              updatedAt:
                admin.firestore.FieldValue.serverTimestamp(),
            });

            await db
              .collection(
                "payments"
              )
              .doc(paymentId)
              .set(
                {
                  paymentId,

                  razorpayPaymentId:
                    paymentId,

                  razorpayOrderId:
                    String(
                      orderId
                    ),

                  uid:
                    String(uid),

                  amount:
                    Number(
                      paymentEntity.amount
                    ),

                  currency:
                    String(
                      paymentEntity.currency
                    ),

                  status:
                    "CAPTURED",

                  plan:
                    "PREMIUM_MONTHLY",

                  source:
                    "RAZORPAY_WEBHOOK",

                  verifiedAt:
                    admin.firestore.FieldValue.serverTimestamp(),

                  createdAt:
                    admin.firestore.FieldValue.serverTimestamp(),
                },
                {
                  merge:
                    true,
                }
              );
          } catch (
            webhookPaymentError
          ) {
            console.error(
              "Webhook payment processing failed:",
              webhookPaymentError.message
            );
          }
        }
      }

      /*
       * Always acknowledge a valid signed webhook.
       * Razorpay can retry webhooks when acknowledgement fails.
       */
      return res.status(200).json({
        success: true,
        received: true,
      });
    } catch (error) {
      console.error(
        "Razorpay webhook failed:",
        error
      );

      return res.status(500).json({
        error:
          "WEBHOOK_PROCESSING_FAILED",
        message:
          error.message ||
          "Webhook processing failed.",
      });
    }
  }
);


// ============================================================
// 404 HANDLER
// ============================================================

app.use(
  (req, res) => {
    return res.status(404).json({
      error:
        "NOT_FOUND",

      message:
        `Route ${req.method} ${req.originalUrl} was not found.`,
    });
  }
);


// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled backend error:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res.status(500).json({
      error:
        "INTERNAL_SERVER_ERROR",

      message:
        process.env.NODE_ENV ===
        "production"
          ? "An internal server error occurred."
          : (
              error.message ||
              "Internal server error."
            ),
    });
  }
);


// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "============================================================"
    );

    console.log(
      "CineNova Backend Started"
    );

    console.log(
      "============================================================"
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
      `Firebase Admin: ${
        isFirebaseReady()
          ? "READY"
          : "NOT READY"
      }`
    );

    console.log(
      `GCS Storage: ${
        isStorageReady()
          ? "READY"
          : "NOT READY"
      }`
    );

    console.log(
      `Razorpay: ${
        isRazorpayConfigured()
          ? "CONFIGURED"
          : "NOT CONFIGURED"
      }`
    );

    console.log(
      `Google Drive OAuth: ${
        GOOGLE_WEB_CLIENT_ID &&
        GOOGLE_WEB_CLIENT_SECRET
          ? "CONFIGURED"
          : "NOT CONFIGURED"
      }`
    );

    console.log(
      "============================================================"
    );
  }
);


// ============================================================
// EXPORT
// ============================================================

module.exports = app;
module.exports = app;
