"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const crypto = require("crypto");
const admin = require("firebase-admin");
const { Storage } = require("@google-cloud/storage");
const { Readable } = require("stream");

const app = express();

/* ============================================================
   CONFIG
============================================================ */

const PORT = Number(process.env.PORT || 8080);

const PROJECT_ID =
  process.env.GOOGLE_CLOUD_PROJECT ||
  process.env.GCLOUD_PROJECT ||
  "cinenova-1232d";

const GCS_BUCKET_NAME =
  process.env.GCS_BUCKET_NAME ||
  "cinenova-movies-vault-secure";

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

/* ============================================================
   PRODUCTION CONFIG CHECK
============================================================ */

if (process.env.NODE_ENV === "production") {
  const required = [
    "FIREBASE_CONFIG_JSON",
    "GCS_BUCKET_NAME",
    "GOOGLE_CLOUD_PROJECT",
    "JWT_SECRET"
  ];

  const missing = required.filter(
    (name) => !process.env[name]
  );

  if (missing.length) {
    console.error(
      "Missing production environment variables:",
      missing.join(", ")
    );
  }
}

/* ============================================================
   FIREBASE SERVICE ACCOUNT
============================================================ */

let serviceAccount = null;

try {
  if (!process.env.FIREBASE_CONFIG_JSON) {
    throw new Error(
      "FIREBASE_CONFIG_JSON is missing"
    );
  }

  serviceAccount = JSON.parse(
    process.env.FIREBASE_CONFIG_JSON
  );

  if (serviceAccount.private_key) {
    serviceAccount.private_key =
      String(serviceAccount.private_key)
        .replace(/\\n/g, "\n")
        .replace(/\r\n/g, "\n");
  }

  if (
    !serviceAccount.project_id ||
    !serviceAccount.client_email ||
    !serviceAccount.private_key
  ) {
    throw new Error(
      "FIREBASE_CONFIG_JSON must contain project_id, client_email and private_key"
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

/* ============================================================
   FIREBASE ADMIN
============================================================ */

let firebaseApp = null;
let db = null;
let auth = null;

try {
  if (serviceAccount) {
    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      storageBucket: GCS_BUCKET_NAME
    });

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

/* ============================================================
   GOOGLE CLOUD STORAGE
============================================================ */

let storage = null;
let bucket = null;

try {
  if (serviceAccount) {
    storage = new Storage({
      projectId:
        serviceAccount.project_id ||
        PROJECT_ID,

      credentials: {
        client_email:
          serviceAccount.client_email,

        private_key:
          serviceAccount.private_key
      }
    });

    bucket =
      storage.bucket(
        GCS_BUCKET_NAME
      );

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

/* ============================================================
   EXPRESS
============================================================ */

app.use(cors());

app.use(
  morgan("combined")
);

/*
 * Keep exact raw request body for Razorpay webhook.
 */
app.use(
  express.json({
    limit: "25mb",

    verify: (req, res, buf) => {
      req.rawBody =
        Buffer.from(buf);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "25mb"
  })
);

/* ============================================================
   BASIC HELPERS
============================================================ */

function isFirebaseReady() {
  return Boolean(
    firebaseApp &&
    db &&
    auth
  );
}

function isStorageReady() {
  return Boolean(
    storage &&
    bucket
  );
}

function requireFirebaseReady(res) {
  if (!isFirebaseReady()) {
    res.status(503).json({
      error:
        "FIREBASE_NOT_CONFIGURED",

      message:
        "Firebase Admin is not initialized on the backend."
    });

    return false;
  }

  return true;
}

function requireStorageReady(res) {
  if (!isStorageReady()) {
    res.status(503).json({
      error:
        "STORAGE_NOT_CONFIGURED",

      message:
        "Google Cloud Storage is not initialized on the backend."
    });

    return false;
  }

  return true;
}

function getBearerToken(req) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header
    .substring(7)
    .trim() || null;
}

function cleanMovieId(value) {
  return String(value || "")
    .replace(
      /[^a-zA-Z0-9_-]/g,
      ""
    );
}

function cleanFileName(value) {
  return String(value || "")
    .replace(
      /[^a-zA-Z0-9._-]/g,
      "_"
    );
}

/* ============================================================
   FIREBASE AUTH
============================================================ */

async function authenticateFirebaseUser(
  req,
  res,
  next
) {
  try {
    if (!requireFirebaseReady(res)) {
      return;
    }

    const token =
      getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error:
          "AUTH_REQUIRED",

        message:
          "Firebase ID token is required."
      });
    }

    const decoded =
      await auth.verifyIdToken(
        token,
        true
      );

    req.firebaseUser =
      decoded;

    req.uid =
      decoded.uid;

    next();
  } catch (error) {
    console.error(
      "Firebase authentication failed:",
      error.message
    );

    return res.status(401).json({
      error:
        "AUTH_INVALID",

      message:
        "Your login session is invalid or expired. Please sign in again."
    });
  }
}

/* ============================================================
   USER DOCUMENT
============================================================ */

async function getUserDocument(uid) {
  if (!db) {
    throw new Error(
      "Firestore is not initialized"
    );
  }

  const snap =
    await db
      .collection("users")
      .doc(uid)
      .get();

  if (!snap.exists) {
    return null;
  }

  return {
    id: snap.id,
    ...snap.data()
  };
}

/* ============================================================
   ADMIN AUTH
============================================================ */

async function requireAdmin(
  req,
  res,
  next
) {
  try {
    if (!req.uid) {
      return res.status(401).json({
        error:
          "AUTH_REQUIRED",

        message:
          "Authentication required."
      });
    }

    const user =
      await getUserDocument(
        req.uid
      );

    if (!user) {
      return res.status(403).json({
        error:
          "USER_PROFILE_NOT_FOUND",

        message:
          "User profile was not found."
      });
    }

    const role =
      String(
        user.role || ""
      ).toUpperCase();

    if (role !== "ADMIN") {
      return res.status(403).json({
        error:
          "ADMIN_REQUIRED",

        message:
          "Administrator access is required."
      });
    }

    req.userDocument =
      user;

    next();
  } catch (error) {
    console.error(
      "Admin authorization failed:",
      error
    );

    return res.status(500).json({
      error:
        "ADMIN_AUTHORIZATION_FAILED",

      message:
        "Unable to verify administrator access."
    });
  }
}

/* ============================================================
   USER AUTH
============================================================ */

async function requireUser(
  req,
  res,
  next
) {
  try {
    const user =
      await getUserDocument(
        req.uid
      );

    if (!user) {
      return res.status(404).json({
        error:
          "USER_NOT_FOUND",

        message:
          "User profile was not found."
      });
    }

    req.userDocument =
      user;

    next();
  } catch (error) {
    console.error(
      "User authorization failed:",
      error
    );

    return res.status(500).json({
      error:
        "USER_AUTHORIZATION_FAILED",

      message:
        "Unable to verify user access."
    });
  }
}

/* ============================================================
   HEALTH
============================================================ */

app.get(
  "/health",
  (req, res) => {
    res.status(200).json({
      ok: true,

      service:
        "cine-nova-backend",

      projectId:
        PROJECT_ID,

      firebase:
        isFirebaseReady(),

      storage:
        isStorageReady(),

      bucket:
        GCS_BUCKET_NAME,

      timestamp:
        new Date().toISOString()
    });
  }
);

/* ============================================================
   ROOT
============================================================ */

app.get(
  "/",
  (req, res) => {
    res.status(404).json({
      error:
        "NOT_FOUND",

      message:
        "CineNova backend is running. Use /health for health status."
    });
  }
);

/* ============================================================
   DIAGNOSTICS
============================================================ */

app.get(
  "/diagnostics",
  authenticateFirebaseUser,
  async (req, res) => {
    let user = null;

    try {
      user =
        await getUserDocument(
          req.uid
        );
    } catch (error) {
      console.error(
        "Diagnostics user lookup failed:",
        error.message
      );
    }

    res.status(200).json({
      ok: true,

      uid:
        req.uid,

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
        new Date().toISOString()
    });
  }
);

/* ============================================================
   ADMIN - CREATE GCS UPLOAD SESSION
============================================================ */

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
        fileSize
      } = req.body || {};

      if (!movieId) {
        return res.status(400).json({
          error:
            "MOVIE_ID_REQUIRED",

          message:
            "movieId is required."
        });
      }

      if (!fileName) {
        return res.status(400).json({
          error:
            "FILE_NAME_REQUIRED",

          message:
            "fileName is required."
        });
      }

      const safeMovieId =
        cleanMovieId(
          movieId
        );

      const safeFileName =
        cleanFileName(
          fileName
        );

      if (!safeMovieId) {
        return res.status(400).json({
          error:
            "INVALID_MOVIE_ID",

          message:
            "Invalid movieId."
        });
      }

      const objectPath =
        `movies/${safeMovieId}/video/original/${safeFileName}`;

      const file =
        bucket.file(
          objectPath
        );

      /*
       * IMPORTANT:
       * Do NOT send an Android origin here.
       * GCS creates the resumable session itself.
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
                  : ""
            }
          }
        });

      res.status(200).json({
        success: true,

        movieId:
          safeMovieId,

        objectPath,

        uploadUrl,

        storageProvider:
          "GCS_PRIVATE"
      });
    } catch (error) {
      console.error(
        "Create upload session failed:",
        error
      );

      res.status(500).json({
        error:
          "UPLOAD_SESSION_CREATION_FAILED",

        message:
          error.message ||
          "Unable to create cloud storage upload session."
      });
    }
  }
);

/* ============================================================
   ADMIN - CREATE MOVIE
============================================================ */

app.post(
  "/admin/movies",

  authenticateFirebaseUser,
  requireAdmin,

  async (req, res) => {
    try {
      if (!requireFirebaseReady(res)) {
        return;
      }

      const body =
        req.body || {};

      const title =
        String(
          body.title || ""
        ).trim();

      if (!title) {
        return res.status(400).json({
          error:
            "TITLE_REQUIRED",

          message:
            "Movie title is required."
        });
      }

      const movieRef =
        db
          .collection("movies")
          .doc();

      const movie = {
        movieId:
          movieRef.id,

        title,

        description:
          String(
            body.description || ""
          ).trim(),

        genre:
          String(
            body.genre || ""
          ).trim(),

        language:
          String(
            body.language || ""
          ).trim(),

        year:
          body.year != null
            ? Number(body.year)
            : null,

        duration:
          body.duration != null
            ? Number(body.duration)
            : null,

        rating:
          body.rating != null
            ? Number(body.rating)
            : null,

        maturity:
          String(
            body.maturity || ""
          ).trim(),

        quality:
          String(
            body.quality || ""
          ).trim(),

        featured:
          Boolean(
            body.featured
          ),

        published:
          Boolean(
            body.published
          ),

        videoObjectPath:
          body.videoObjectPath ||
          null,

        posterObjectPath:
          body.posterObjectPath ||
          null,

        bannerObjectPath:
          body.bannerObjectPath ||
          null,

        storageProvider:
          "GCS_PRIVATE",

        importStatus:
          "DRAFT",

        createdBy:
          req.uid,

        createdAt:
          admin.firestore.FieldValue.serverTimestamp(),

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp()
      };

      await movieRef.set(
        movie
      );

      res.status(201).json({
        success: true,

        movieId:
          movieRef.id,

        movie
      });
    } catch (error) {
      console.error(
        "Create movie failed:",
        error
      );

      res.status(500).json({
        error:
          "MOVIE_CREATE_FAILED",

        message:
          error.message ||
          "Unable to create movie."
      });
    }
  }
);

/* ============================================================
   ADMIN - FINALIZE UPLOAD
============================================================ */

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
        bannerObjectPath
      } = req.body || {};

      if (!movieId) {
        return res.status(400).json({
          error:
            "MOVIE_ID_REQUIRED",

          message:
            "movieId is required."
        });
      }

      const movieRef =
        db
          .collection("movies")
          .doc(
            String(movieId)
          );

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",

          message:
            "Movie document was not found."
        });
      }

      const updates = {
        storageProvider:
          "GCS_PRIVATE",

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp()
      };

      if (videoObjectPath) {
        const path =
          String(
            videoObjectPath
          );

        const file =
          bucket.file(path);

        const [exists] =
          await file.exists();

        if (!exists) {
          return res.status(400).json({
            error:
              "VIDEO_OBJECT_NOT_FOUND",

            message:
              "Uploaded video was not found in private cloud storage."
          });
        }

        const [metadata] =
          await file.getMetadata();

        updates.videoObjectPath =
          path;

        updates.assetSize =
          Number(
            metadata.size || 0
          );

        updates.contentType =
          metadata.contentType ||
          "video/mp4";

        updates.importStatus =
          "COMPLETED";
      }

      if (posterObjectPath) {
        updates.posterObjectPath =
          String(
            posterObjectPath
          );
      }

      if (bannerObjectPath) {
        updates.bannerObjectPath =
          String(
            bannerObjectPath
          );
      }

      await movieRef.update(
        updates
      );

      const finalSnap =
        await movieRef.get();

      res.status(200).json({
        success: true,

        movieId,

        movie:
          finalSnap.data()
      });
    } catch (error) {
      console.error(
        "Finalize upload failed:",
        error
      );

      res.status(500).json({
        error:
          "UPLOAD_FINALIZATION_FAILED",

        message:
          error.message ||
          "Unable to finalize upload."
      });
    }
  }
);

/* ============================================================
   GOOGLE DRIVE AUTH CODE EXCHANGE
============================================================ */

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

  const response =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method:
          "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
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
              "authorization_code"
          }).toString()
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
      raw: text
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        data.error_description ||
        data.error ||
        "Google OAuth token exchange failed"
      );

    error.code =
      "OAUTH_EXCHANGE_FAILED";

    throw error;
  }

  if (!data.access_token) {
    throw new Error(
      "Google OAuth exchange returned no access token"
    );
  }

  return data;
}

/* ============================================================
   GOOGLE DRIVE IMPORT
============================================================ */

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
        contentType
      } = req.body || {};

      if (!movieId) {
        return res.status(400).json({
          error:
            "MOVIE_ID_REQUIRED",

          message:
            "movieId is required."
        });
      }

      if (!driveFileId) {
        return res.status(400).json({
          error:
            "DRIVE_FILE_ID_REQUIRED",

          message:
            "Google Drive file ID is required."
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
            "Google Drive server authorization code is required."
        });
      }

      let accessToken =
        null;

      if (serverAuthCode) {
        try {
          const tokenData =
            await exchangeGoogleServerAuthCode(
              serverAuthCode
            );

          accessToken =
            tokenData.access_token;
        } catch (error) {
          console.error(
            "Google OAuth exchange error:",
            error.message
          );

          return res.status(400).json({
            error:
              "OAUTH_EXCHANGE_FAILED",

            message:
              error.message
          });
        }
      }

      if (
        !accessToken &&
        ALLOW_LEGACY_DRIVE_TOKEN
      ) {
        accessToken =
          req.body.accessToken ||
          null;
      }

      if (!accessToken) {
        return res.status(400).json({
          error:
            "DRIVE_AUTH_FAILED",

          message:
            "A valid Google Drive authorization token is required."
        });
      }

      const authHeader = {
        Authorization:
          `Bearer ${accessToken}`
      };

      /* ---- Drive metadata ---- */

      const metadataResponse =
        await fetch(
          `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(
            driveFileId
          )}?fields=id,name,mimeType,size,trashed&supportsAllDrives=true`,
          {
            headers:
              authHeader
          }
        );

      const metadataText =
        await metadataResponse.text();

      let driveMetadata;

      try {
        driveMetadata =
          JSON.parse(
            metadataText
          );
      } catch {
        driveMetadata = null;
      }

      if (!metadataResponse.ok) {
        return res.status(400).json({
          error:
            "DRIVE_METADATA_FAILED",

          message:
            driveMetadata?.error?.message ||
            "Unable to read the selected Google Drive file."
        });
      }

      if (driveMetadata.trashed) {
        return res.status(400).json({
          error:
            "DRIVE_FILE_TRASHED",

          message:
            "The selected Google Drive file is in trash."
        });
      }

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
            "The selected Google Drive file is not a video."
        });
      }

      const safeMovieId =
        cleanMovieId(
          movieId
        );

      const safeFileName =
        cleanFileName(
          fileName ||
          driveMetadata.name ||
          "movie.mp4"
        );

      const objectPath =
        `movies/${safeMovieId}/video/original/${safeFileName}`;

      const movieRef =
        db
          .collection("movies")
          .doc(
            safeMovieId
          );

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",

          message:
            "Movie document was not found."
        });
      }

      /* ---- Drive media stream ---- */

      const mediaResponse =
        await fetch(
          `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(
            driveFileId
          )}?alt=media&supportsAllDrives=true`,
          {
            headers:
              authHeader
          }
        );

      if (!mediaResponse.ok) {
        const errorText =
          await mediaResponse.text();

        console.error(
          "Drive media error:",
          errorText
        );

        return res.status(400).json({
          error:
            "DRIVE_MEDIA_DOWNLOAD_FAILED",

          message:
            "Unable to read video data from Google Drive."
        });
      }

      if (!mediaResponse.body) {
        return res.status(400).json({
          error:
            "DRIVE_EMPTY_RESPONSE",

          message:
            "Google Drive returned no video stream."
        });
      }

      const nodeStream =
        Readable.fromWeb(
          mediaResponse.body
        );

      const destinationFile =
        bucket.file(
          objectPath
        );

      await new Promise(
        (resolve, reject) => {
          const writeStream =
            destinationFile.createWriteStream({
              resumable:
                true,

              metadata: {
                contentType:
                  mime ||
                  "video/mp4",

                metadata: {
                  cineNovaMovieId:
                    safeMovieId,

                  driveVideoFileId:
                    String(
                      driveFileId
                    ),

                  importedBy:
                    req.uid,

                  storageProvider:
                    "GCS_PRIVATE"
                }
              }
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

      await movieRef.update({
        driveVideoFileId:
          String(
            driveFileId
          ),

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
          admin.firestore.FieldValue.serverTimestamp()
      });

      res.status(200).json({
        success: true,

        movieId:
          safeMovieId,

        driveVideoFileId:
          String(
            driveFileId
          ),

        videoObjectPath:
          objectPath,

        assetSize:
          Number(
            gcsMetadata.size || 0
          ),

        storageProvider:
          "GCS_PRIVATE",

        importStatus:
          "COMPLETED"
      });
    } catch (error) {
      console.error(
        "Google Drive import failed:",
        error
      );

      res.status(500).json({
        error:
          "DRIVE_IMPORT_FAILED",

        message:
          error.message ||
          "Google Drive import failed."
      });
    }
  }
);

/* ============================================================
   ADMIN - LIST MOVIES
============================================================ */

app.get(
  "/admin/movies",

  authenticateFirebaseUser,
  requireAdmin,

  async (req, res) => {
    try {
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

            ...doc.data()
          })
        );

      res.status(200).json({
        success: true,
        movies
      });
    } catch (error) {
      console.error(
        "Admin movie list failed:",
        error
      );

      res.status(500).json({
        error:
          "MOVIE_LIST_FAILED",

        message:
          error.message ||
          "Unable to load movies."
      });
    }
  }
);

/* ============================================================
   ADMIN - GET MOVIE
============================================================ */

app.get(
  "/admin/movies/:movieId",

  authenticateFirebaseUser,
  requireAdmin,

  async (req, res) => {
    try {
      const snap =
        await db
          .collection("movies")
          .doc(
            String(
              req.params.movieId
            )
          )
          .get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",

          message:
            "Movie was not found."
        });
      }

      res.status(200).json({
        success: true,

        movie: {
          movieId:
            snap.id,

          ...snap.data()
        }
      });
    } catch (error) {
      console.error(
        "Movie details failed:",
        error
      );

      res.status(500).json({
        error:
          "MOVIE_DETAILS_FAILED",

        message:
          error.message ||
          "Unable to load movie details."
      });
    }
  }
);

/* ============================================================
   ADMIN - UPDATE MOVIE
============================================================ */

app.patch(
  "/admin/movies/:movieId",

  authenticateFirebaseUser,
  requireAdmin,

  async (req, res) => {
    try {
      const movieRef =
        db
          .collection("movies")
          .doc(
            String(
              req.params.movieId
            )
          );

      const movieSnap =
        await movieRef.get();

      if (!movieSnap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",

          message:
            "Movie was not found."
        });
      }

      const allowed = [
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
        "bannerObjectPath"
      ];

      const updates = {};

      for (const field of allowed) {
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
        !Object.keys(updates).length
      ) {
        return res.status(400).json({
          error:
            "NO_UPDATES",

          message:
            "No valid movie fields were supplied."
        });
      }

      updates.updatedAt =
        admin.firestore.FieldValue.serverTimestamp();

      await movieRef.update(
        updates
      );

      const finalSnap =
        await movieRef.get();

      res.status(200).json({
        success: true,

        movie: {
          movieId:
            finalSnap.id,

          ...finalSnap.data()
        }
      });
    } catch (error) {
      console.error(
        "Movie update failed:",
        error
      );

      res.status(500).json({
        error:
          "MOVIE_UPDATE_FAILED",

        message:
          error.message ||
          "Unable to update movie."
      });
    }
  }
);

/* ============================================================
   ADMIN - DELETE MOVIE
============================================================ */

app.delete(
  "/admin/movies/:movieId",

  authenticateFirebaseUser,
  requireAdmin,

  async (req, res) => {
    try {
      const movieId =
        String(
          req.params.movieId
        );

      const movieRef =
        db
          .collection("movies")
          .doc(movieId);

      const snap =
        await movieRef.get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",

          message:
            "Movie was not found."
        });
      }

      const movie =
        snap.data();

      if (isStorageReady()) {
        try {
          const [files] =
            await bucket.getFiles({
              prefix:
                `movies/${movieId}/`
            });

          await Promise.all(
            files.map(
              (file) =>
                file.delete({
                  ignoreNotFound:
                    true
                })
            )
          );
        } catch (error) {
          console.error(
            "Movie storage cleanup failed:",
            error.message
          );
        }

        for (
          const path of [
            movie.videoObjectPath,
            movie.posterObjectPath,
            movie.bannerObjectPath
          ].filter(Boolean)
        ) {
          try {
            await bucket
              .file(path)
              .delete({
                ignoreNotFound:
                  true
              });
          } catch {}
        }
      }

      await movieRef.delete();

      res.status(200).json({
        success: true,

        movieId,

        deleted:
          true
      });
    } catch (error) {
      console.error(
        "Movie delete failed:",
        error
      );

      res.status(500).json({
        error:
          "MOVIE_DELETE_FAILED",

        message:
          error.message ||
          "Unable to delete movie."
      });
    }
  }
);

/* ============================================================
   ADMIN - REPLACE MOVIE VIDEO
============================================================ */

app.post(
  "/admin/movies/:movieId/replace-video",

  authenticateFirebaseUser,
  requireAdmin,

  async (req, res) => {
    try {
      if (!requireStorageReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const path =
        String(
          req.body?.videoObjectPath ||
          ""
        );

      if (!path) {
        return res.status(400).json({
          error:
            "VIDEO_OBJECT_PATH_REQUIRED",

          message:
            "videoObjectPath is required."
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
            "Movie was not found."
        });
      }

      const file =
        bucket.file(path);

      const [exists] =
        await file.exists();

      if (!exists) {
        return res.status(400).json({
          error:
            "VIDEO_OBJECT_NOT_FOUND",

          message:
            "Replacement video was not found."
        });
      }

      const [metadata] =
        await file.getMetadata();

      await movieRef.update({
        videoObjectPath:
          path,

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
          admin.firestore.FieldValue.serverTimestamp()
      });

      res.status(200).json({
        success: true,

        movieId,

        videoObjectPath:
          path,

        assetSize:
          Number(
            metadata.size || 0
          )
      });
    } catch (error) {
      console.error(
        "Replace video failed:",
        error
      );

      res.status(500).json({
        error:
          "REPLACE_VIDEO_FAILED",

        message:
          error.message ||
          "Unable to replace movie video."
      });
    }
  }
);

/* ============================================================
   USER - GET MOVIE
============================================================ */

app.get(
  "/movies/:movieId",

  authenticateFirebaseUser,
  requireUser,

  async (req, res) => {
    try {
      const snap =
        await db
          .collection("movies")
          .doc(
            String(
              req.params.movieId
            )
          )
          .get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_FOUND",

          message:
            "Movie was not found."
        });
      }

      const movie =
        snap.data();

      if (
        movie.published !== true
      ) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_AVAILABLE",

          message:
            "This movie is not currently available."
        });
      }

      res.status(200).json({
        success: true,

        movie: {
          movieId:
            snap.id,

          ...movie
        }
      });
    } catch (error) {
      console.error(
        "User movie lookup failed:",
        error
      );

      res.status(500).json({
        error:
          "MOVIE_LOOKUP_FAILED",

        message:
          error.message ||
          "Unable to load movie."
      });
    }
  }
);

/* ============================================================
   PREMIUM CHECK
============================================================ */

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
    entitlement !==
    "PREMIUM"
  ) {
    return false;
  }

  const expiry =
    userData.subscriptionExpiry ||
    userData.subscriptionExpiresAt ||
    userData.premiumUntil ||
    userData.expiryDate ||
    null;

  if (!expiry) {
    return false;
  }

  let millis = 0;

  if (
    typeof expiry.toMillis ===
    "function"
  ) {
    millis =
      expiry.toMillis();
  } else if (
    expiry._seconds != null
  ) {
    millis =
      Number(
        expiry._seconds
      ) * 1000;
  } else {
    millis =
      new Date(
        expiry
      ).getTime();
  }

  return (
    Number.isFinite(millis) &&
    millis > Date.now()
  );
}

/* ============================================================
   QUALITY
============================================================ */

function normalizeQuality(
  quality
) {
  const value =
    String(
      quality ||
      "480p"
    )
      .trim()
      .toLowerCase();

  const allowed = [
    "480p",
    "720p",
    "1080p",
    "4k"
  ];

  return allowed.includes(
    value
  )
    ? value
    : null;
}

/* ============================================================
   SECURE STREAM URL
============================================================ */

app.get(
  "/movies/:movieId/stream-url",

  authenticateFirebaseUser,
  requireUser,

  async (req, res) => {
    try {
      if (!requireStorageReady(res)) {
        return;
      }

      const movieId =
        String(
          req.params.movieId
        );

      const quality =
        normalizeQuality(
          req.query.q
        );

      if (!quality) {
        return res.status(400).json({
          error:
            "INVALID_QUALITY",

          message:
            "Supported qualities are 480p, 720p, 1080p and 4k."
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
            "Movie was not found."
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
            "Movie is not published."
        });
      }

      const premium =
        isPremiumSubscriptionActive(
          req.userDocument
        );

      if (
        !premium &&
        quality !== "480p"
      ) {
        return res.status(403).json({
          error:
            "PREMIUM_REQUIRED",

          message:
            "This quality requires an active Premium subscription."
        });
      }

      /*
       * No fallback to original file.
       * Real quality object must exist.
       */
      const qualityPath =
        `movies/${movieId}/video/${quality}/movie.mp4`;

      const file =
        bucket.file(
          qualityPath
        );

      const [exists] =
        await file.exists();

      if (!exists) {
        return res.status(404).json({
          error:
            "QUALITY_NOT_AVAILABLE",

          message:
            `${quality} version is not available for this movie.`
        });
      }

      const expiresAt =
        Date.now() +
        15 * 60 * 1000;

      const [signedUrl] =
        await file.getSignedUrl({
          version:
            "v4",

          action:
            "read",

          expires:
            new Date(
              expiresAt
            )
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

          quality,

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
            admin.firestore.FieldValue.serverTimestamp()
        });

      res.status(200).json({
        success: true,

        streamUrl:
          signedUrl,

        sessionId,

        quality,

        entitlement:
          premium
            ? "PREMIUM"
            : "FREE",

        expiresAt
      });
    } catch (error) {
      console.error(
        "Stream URL generation failed:",
        error
      );

      res.status(500).json({
        error:
          "STREAM_URL_FAILED",

        message:
          error.message ||
          "Unable to create secure stream URL."
      });
    }
  }
);

/* ============================================================
   PLAYBACK HEARTBEAT
============================================================ */

app.post(
  "/playback/session/heartbeat",

  authenticateFirebaseUser,
  requireUser,

  async (req, res) => {
    try {
      const sessionId =
        String(
          req.body?.sessionId ||
          ""
        );

      if (!sessionId) {
        return res.status(400).json({
          error:
            "SESSION_ID_REQUIRED",

          message:
            "Playback session ID is required."
        });
      }

      const sessionRef =
        db
          .collection(
            "playbackSessions"
          )
          .doc(sessionId);

      const date =
        new Date()
          .toISOString()
          .slice(
            0,
            10
          );

      const usageRef =
        db
          .collection(
            "dailyPlaybackUsage"
          )
          .doc(
            `${req.uid}_${date}`
          );

      const result =
        await db.runTransaction(
          async (
            transaction
          ) => {
            const sessionSnap =
              await transaction.get(
                sessionRef
              );

            if (!sessionSnap.exists) {
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
                  0
              };
            }

            const now =
              Date.now();

            let last =
              now;

            const hb =
              session.lastHeartbeatAt;

            if (
              hb &&
              typeof hb.toMillis ===
                "function"
            ) {
              last =
                hb.toMillis();
            } else if (
              hb?._seconds !=
              null
            ) {
              last =
                Number(
                  hb._seconds
                ) * 1000;
            }

            let delta =
              Math.floor(
                (now - last) /
                1000
              );

            if (
              !Number.isFinite(
                delta
              ) ||
              delta < 0
            ) {
              delta = 0;
            }

            /*
             * Android sends heartbeat roughly every 10 sec.
             * Cap abnormal gaps.
             */
            delta =
              Math.min(
                delta,
                30
              );

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
                      delta
                    )
                }
              );

              return {
                active:
                  true,

                remainingSeconds:
                  null,

                countedSeconds:
                  delta,

                entitlement:
                  "PREMIUM"
              };
            }

            const usageSnap =
              await transaction.get(
                usageRef
              );

            const current =
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
                current
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
                    admin.firestore.FieldValue.serverTimestamp()
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
                  "FREE"
              };
            }

            const counted =
              Math.min(
                delta,
                remaining
              );

            if (usageSnap.exists) {
              transaction.update(
                usageRef,
                {
                  seconds:
                    current +
                    counted,

                  updatedAt:
                    admin.firestore.FieldValue.serverTimestamp()
                }
              );
            } else {
              transaction.set(
                usageRef,
                {
                  uid:
                    req.uid,

                  date,

                  seconds:
                    counted,

                  createdAt:
                    admin.firestore.FieldValue.serverTimestamp(),

                  updatedAt:
                    admin.firestore.FieldValue.serverTimestamp()
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
                  counted > 0
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
                "FREE"
            };
          }
        );

      res.status(200).json({
        success: true,
        ...result
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
            "Playback session was not found."
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
            "This playback session does not belong to the current user."
        });
      }

      res.status(500).json({
        error:
          "HEARTBEAT_FAILED",

        message:
          error.message ||
          "Playback heartbeat failed."
      });
    }
  }
);

/* ============================================================
   PLAYBACK STOP
============================================================ */

app.post(
  "/playback/session/stop",

  authenticateFirebaseUser,
  requireUser,

  async (req, res) => {
    try {
      const sessionId =
        String(
          req.body?.sessionId ||
          ""
        );

      if (!sessionId) {
        return res.status(400).json({
          error:
            "SESSION_ID_REQUIRED",

          message:
            "Playback session ID is required."
        });
      }

      const ref =
        db
          .collection(
            "playbackSessions"
          )
          .doc(sessionId);

      const snap =
        await ref.get();

      if (!snap.exists) {
        return res.status(404).json({
          error:
            "SESSION_NOT_FOUND",

          message:
            "Playback session was not found."
        });
      }

      if (
        snap.data().uid !==
        req.uid
      ) {
        return res.status(403).json({
          error:
            "SESSION_FORBIDDEN",

          message:
            "This playback session does not belong to the current user."
        });
      }

      await ref.update({
        active:
          false,

        stoppedAt:
          admin.firestore.FieldValue.serverTimestamp(),

        updatedAt:
          admin.firestore.FieldValue.serverTimestamp()
      });

      res.status(200).json({
        success:
          true,

        sessionId,

        stopped:
          true
      });
    } catch (error) {
      console.error(
        "Playback stop failed:",
        error
      );

      res.status(500).json({
        error:
          "SESSION_STOP_FAILED",

        message:
          error.message ||
          "Unable to stop playback session."
      });
    }
  }
);

/* ============================================================
   DAILY USAGE
============================================================ */

app.get(
  "/playback/usage/today",

  authenticateFirebaseUser,
  requireUser,

  async (req, res) => {
    try {
      const date =
        new Date()
          .toISOString()
          .slice(
            0,
            10
          );

      const snap =
        await db
          .collection(
            "dailyPlaybackUsage"
          )
          .doc(
            `${req.uid}_${date}`
          )
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

      res.status(200).json({
        success:
          true,

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
            : "FREE"
      });
    } catch (error) {
      console.error(
        "Daily usage failed:",
        error
      );

      res.status(500).json({
        error:
          "USAGE_LOOKUP_FAILED",

        message:
          error.message ||
          "Unable to load today's playback usage."
      });
    }
  }
);

/* ============================================================
   PREMIUM DOWNLOAD
============================================================ */

app.get(
  "/movies/:movieId/download-url",

  authenticateFirebaseUser,
  requireUser,

  async (req, res) => {
    try {
      if (!requireStorageReady(res)) {
        return;
      }

      if (
        !isPremiumSubscriptionActive(
          req.userDocument
        )
      ) {
        return res.status(403).json({
          error:
            "PREMIUM_REQUIRED",

          message:
            "Movie downloads are available only with an active Premium subscription."
        });
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
            "Movie was not found."
        });
      }

      const movie =
        snap.data();

      if (
        movie.published !== true
      ) {
        return res.status(404).json({
          error:
            "MOVIE_NOT_AVAILABLE",

          message:
            "Movie is not currently available."
        });
      }

      if (
        !movie.videoObjectPath
      ) {
        return res.status(404).json({
          error:
            "VIDEO_NOT_AVAILABLE",

          message:
            "A downloadable video asset is not available."
        });
      }

      const file =
        bucket.file(
          movie.videoObjectPath
        );

      const [exists] =
        await file.exists();

      if (!exists) {
        return res.status(404).json({
          error:
            "VIDEO_OBJECT_NOT_FOUND",

          message:
            "The private video asset could not be found."
        });
      }

      const expiresAt =
        Date.now() +
        15 * 60 * 1000;

      const [url] =
        await file.getSignedUrl({
          version:
            "v4",

          action:
            "read",

          expires:
            new Date(
              expiresAt
            ),

          responseDisposition:
            "attachment"
        });

      res.status(200).json({
        success:
          true,

        movieId,

        downloadUrl:
          url,

        expiresAt
      });
    } catch (error) {
      console.error(
        "Download URL failed:",
        error
      );

      res.status(500).json({
        error:
          "DOWNLOAD_URL_FAILED",

        message:
          error.message ||
          "Unable to create secure download URL."
      });
    }
  }
);

/* ============================================================
   RAZORPAY
============================================================ */

function isRazorpayConfigured() {
  return Boolean(
    RAZORPAY_KEY_ID &&
    RAZORPAY_KEY_SECRET
  );
}

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

          ...(options.headers || {})
        }
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
      raw: text
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

    throw error;
  }

  return data;
}

/* ============================================================
   CREATE PAYMENT ORDER
============================================================ */

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
            "Razorpay payment service is not configured yet."
        });
      }

      const amount =
        PREMIUM_PRICE_INR * 100;

      const receipt =
        `cn_${req.uid}_${Date.now()}`;

      const order =
        await razorpayRequest(
          "/orders",
          {
            method:
              "POST",

            body:
              JSON.stringify({
                amount,

                currency:
                  "INR",

                receipt,

                notes: {
                  uid:
                    req.uid,

                  plan:
                    "PREMIUM_MONTHLY"
                }
              })
          }
        );

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

          amount,

          currency:
            "INR",

          plan:
            "PREMIUM_MONTHLY",

          status:
            "CREATED",

          createdAt:
            admin.firestore.FieldValue.serverTimestamp(),

          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

      res.status(200).json({
        success:
          true,

        orderId:
          order.id,

        amount:
          order.amount,

        currency:
          order.currency,

        keyId:
          RAZORPAY_KEY_ID
      });
    } catch (error) {
      console.error(
        "Create Razorpay order failed:",
        error
      );

      res.status(
        error.status || 500
      ).json({
        error:
          "PAYMENT_ORDER_FAILED",

        message:
          error.message ||
          "Unable to create payment order."
      });
    }
  }
);

/* ============================================================
   PAYMENT SIGNATURE
============================================================ */

function verifyRazorpayPaymentSignature({
  orderId,
  paymentId,
  signature
}) {
  if (
    !orderId ||
    !paymentId ||
    !signature ||
    !RAZORPAY_KEY_SECRET
  ) {
    return false;
  }

  const expected =
    crypto
      .createHmac(
        "sha256",
        RAZORPAY_KEY_SECRET
      )
      .update(
        `${orderId}|${paymentId}`
      )
      .digest("hex");

  const actual =
    String(
      signature
    );

  if (
    expected.length !==
    actual.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(actual)
  );
}

/* ============================================================
   VERIFY PAYMENT
============================================================ */

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
            "Razorpay payment service is not configured."
        });
      }

      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature
      } =
        req.body || {};

      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          error:
            "PAYMENT_DETAILS_MISSING",

          message:
            "Razorpay payment verification details are incomplete."
        });
      }

      const signatureValid =
        verifyRazorpayPaymentSignature({
          orderId:
            razorpay_order_id,

          paymentId:
            razorpay_payment_id,

          signature:
            razorpay_signature
        });

      if (!signatureValid) {
        return res.status(400).json({
          error:
            "INVALID_PAYMENT_SIGNATURE",

          message:
            "Payment signature verification failed."
        });
      }

      const paymentRef =
        db
          .collection("payments")
          .doc(
            String(
              razorpay_order_id
            )
          );

      const paymentSnap =
        await paymentRef.get();

      if (!paymentSnap.exists) {
        return res.status(400).json({
          error:
            "PAYMENT_ORDER_NOT_FOUND",

          message:
            "Payment order was not created for this account."
        });
      }

      const record =
        paymentSnap.data();

      if (
        record.uid !==
        req.uid
      ) {
        return res.status(403).json({
          error:
            "PAYMENT_ORDER_FORBIDDEN",

          message:
            "This payment order does not belong to the current user."
        });
      }

      const payment =
        await razorpayRequest(
          `/payments/${encodeURIComponent(
            razorpay_payment_id
          )}`,
          {
            method:
              "GET"
          }
        );

      const order =
        await razorpayRequest(
          `/orders/${encodeURIComponent(
            razorpay_order_id
          )}`,
          {
            method:
              "GET"
          }
        );

      if (
        Number(payment.amount) !==
        PREMIUM_PRICE_INR * 100
      ) {
        return res.status(400).json({
          error:
            "INVALID_PAYMENT_AMOUNT",

          message:
            "Payment amount does not match the Premium plan price."
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
            "Payment currency is invalid."
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
            "Payment order amount is invalid."
        });
      }

      if (
        String(payment.order_id) !==
        String(razorpay_order_id)
      ) {
        return res.status(400).json({
          error:
            "PAYMENT_ORDER_MISMATCH",

          message:
            "Payment and order do not match."
        });
      }

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
            "Payment has not been captured successfully."
        });
      }

      const existing =
        await db
          .collection("payments")
          .where(
            "razorpayPaymentId",
            "==",
            String(
              razorpay_payment_id
            )
          )
          .limit(1)
          .get();

      if (!existing.empty) {
        const user =
          await getUserDocument(
            req.uid
          );

        return res.status(200).json({
          success:
            true,

          alreadyProcessed:
            true,

          entitlement:
            user?.entitlement ||
            "FREE",

          subscriptionExpiry:
            user?.subscriptionExpiry ||
            null
        });
      }

      const userRef =
        db
          .collection("users")
          .doc(req.uid);

      const userSnap =
        await userRef.get();

      const user =
        userSnap.exists
          ? userSnap.data()
          : {};

      let baseDate =
        new Date();

      const currentExpiry =
        user.subscriptionExpiry;

      if (currentExpiry) {
        let expiryMillis = 0;

        if (
          typeof currentExpiry.toMillis ===
          "function"
        ) {
          expiryMillis =
            currentExpiry.toMillis();
        } else if (
          currentExpiry._seconds !=
          null
        ) {
          expiryMillis =
            Number(
              currentExpiry._seconds
            ) * 1000;
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

      await db.runTransaction(
        async (transaction) => {
          transaction.update(
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
                admin.firestore.FieldValue.serverTimestamp()
            }
          );

          transaction.update(
            paymentRef,
            {
              razorpayPaymentId:
                String(
                  razorpay_payment_id
                ),

              status:
                "CAPTURED",

              verifiedAt:
                admin.firestore.FieldValue.serverTimestamp(),

              updatedAt:
                admin.firestore.FieldValue.serverTimestamp()
            }
          );
        }
      );

      res.status(200).json({
        success:
          true,

        alreadyProcessed:
          false,

        entitlement:
          "PREMIUM",

        subscriptionPlan:
          "PREMIUM_MONTHLY",

        subscriptionExpiry:
          expiryDate.toISOString()
      });
    } catch (error) {
      console.error(
        "Payment verification failed:",
        error
      );

      res.status(
        error.status || 500
      ).json({
        error:
          "PAYMENT_VERIFICATION_FAILED",

        message:
          error.message ||
          "Unable to verify payment."
      });
    }
  }
);

/* ============================================================
   RAZORPAY WEBHOOK
============================================================ */

function verifyWebhookSignature(
  rawBody,
  signature
) {
  if (
    !RAZORPAY_WEBHOOK_SECRET ||
    !rawBody ||
    !signature
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

  const actual =
    String(
      signature
    );

  if (
    expected.length !==
    actual.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(actual)
  );
}

app.post(
  "/payment/webhook",

  async (req, res) => {
    try {
      const signature =
        req.headers[
          "x-razorpay-signature"
        ];

      const rawBody =
        req.rawBody;

      if (
        !verifyWebhookSignature(
          rawBody,
          signature
        )
      ) {
        return res.status(400).json({
          error:
            "INVALID_WEBHOOK_SIGNATURE",

          message:
            "Webhook signature verification failed."
        });
      }

      const payload =
        JSON.parse(
          rawBody.toString(
            "utf8"
          )
        );

      const event =
        String(
          payload.event || ""
        );

      if (
        event !==
          "payment.captured" &&
        event !==
          "order.paid"
      ) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      const payment =
        payload?.payload
          ?.payment
          ?.entity;

      if (!payment?.id) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      const paymentId =
        String(
          payment.id
        );

      const orderId =
        String(
          payment.order_id ||
          ""
        );

      if (!orderId) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      const order =
        await razorpayRequest(
          `/orders/${encodeURIComponent(
            orderId
          )}`,
          {
            method:
              "GET"
          }
        );

      const uid =
        String(
          order?.notes?.uid ||
          ""
        );

      if (!uid) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      if (
        Number(payment.amount) !==
        PREMIUM_PRICE_INR * 100
      ) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      if (
        String(
          payment.currency
        ).toUpperCase() !==
        "INR"
      ) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      if (
        String(
          payment.status
        ).toLowerCase() !==
        "captured"
      ) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      const paymentRef =
        db
          .collection("payments")
          .doc(paymentId);

      const existing =
        await paymentRef.get();

      if (
        existing.exists &&
        existing.data()
          ?.status ===
          "CAPTURED"
      ) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false,

          reason:
            "ALREADY_PROCESSED"
        });
      }

      const userRef =
        db
          .collection("users")
          .doc(uid);

      const userSnap =
        await userRef.get();

      if (!userSnap.exists) {
        return res.status(200).json({
          success:
            true,

          received:
            true,

          processed:
            false
        });
      }

      const user =
        userSnap.data();

      let baseDate =
        new Date();

      const currentExpiry =
        user.subscriptionExpiry;

      if (currentExpiry) {
        let millis = 0;

        if (
          typeof currentExpiry.toMillis ===
          "function"
        ) {
          millis =
            currentExpiry.toMillis();
        } else if (
          currentExpiry._seconds !=
          null
        ) {
          millis =
            Number(
              currentExpiry._seconds
            ) * 1000;
        } else {
          millis =
            new Date(
              currentExpiry
            ).getTime();
        }

        if (
          Number.isFinite(millis) &&
          millis > Date.now()
        ) {
          baseDate =
            new Date(millis);
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
          admin.firestore.FieldValue.serverTimestamp()
      });

      await paymentRef.set(
        {
          paymentId,

          razorpayPaymentId:
            paymentId,

          razorpayOrderId:
            orderId,

          uid,

          amount:
            Number(
              payment.amount
            ),

          currency:
            "INR",

          plan:
            "PREMIUM_MONTHLY",

          status:
            "CAPTURED",

          source:
            "RAZORPAY_WEBHOOK",

          verifiedAt:
            admin.firestore.FieldValue.serverTimestamp(),

          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        },
        {
          merge:
            true
        }
      );

      res.status(200).json({
        success:
          true,

        received:
          true,

        processed:
          true
      });
    } catch (error) {
      console.error(
        "Razorpay webhook failed:",
        error
      );

      res.status(500).json({
        error:
          "WEBHOOK_PROCESSING_FAILED",

        message:
          error.message ||
          "Webhook processing failed."
      });
    }
  }
);

/* ============================================================
   404
============================================================ */

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "NOT_FOUND",

      message:
        `Route ${req.method} ${req.originalUrl} was not found.`
    });
  }
);

/* ============================================================
   GLOBAL ERROR HANDLER
============================================================ */

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

    res.status(500).json({
      error:
        "INTERNAL_SERVER_ERROR",

      message:
        process.env.NODE_ENV ===
        "production"
          ? "An internal server error occurred."
          : (
              error.message ||
              "Internal server error."
            )
    });
  }
);

/* ============================================================
   START SERVER
============================================================ */

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

module.exports = app;
