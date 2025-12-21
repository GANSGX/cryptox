import type { FastifyInstance } from "fastify";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { writeFile, unlink } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";
import { pool } from "../db/pool.js";
import type { Server as SocketIOServer } from "socket.io";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface ProfilePhoto {
  id: string;
  username: string;
  photo_path: string;
  is_primary: boolean;
  position: number;
  created_at: Date;
}

export async function profilePhotosRoutes(fastify: FastifyInstance) {
  /**
   * POST /profile/photos
   * Upload new profile photo
   */
  fastify.post(
    "/profile/photos",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        const data = await request.file();

        if (!data) {
          return reply.code(400).send({
            success: false,
            error: "No file uploaded",
          });
        }

        // Validate file type
        const allowedMimeTypes = [
          "image/jpeg",
          "image/jpg",
          "image/png",
          "image/gif",
          "image/webp",
        ];
        if (!allowedMimeTypes.includes(data.mimetype)) {
          return reply.code(400).send({
            success: false,
            error: "Only image files are allowed (JPEG, PNG, GIF, WEBP)",
          });
        }

        // Generate unique filename
        const ext = data.filename.split(".").pop() || "jpg";
        const filename = `${request.user!.username}_${randomBytes(8).toString("hex")}.${ext}`;

        // Save file
        const uploadsDir = join(__dirname, "..", "..", "uploads", "avatars");
        const filepath = join(uploadsDir, filename);

        const buffer = await data.toBuffer();
        await writeFile(filepath, buffer);

        const photoPath = `/uploads/avatars/${filename}`;

        // Get current photo count for position
        const countResult = await pool.query<{ count: string }>(
          "SELECT COUNT(*) as count FROM profile_photos WHERE username = $1",
          [request.user!.username.toLowerCase()],
        );
        const position = parseInt(countResult.rows[0].count);

        // Insert into database
        const result = await pool.query<ProfilePhoto>(
          `INSERT INTO profile_photos (username, photo_path, is_primary, position)
           VALUES ($1, $2, $3, $4)
           RETURNING id, username, photo_path, is_primary, position, created_at`,
          [
            request.user!.username.toLowerCase(),
            photoPath,
            position === 0, // First photo is primary by default
            position,
          ],
        );

        const photo = result.rows[0];

        // If this is the first photo, update users.avatar_path
        if (position === 0) {
          await pool.query(
            "UPDATE users SET avatar_path = $1 WHERE username = $2",
            [photoPath, request.user!.username.toLowerCase()],
          );

          // Broadcast avatar update to all connected clients
          if (fastify.io) {
            fastify.io.emit("avatar_updated", {
              username: request.user!.username.toLowerCase(),
              avatar_path: photoPath,
            });
          }
        }

        return reply.code(201).send({
          success: true,
          data: {
            id: photo.id,
            photo_path: photo.photo_path,
            is_primary: photo.is_primary,
            position: photo.position,
          },
          message: "Photo uploaded successfully",
        });
      } catch (error) {
        console.error("❌ Error in POST /profile/photos:", error);

        return reply.code(500).send({
          success: false,
          error: "Failed to upload photo",
        });
      }
    },
  );

  /**
   * GET /profile/photos
   * Get all profile photos for current user
   */
  fastify.get(
    "/profile/photos",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        const result = await pool.query<ProfilePhoto>(
          `SELECT id, username, photo_path, is_primary, position, created_at
           FROM profile_photos
           WHERE username = $1
           ORDER BY position ASC`,
          [request.user!.username.toLowerCase()],
        );

        return reply.code(200).send({
          success: true,
          data: {
            photos: result.rows.map((photo) => ({
              id: photo.id,
              photo_path: photo.photo_path,
              is_primary: photo.is_primary,
              position: photo.position,
              created_at: photo.created_at.toISOString(),
            })),
          },
        });
      } catch (error) {
        console.error("❌ Error in GET /profile/photos:", error);

        return reply.code(500).send({
          success: false,
          error: "Failed to fetch photos",
        });
      }
    },
  );

  /**
   * DELETE /profile/photos/:id
   * Delete a profile photo
   */
  fastify.delete<{
    Params: { id: string };
  }>(
    "/profile/photos/:id",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        const { id } = request.params;

        // Get photo info
        const photoResult = await pool.query<ProfilePhoto>(
          "SELECT * FROM profile_photos WHERE id = $1 AND username = $2",
          [id, request.user!.username.toLowerCase()],
        );

        if (photoResult.rows.length === 0) {
          return reply.code(404).send({
            success: false,
            error: "Photo not found",
          });
        }

        const photo = photoResult.rows[0];

        // Delete file from disk
        try {
          const filepath = join(
            __dirname,
            "..",
            "..",
            photo.photo_path.replace(/^\//, ""),
          );
          await unlink(filepath);
        } catch (err) {
          console.error("Failed to delete file from disk:", err);
          // Continue anyway
        }

        // Delete from database
        await pool.query("DELETE FROM profile_photos WHERE id = $1", [id]);

        // If this was the primary photo, set next photo as primary
        if (photo.is_primary) {
          const nextPhotoResult = await pool.query<ProfilePhoto>(
            `SELECT id FROM profile_photos
             WHERE username = $1
             ORDER BY position ASC
             LIMIT 1`,
            [request.user!.username.toLowerCase()],
          );

          if (nextPhotoResult.rows.length > 0) {
            const nextPhotoId = nextPhotoResult.rows[0].id;
            await pool.query(
              "UPDATE profile_photos SET is_primary = true WHERE id = $1 RETURNING photo_path",
              [nextPhotoId],
            );

            // Update users.avatar_path
            const updatedPhoto = await pool.query<{ photo_path: string }>(
              "SELECT photo_path FROM profile_photos WHERE id = $1",
              [nextPhotoId],
            );
            if (updatedPhoto.rows.length > 0) {
              await pool.query(
                "UPDATE users SET avatar_path = $1 WHERE username = $2",
                [
                  updatedPhoto.rows[0].photo_path,
                  request.user!.username.toLowerCase(),
                ],
              );

              // Broadcast avatar update
              if (fastify.io) {
                fastify.io.emit("avatar_updated", {
                  username: request.user!.username.toLowerCase(),
                  avatar_path: updatedPhoto.rows[0].photo_path,
                });
              }
            }
          } else {
            // No more photos, clear avatar_path
            await pool.query(
              "UPDATE users SET avatar_path = NULL WHERE username = $1",
              [request.user!.username.toLowerCase()],
            );

            // Broadcast avatar removal
            if (fastify.io) {
              fastify.io.emit("avatar_updated", {
                username: request.user!.username.toLowerCase(),
                avatar_path: null,
              });
            }
          }
        }

        // Reorder remaining photos
        await pool.query(
          `UPDATE profile_photos
           SET position = position - 1
           WHERE username = $1 AND position > $2`,
          [request.user!.username.toLowerCase(), photo.position],
        );

        return reply.code(200).send({
          success: true,
          message: "Photo deleted successfully",
        });
      } catch (error) {
        console.error("❌ Error in DELETE /profile/photos/:id:", error);

        return reply.code(500).send({
          success: false,
          error: "Failed to delete photo",
        });
      }
    },
  );

  /**
   * PATCH /profile/photos/:id/set-primary
   * Set a photo as primary (main avatar)
   */
  fastify.patch<{
    Params: { id: string };
  }>(
    "/profile/photos/:id/set-primary",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        const { id } = request.params;

        // Verify photo belongs to user
        const photoResult = await pool.query<ProfilePhoto>(
          "SELECT * FROM profile_photos WHERE id = $1 AND username = $2",
          [id, request.user!.username.toLowerCase()],
        );

        if (photoResult.rows.length === 0) {
          return reply.code(404).send({
            success: false,
            error: "Photo not found",
          });
        }

        const photo = photoResult.rows[0];

        // Unset current primary
        await pool.query(
          "UPDATE profile_photos SET is_primary = false WHERE username = $1 AND is_primary = true",
          [request.user!.username.toLowerCase()],
        );

        // Set new primary
        await pool.query(
          "UPDATE profile_photos SET is_primary = true WHERE id = $1",
          [id],
        );

        // Update users.avatar_path
        await pool.query(
          "UPDATE users SET avatar_path = $1 WHERE username = $2",
          [photo.photo_path, request.user!.username.toLowerCase()],
        );

        // Broadcast avatar update to all connected clients
        if (fastify.io) {
          fastify.io.emit("avatar_updated", {
            username: request.user!.username.toLowerCase(),
            avatar_path: photo.photo_path,
          });
        }

        return reply.code(200).send({
          success: true,
          data: {
            photo_path: photo.photo_path,
          },
          message: "Primary photo updated successfully",
        });
      } catch (error) {
        console.error(
          "❌ Error in PATCH /profile/photos/:id/set-primary:",
          error,
        );

        return reply.code(500).send({
          success: false,
          error: "Failed to set primary photo",
        });
      }
    },
  );
}
