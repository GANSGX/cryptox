import type { FastifyInstance } from "fastify";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { MediaService } from "../services/media.service.js";

export async function mediaRoutes(fastify: FastifyInstance) {
  /**
   * POST /media/upload-photo
   * Upload photo (with mode: "photo" or "file")
   */
  fastify.post(
    "/media/upload-photo",
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

        // Get mode from fields (default: "photo")
        const fields = data.fields as any;
        const mode = (fields?.mode?.value as "photo" | "file") || "photo";

        // Validate mode
        if (mode !== "photo" && mode !== "file") {
          return reply.code(400).send({
            success: false,
            error: 'Mode must be "photo" or "file"',
          });
        }

        // Process file
        const buffer = await data.toBuffer();

        // Validate file size (max 10MB for photos)
        const maxSize = 10 * 1024 * 1024; // 10MB
        if (buffer.length > maxSize) {
          return reply.code(400).send({
            success: false,
            error: "File too large (max 10MB)",
          });
        }

        const result = await MediaService.processPhoto(
          buffer,
          data.filename,
          request.user!.username,
          mode,
        );

        return reply.code(200).send({
          success: true,
          data: result,
          message: "Photo uploaded successfully",
        });
      } catch (error) {
        console.error("❌ Error in POST /media/upload-photo:", error);

        return reply.code(500).send({
          success: false,
          error: "Failed to upload photo",
        });
      }
    },
  );

  /**
   * GET /media/:id
   * Get media file info
   */
  fastify.get<{
    Params: { id: string };
  }>(
    "/media/:id",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        const { id } = request.params;

        const media = await MediaService.getMediaInfo(id);

        if (!media) {
          return reply.code(404).send({
            success: false,
            error: "Media not found",
          });
        }

        return reply.code(200).send({
          success: true,
          data: media,
        });
      } catch (error) {
        console.error("❌ Error in GET /media/:id:", error);

        return reply.code(500).send({
          success: false,
          error: "Failed to get media info",
        });
      }
    },
  );
}
