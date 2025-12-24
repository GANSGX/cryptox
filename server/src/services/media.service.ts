import sharp from "sharp";
import { writeFile, mkdir } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { randomBytes } from "crypto";
import { pool } from "../db/pool.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface MediaProcessingResult {
  media_id: string;
  file_path: string;
  thumbnail_path: string | null;
  file_size: number;
  width: number | null;
  height: number | null;
  mime_type: string;
  original_name: string;
}

export class MediaService {
  private static uploadsDir = join(__dirname, "..", "..", "uploads");

  /**
   * Process and save photo
   * Two modes:
   * - "photo": Compress to WebP, generate thumbnail (for quick sending)
   * - "file": Save original quality (for Send as File)
   */
  static async processPhoto(
    buffer: Buffer,
    filename: string,
    username: string,
    mode: "photo" | "file" = "photo",
  ): Promise<MediaProcessingResult> {
    const ext = filename.split(".").pop()?.toLowerCase() || "jpg";
    const baseName = `${username}_${randomBytes(12).toString("hex")}`;

    // Create directories
    const photoDir = join(this.uploadsDir, "photos");
    const thumbnailDir = join(this.uploadsDir, "thumbnails");
    await mkdir(photoDir, { recursive: true });
    await mkdir(thumbnailDir, { recursive: true });

    let processedPath: string;
    let thumbnailPath: string | null = null;
    let fileSize: number;
    let width: number;
    let height: number;
    let mimeType: string;

    const image = sharp(buffer);
    const metadata = await image.metadata();

    if (mode === "photo") {
      // Compress to WebP (good quality, small size)
      const webpFilename = `${baseName}.webp`;
      processedPath = join(photoDir, webpFilename);

      // Resize if too large (max 2560px width, maintain aspect ratio)
      let processedImage = image;
      if (metadata.width && metadata.width > 2560) {
        processedImage = processedImage.resize(2560, null, {
          withoutEnlargement: true,
        });
      }

      // Convert to WebP with quality 85 (visually lossless, great compression)
      const webpBuffer = await processedImage
        .webp({ quality: 85, effort: 6 })
        .toBuffer();

      await writeFile(processedPath, webpBuffer);

      fileSize = webpBuffer.length;
      const resizedMetadata = await sharp(webpBuffer).metadata();
      width = resizedMetadata.width || metadata.width || 0;
      height = resizedMetadata.height || metadata.height || 0;
      mimeType = "image/webp";

      // Generate thumbnail (320px width)
      const thumbFilename = `thumb_${baseName}.webp`;
      thumbnailPath = join(thumbnailDir, thumbFilename);

      const thumbnailBuffer = await image
        .resize(320, null, { withoutEnlargement: true })
        .webp({ quality: 75 })
        .toBuffer();

      await writeFile(thumbnailPath, thumbnailBuffer);
    } else {
      // Save original (for "Send as File")
      const originalFilename = `${baseName}.${ext}`;
      processedPath = join(photoDir, originalFilename);

      await writeFile(processedPath, buffer);

      fileSize = buffer.length;
      width = metadata.width || 0;
      height = metadata.height || 0;
      mimeType = `image/${ext === "jpg" ? "jpeg" : ext}`;

      // Still generate thumbnail for preview
      const thumbFilename = `thumb_${baseName}.webp`;
      thumbnailPath = join(thumbnailDir, thumbFilename);

      const thumbnailBuffer = await image
        .resize(320, null, { withoutEnlargement: true })
        .webp({ quality: 75 })
        .toBuffer();

      await writeFile(thumbnailPath, thumbnailBuffer);
    }

    // Save to database
    const result = await pool.query<{ id: string }>(
      `INSERT INTO media_files (
        owner_username, file_type, file_path, file_name, file_size,
        mime_type, encrypted_key, thumbnail_path, width, height
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id`,
      [
        username.toLowerCase(),
        "image",
        processedPath.replace(/\\/g, "/").split("uploads/")[1],
        filename,
        fileSize,
        mimeType,
        "", // encrypted_key (will be set by client for E2E)
        thumbnailPath
          ? thumbnailPath.replace(/\\/g, "/").split("uploads/")[1]
          : null,
        width,
        height,
      ],
    );

    return {
      media_id: result.rows[0].id,
      file_path: processedPath.replace(/\\/g, "/").split("uploads/")[1],
      thumbnail_path: thumbnailPath
        ? thumbnailPath.replace(/\\/g, "/").split("uploads/")[1]
        : null,
      file_size: fileSize,
      width,
      height,
      mime_type: mimeType,
      original_name: filename,
    };
  }

  /**
   * Get media file info
   */
  static async getMediaInfo(mediaId: string) {
    const result = await pool.query(`SELECT * FROM media_files WHERE id = $1`, [
      mediaId,
    ]);

    if (result.rows.length === 0) {
      return null;
    }

    return result.rows[0];
  }
}
