import { apiService } from "./api.service";

export interface MediaUploadResult {
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
  /**
   * Upload photo
   * @param file - File to upload
   * @param mode - "photo" (compressed) or "file" (original)
   * @param onProgress - Progress callback (0-100)
   */
  static async uploadPhoto(
    file: File,
    mode: "photo" | "file" = "photo",
    onProgress?: (progress: number) => void,
  ): Promise<MediaUploadResult> {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("mode", mode);

    const token = localStorage.getItem("token");
    if (!token) {
      throw new Error("Not authenticated");
    }

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();

      // Progress tracking
      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable && onProgress) {
          const progress = Math.round((e.loaded / e.total) * 100);
          onProgress(progress);
        }
      });

      // Complete
      xhr.addEventListener("load", () => {
        if (xhr.status === 200) {
          const response = JSON.parse(xhr.responseText);
          if (response.success) {
            resolve(response.data);
          } else {
            reject(new Error(response.error || "Upload failed"));
          }
        } else {
          reject(new Error(`Upload failed: ${xhr.status}`));
        }
      });

      // Error
      xhr.addEventListener("error", () => {
        reject(new Error("Network error"));
      });

      // Abort
      xhr.addEventListener("abort", () => {
        reject(new Error("Upload cancelled"));
      });

      xhr.open("POST", `${apiService.API_URL}/media/upload-photo`);
      xhr.setRequestHeader("Authorization", `Bearer ${token}`);
      xhr.send(formData);
    });
  }

  /**
   * Get media URL
   */
  static getMediaUrl(filePath: string): string {
    return `${apiService.API_URL.replace("/api", "")}/uploads/${filePath}`;
  }

  /**
   * Get thumbnail URL
   */
  static getThumbnailUrl(thumbnailPath: string | null): string | null {
    if (!thumbnailPath) return null;
    return `${apiService.API_URL.replace("/api", "")}/uploads/${thumbnailPath}`;
  }
}
