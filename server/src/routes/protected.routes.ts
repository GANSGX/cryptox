import type { FastifyInstance } from "fastify";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { UserService } from "../services/user.service.js";

export async function protectedRoutes(fastify: FastifyInstance) {
  /**
   * GET /me
   * Получение информации о текущем пользователе
   */
  fastify.get(
    "/me",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        console.log("🔍 /me called, user:", request.user);

        // Получаем полную информацию о пользователе из БД
        const user = await UserService.getUserByUsername(
          request.user!.username,
        );

        console.log("📦 User from DB:", user);

        // Generic error (prevent username enumeration)
        if (!user) {
          return reply.code(400).send({
            success: false,
            error: "Invalid request",
          });
        }

        return reply.code(200).send({
          success: true,
          data: {
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
            status: user.status,
            birthday: user.birthday,
            avatar_path: user.avatar_path,
            status_privacy: user.status_privacy,
            online_privacy: user.online_privacy,
            typing_privacy: user.typing_privacy,
          },
          message: "Authenticated successfully",
        });
      } catch (error) {
        // Log error server-side only
        console.error("❌ Error in /me:", error);

        // Generic error response
        return reply.code(500).send({
          success: false,
          error: "Operation failed",
        });
      }
    },
  );

  /**
   * PATCH /profile
   * Обновление профиля пользователя
   */
  fastify.patch<{
    Body: {
      status?: string;
      birthday?: string | null;
      avatar_path?: string | null;
      status_privacy?: "everyone" | "chats" | "friends" | "nobody";
      online_privacy?: "everyone" | "chats" | "friends" | "nobody";
      typing_privacy?: "everyone" | "chats" | "friends" | "nobody";
    };
  }>(
    "/profile",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      try {
        const {
          status,
          birthday,
          avatar_path,
          status_privacy,
          online_privacy,
          typing_privacy,
        } = request.body;

        // Валидация status (если предоставлен)
        if (status !== undefined && status !== null && status.length > 70) {
          return reply.code(400).send({
            success: false,
            error: "Status must be 70 characters or less",
          });
        }

        // Валидация birthday (если предоставлен)
        if (birthday !== undefined && birthday !== null) {
          const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
          if (!dateRegex.test(birthday)) {
            return reply.code(400).send({
              success: false,
              error: "Birthday must be in YYYY-MM-DD format",
            });
          }
        }

        // Валидация privacy settings
        const validPrivacyOptions = ["everyone", "chats", "friends", "nobody"];
        if (status_privacy && !validPrivacyOptions.includes(status_privacy)) {
          return reply.code(400).send({
            success: false,
            error: "Invalid status_privacy value",
          });
        }
        if (online_privacy && !validPrivacyOptions.includes(online_privacy)) {
          return reply.code(400).send({
            success: false,
            error: "Invalid online_privacy value",
          });
        }
        if (typing_privacy && !validPrivacyOptions.includes(typing_privacy)) {
          return reply.code(400).send({
            success: false,
            error: "Invalid typing_privacy value",
          });
        }

        // Обновляем профиль
        const updatedUser = await UserService.updateProfile(
          request.user!.username,
          {
            status,
            birthday,
            avatar_path,
            status_privacy,
            online_privacy,
            typing_privacy,
          },
        );

        return reply.code(200).send({
          success: true,
          data: {
            username: updatedUser.username,
            email: updatedUser.email,
            email_verified: updatedUser.email_verified,
            status: updatedUser.status,
            birthday: updatedUser.birthday,
            avatar_path: updatedUser.avatar_path,
            status_privacy: updatedUser.status_privacy,
            online_privacy: updatedUser.online_privacy,
            typing_privacy: updatedUser.typing_privacy,
          },
          message: "Profile updated successfully",
        });
      } catch (error) {
        console.error("❌ Error in /profile:", error);

        return reply.code(500).send({
          success: false,
          error: "Failed to update profile",
        });
      }
    },
  );
}
