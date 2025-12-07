import type { FastifyInstance } from "fastify";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { UserService } from "../services/user.service.js";
import { sanitizeSearchQuery } from "../utils/sanitize.js";
import type {
  SearchUsersQuery,
  SearchUsersResponse,
  ApiResponse,
} from "../types/api.types.js";

export async function usersRoutes(fastify: FastifyInstance) {
  /**
   * GET /search
   * Поиск пользователей по username
   */
  fastify.get<{
    Querystring: SearchUsersQuery;
    Reply: ApiResponse<SearchUsersResponse>;
  }>(
    "/search",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      let { q } = request.query;

      // Sanitize search query to prevent XSS and SQL injection
      q = sanitizeSearchQuery(q || "");

      // Валидация query
      if (!q || q.trim().length < 2) {
        return reply.code(400).send({
          success: false,
          error: "Query must be at least 2 characters",
        });
      }

      // Поиск пользователей
      const users = await UserService.searchUsers(q.trim());

      return reply.code(200).send({
        success: true,
        data: {
          users,
          count: users.length,
        },
      });
    },
  );
}
