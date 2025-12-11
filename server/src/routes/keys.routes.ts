/**
 * 🔑 SIGNAL PROTOCOL KEY MANAGEMENT ROUTES
 *
 * Эндпоинты для обмена публичными ключами Signal Protocol:
 * - Загрузка PreKey bundle (при регистрации/генерации новых ключей)
 * - Получение PreKey bundle другого пользователя (для установки сессии)
 * - Удаление использованного one-time prekey
 */

import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { pool } from "../db/pool.js";
import { authMiddleware } from "../middleware/auth.middleware.js";

export async function keysRoutes(fastify: FastifyInstance) {
  /**
   * POST /api/keys/prekey-bundle
   * Загрузка PreKey bundle на сервер (при регистрации или ротации ключей)
   */
  fastify.post(
    "/api/keys/prekey-bundle",
    { preHandler: [authMiddleware] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { username } = request.user as { username: string };
      const body = request.body as {
        registrationId: number;
        identityKey: string;
        signedPreKey: {
          keyId: number;
          publicKey: string;
          signature: string;
        };
        preKeys: Array<{
          keyId: number;
          publicKey: string;
        }>;
      };

      const { registrationId, identityKey, signedPreKey, preKeys } = body;

      try {
        // Сохраняем identity key и signed prekey
        await pool.query(
          `INSERT INTO signal_identity_keys (username, registration_id, identity_key, signed_prekey_id, signed_prekey_public, signed_prekey_signature)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (username)
           DO UPDATE SET
             registration_id = EXCLUDED.registration_id,
             identity_key = EXCLUDED.identity_key,
             signed_prekey_id = EXCLUDED.signed_prekey_id,
             signed_prekey_public = EXCLUDED.signed_prekey_public,
             signed_prekey_signature = EXCLUDED.signed_prekey_signature,
             updated_at = NOW()`,
          [
            username,
            registrationId,
            identityKey,
            signedPreKey.keyId,
            signedPreKey.publicKey,
            signedPreKey.signature,
          ],
        );

        // Удаляем старые one-time prekeys
        await pool.query("DELETE FROM signal_prekeys WHERE username = $1", [
          username,
        ]);

        // Сохраняем новые one-time prekeys
        for (const preKey of preKeys) {
          await pool.query(
            `INSERT INTO signal_prekeys (username, key_id, public_key)
             VALUES ($1, $2, $3)`,
            [username, preKey.keyId, preKey.publicKey],
          );
        }

        return reply.code(201).send({
          success: true,
          message: "PreKey bundle uploaded successfully",
        });
      } catch (error: unknown) {
        fastify.log.error({ error }, "Error uploading PreKey bundle");
        return reply.code(500).send({
          success: false,
          error: "Failed to upload PreKey bundle",
        });
      }
    },
  );

  /**
   * GET /api/keys/prekey-bundle/:username
   * Получение PreKey bundle другого пользователя (для установки сессии)
   */
  fastify.get(
    "/api/keys/prekey-bundle/:username",
    { preHandler: [authMiddleware] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { username } = request.params as { username: string };

      try {
        // Получаем identity key и signed prekey
        const identityResult = await pool.query(
          `SELECT registration_id, identity_key, signed_prekey_id, signed_prekey_public, signed_prekey_signature
           FROM signal_identity_keys
           WHERE username = $1`,
          [username],
        );

        if (identityResult.rowCount === 0) {
          return reply.code(404).send({
            success: false,
            error: "User not found or no keys available",
          });
        }

        const identityRow = identityResult.rows[0];

        // Получаем один one-time prekey (если есть)
        const preKeyResult = await pool.query(
          `SELECT key_id, public_key
           FROM signal_prekeys
           WHERE username = $1
           LIMIT 1`,
          [username],
        );

        let preKey = null;
        if (preKeyResult.rowCount && preKeyResult.rowCount > 0) {
          const preKeyRow = preKeyResult.rows[0];
          preKey = {
            keyId: preKeyRow.key_id,
            publicKey: preKeyRow.public_key,
          };

          // Удаляем использованный one-time prekey
          await pool.query(
            "DELETE FROM signal_prekeys WHERE username = $1 AND key_id = $2",
            [username, preKeyRow.key_id],
          );
        }

        return reply.send({
          success: true,
          data: {
            registrationId: identityRow.registration_id,
            identityKey: identityRow.identity_key,
            signedPreKey: {
              keyId: identityRow.signed_prekey_id,
              publicKey: identityRow.signed_prekey_public,
              signature: identityRow.signed_prekey_signature,
            },
            preKey,
          },
        });
      } catch (error: unknown) {
        fastify.log.error({ error }, "Error fetching PreKey bundle");
        return reply.code(500).send({
          success: false,
          error: "Failed to fetch PreKey bundle",
        });
      }
    },
  );

  /**
   * GET /api/keys/prekey-count
   * Получение количества оставшихся one-time prekeys (для мониторинга)
   */
  fastify.get(
    "/api/keys/prekey-count",
    { preHandler: [authMiddleware] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { username } = request.user as { username: string };

      try {
        const result = await pool.query(
          "SELECT COUNT(*) as count FROM signal_prekeys WHERE username = $1",
          [username],
        );

        return reply.send({
          success: true,
          data: {
            count: parseInt(result.rows[0].count),
          },
        });
      } catch (error: unknown) {
        fastify.log.error({ error }, "Error fetching prekey count");
        return reply.code(500).send({
          success: false,
          error: "Failed to fetch prekey count",
        });
      }
    },
  );
}
