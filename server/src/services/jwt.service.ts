import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { env } from "../config/env.js";

export interface JwtPayload {
  username: string;
  email: string;
  jti?: string; // JWT ID для уникальности
}

export class JwtService {
  /**
   * Генерация JWT токена
   */
  static generate(payload: JwtPayload): string {
    // Добавляем уникальный jti чтобы каждый токен был уникальным
    const payloadWithJti = {
      ...payload,
      jti: randomUUID(),
    };

    return jwt.sign(payloadWithJti, env.JWT_SECRET, {
      expiresIn: env.JWT_EXPIRES_IN,
    } as jwt.SignOptions);
  }

  /**
   * Проверка JWT токена
   */
  static verify(token: string): JwtPayload | null {
    try {
      const decoded = jwt.verify(token, env.JWT_SECRET) as JwtPayload;
      return decoded;
    } catch (error) {
      return null;
    }
  }

  /**
   * Декодирование без проверки (для debug)
   */
  static decode(token: string): JwtPayload | null {
    try {
      return jwt.decode(token) as JwtPayload;
    } catch (error) {
      return null;
    }
  }
}
