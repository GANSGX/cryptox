import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export interface JwtPayload {
  username: string;
  email: string;
}

export class JwtService {
  /**
   * Генерация JWT токена
   */
  static generate(payload: JwtPayload): string {
    return jwt.sign(payload, env.JWT_SECRET, {
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
