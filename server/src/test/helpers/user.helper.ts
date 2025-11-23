// User helper для тестов - упрощает создание пользователей и аутентификацию
import { FastifyInstance } from "fastify";

export interface TestUser {
  username: string;
  email: string;
  password: string;
  token?: string;
  userId?: number;
}

/**
 * Регистрация тестового пользователя
 */
export async function registerUser(
  app: FastifyInstance,
  userData: Partial<TestUser> = {},
): Promise<{ response: any; user: TestUser }> {
  const user: TestUser = {
    username: userData.username || `testuser_${Date.now()}`,
    email: userData.email || `test_${Date.now()}@example.com`,
    password: userData.password || "testPassword123",
  };

  // Генерируем публичный ключ (mock для тестов)
  const mockPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA${Buffer.from(user.username).toString("base64")}
-----END PUBLIC KEY-----`;

  const response = await app.inject({
    method: "POST",
    url: "/api/auth/register",
    payload: {
      username: user.username,
      email: user.email,
      password: user.password,
      public_key: mockPublicKey,
      deviceFingerprint: `test-device-${Date.now()}`,
    },
  });

  const body = JSON.parse(response.body);

  if (response.statusCode === 201) {
    // API returns { success, data: { token, user } }
    user.token = body.data?.token || body.token;
    user.userId = body.data?.user?.id || body.user?.id;
  }

  return { response, user };
}

/**
 * Логин пользователя
 */
export async function loginUser(
  app: FastifyInstance,
  username: string,
  password: string,
): Promise<{ response: any; token?: string }> {
  const response = await app.inject({
    method: "POST",
    url: "/api/auth/login",
    payload: { username, password },
  });

  const body = JSON.parse(response.body);
  // API returns { success, data: { token, user } }
  const token = body.data?.token || body.token || null;

  return { response, token };
}

/**
 * Создать и залогинить пользователя (shortcut)
 */
export async function createAuthenticatedUser(
  app: FastifyInstance,
  userData: Partial<TestUser> = {},
): Promise<TestUser> {
  const { user } = await registerUser(app, userData);

  if (!user.token) {
    throw new Error("Failed to authenticate user");
  }

  return user;
}

/**
 * Authenticated request helper
 */
export async function authenticatedRequest(
  app: FastifyInstance,
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
  url: string,
  token: string,
  payload?: any,
) {
  return app.inject({
    method,
    url,
    headers: {
      authorization: `Bearer ${token}`,
    },
    payload,
  });
}

/**
 * Создать несколько пользователей
 */
export async function createMultipleUsers(
  app: FastifyInstance,
  count: number,
): Promise<TestUser[]> {
  const users: TestUser[] = [];

  for (let i = 0; i < count; i++) {
    const { user } = await registerUser(app, {
      username: `testuser_${i}_${Date.now()}`,
      email: `test_${i}_${Date.now()}@example.com`,
    });
    users.push(user);
  }

  return users;
}
