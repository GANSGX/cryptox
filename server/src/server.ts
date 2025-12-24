import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import multipart from "@fastify/multipart";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { env } from "./config/env.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import { authRoutes } from "./routes/auth.routes.js";
import { protectedRoutes } from "./routes/protected.routes.js";
import { usersRoutes } from "./routes/users.routes.js";
import { messagesRoutes } from "./routes/messages.routes.js";
import { sessionsRoutes } from "./routes/sessions.routes";
import { keysRoutes } from "./routes/keys.routes.js";
import { profilePhotosRoutes } from "./routes/profile-photos.routes.js";
import { mediaRoutes } from "./routes/media.routes.js";
import {
  errorHandler,
  notFoundHandler,
} from "./middleware/error.middleware.js";
import {
  enhancedErrorHandler,
  setupGlobalErrorHandlers,
} from "./middleware/error.middleware.enhanced.js";
import { securityMiddleware } from "./middleware/security.middleware.js";
import { validateContentType } from "./middleware/content-type.middleware.js";
import { log } from "./services/logger.service.js";
import { initializeSocketServer } from "./sockets/socket.server.js";

// Setup global error handlers (uncaught exceptions, unhandled rejections)
setupGlobalErrorHandlers();

const fastify = Fastify({
  logger: false,
  ignoreTrailingSlash: true,
  // Body parser limits (prevent DoS via large payloads)
  bodyLimit: 10485760, // 10MB max body size (для файлов)
  // Request timeout (prevent slowloris attacks)
  connectionTimeout: 30000, // 30 seconds
  keepAliveTimeout: 5000, // 5 seconds
  // Disable powered-by header (information disclosure)
  disableRequestLogging: false,
  // Trust proxy (for correct IP behind reverse proxy)
  trustProxy: true,
});

// Multipart для загрузки файлов
await fastify.register(multipart, {
  limits: {
    fileSize: 5242880, // 5MB max file size
    files: 1, // только 1 файл за раз
  },
});

// Static files для раздачи аватарок
await fastify.register(fastifyStatic, {
  root: join(__dirname, "..", "uploads"),
  prefix: "/uploads/",
  constraints: {},
  decorateReply: false,
  setHeaders: (res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  },
});

// Plugins
await fastify.register(cors, {
  origin: (origin, cb) => {
    if (!origin) {
      cb(null, true);
      return;
    }

    if (
      origin.includes("localhost") ||
      origin.includes("127.0.0.1") ||
      origin.includes("file://")
    ) {
      cb(null, true);
      return;
    }

    if (origin === env.CORS_ORIGIN) {
      cb(null, true);
      return;
    }

    cb(new Error("Not allowed by CORS"), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
});

await fastify.register(helmet, {
  // Content Security Policy (XSS protection)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "http://localhost:3001"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // Strict Transport Security (HTTPS enforcement)
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  // X-Frame-Options (clickjacking protection)
  frameguard: {
    action: "deny",
  },
  // X-Content-Type-Options (MIME sniffing protection)
  noSniff: true,
  // X-XSS-Protection
  xssFilter: true,
  // Referrer Policy
  referrerPolicy: {
    policy: "no-referrer",
  },
  // Remove X-Powered-By header
  hidePoweredBy: true,
  // Cross-Origin policies
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: false, // Отключаем для статики
});

// Rate limiting - отключен в тестах (иначе тесты падают из-за кэша в памяти)
if (env.NODE_ENV !== "test") {
  await fastify.register(rateLimit, {
    max: 100,
    timeWindow: "1 minute",
    cache: 10000,
    allowList: ["127.0.0.1"],
    redis: undefined,
    skipOnError: true,
    errorResponseBuilder: (request, context) => {
      return {
        success: false,
        error: "Too many requests. Please try again later.",
        retryAfter: context.after,
      };
    },
  });
}

// Block access to sensitive files and directories (Information Disclosure prevention)
fastify.addHook("onRequest", async (request, reply) => {
  const path = request.url.toLowerCase();

  // Block .env files
  if (path.includes("/.env")) {
    return reply.code(404).send({ error: "Not Found" });
  }

  // Block .git directory
  if (path.includes("/.git")) {
    return reply.code(404).send({ error: "Not Found" });
  }

  // Block package.json
  if (path.includes("/package.json")) {
    return reply.code(404).send({ error: "Not Found" });
  }

  // Block backup files
  if (path.match(/\.(bak|backup|old|tmp|swp|sql|zip|tar\.gz|tgz)$/)) {
    return reply.code(404).send({ error: "Not Found" });
  }

  // Block debug/admin endpoints in production
  if (env.NODE_ENV === "production") {
    if (
      path.startsWith("/debug") ||
      path.startsWith("/console") ||
      path.startsWith("/admin") ||
      path.startsWith("/server-status") ||
      path.startsWith("/phpinfo")
    ) {
      return reply.code(404).send({ error: "Not Found" });
    }
  }
});

// Security middleware (XSS, SQL injection, command injection, etc.)
// Skip for /api/auth/* routes - they have strict Zod validation + manual sanitization
// Skip for /uploads/* routes - they are static files served by fastifyStatic
fastify.addHook("preHandler", async (request, reply) => {
  // Auth routes already have:
  // 1. Zod schema validation (very strict)
  // 2. Manual sanitization in handlers (sanitizeUsername, sanitizeEmail)
  // 3. Database constraints
  // Double sanitization breaks username matching
  if (request.url.startsWith("/api/auth")) {
    return;
  }

  // Skip static files - they are served by fastifyStatic plugin
  if (request.url.startsWith("/uploads/")) {
    return;
  }

  return securityMiddleware(request, reply);
});

// Content-Type validation (prevent Content-Type confusion attacks)
fastify.addHook("preHandler", validateContentType);

// HTTP Request logging (DO NOT log sensitive data!)
fastify.addHook("onRequest", async (request, reply) => {
  // DO NOT log: passwords, tokens, cookies, authorization headers
  const sanitizedHeaders = { ...request.headers };
  delete sanitizedHeaders.authorization;
  delete sanitizedHeaders.cookie;

  log.http(`${request.method} ${request.url}`, {
    ip: request.ip,
    userAgent: request.headers["user-agent"],
    // Do NOT log full headers (may contain tokens)
  });
});

// Remove version disclosure headers (security)
fastify.addHook("onSend", async (request, reply, payload) => {
  // Remove server version headers
  reply.removeHeader("Server");
  reply.removeHeader("X-Powered-By");
  reply.removeHeader("X-Fastify-Version");

  return payload;
});

fastify.addHook("onResponse", async (request, reply) => {
  log.http(`${request.method} ${request.url} - ${reply.statusCode}`, {
    responseTime: reply.elapsedTime,
  });
});

// API Routes
await fastify.register(authRoutes, { prefix: "/api/auth" });
await fastify.register(protectedRoutes, { prefix: "/api" });
await fastify.register(usersRoutes, { prefix: "/api/users" });
await fastify.register(messagesRoutes, { prefix: "/api" });
await fastify.register(sessionsRoutes, { prefix: "/api" });
await fastify.register(keysRoutes, { prefix: "/api" });
await fastify.register(profilePhotosRoutes, { prefix: "/api" });
await fastify.register(mediaRoutes, { prefix: "/api" });

// Error handlers (enhanced - no information disclosure)
fastify.setErrorHandler(enhancedErrorHandler);
fastify.setNotFoundHandler(notFoundHandler);

// Health check route (no sensitive information!)
fastify.get("/health", async () => {
  return {
    status: "ok",
    timestamp: new Date().toISOString(),
    // DO NOT expose: environment, version, database status, etc.
  };
});

// Root route
fastify.get("/", async () => {
  return {
    name: "CryptoX API",
    version: "0.1.0",
    docs: "/docs",
  };
});

// Расширяем Fastify для добавления io
declare module "fastify" {
  interface FastifyInstance {
    io: ReturnType<typeof initializeSocketServer>;
  }
}

// Start server
const start = async () => {
  try {
    fastify.decorate("io", null as any);

    await fastify.listen({
      port: env.PORT,
      host: env.HOST,
    });

    const io = initializeSocketServer(fastify.server);

    fastify.io = io;

    log.info("🚀 CryptoX Server started!", {
      url: `http://localhost:${env.PORT}`,
      health: `http://localhost:${env.PORT}/health`,
      auth: `http://localhost:${env.PORT}/api/auth/register`,
      search: `http://localhost:${env.PORT}/api/users/search?q=username`,
      messages: `http://localhost:${env.PORT}/api/messages`,
      sessions: `http://localhost:${env.PORT}/api/sessions`,
      rateLimit: "100 requests per minute",
      socketio: "enabled",
      environment: env.NODE_ENV,
    });

    console.log(`
🚀 CryptoX Server started!
    
📍 URL: http://localhost:${env.PORT}
🏥 Health: http://localhost:${env.PORT}/health
🔐 Auth: http://localhost:${env.PORT}/api/auth/register
🔍 Search: http://localhost:${env.PORT}/api/users/search?q=username
💬 Messages: http://localhost:${env.PORT}/api/messages
🔒 Sessions: http://localhost:${env.PORT}/api/sessions
🛡️  Rate Limit: 100 requests per minute
🔌 Socket.io: Enabled
🌍 Environment: ${env.NODE_ENV}
    `);
  } catch (err) {
    log.error("Failed to start server", err);
    process.exit(1);
  }
};

start();
