import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { env } from "./config/env.js";
import { authRoutes } from "./routes/auth.routes.js";
import { protectedRoutes } from "./routes/protected.routes.js";
import { usersRoutes } from "./routes/users.routes.js";
import { messagesRoutes } from "./routes/messages.routes.js";
import { sessionsRoutes } from "./routes/sessions.routes";
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
  bodyLimit: 1048576, // 1MB max body size
  // Request timeout (prevent slowloris attacks)
  connectionTimeout: 30000, // 30 seconds
  keepAliveTimeout: 5000, // 5 seconds
  // Disable powered-by header (information disclosure)
  disableRequestLogging: false,
  // Trust proxy (for correct IP behind reverse proxy)
  trustProxy: true,
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
      imgSrc: ["'self'", "data:", "https:"],
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
  crossOriginResourcePolicy: { policy: "same-origin" },
});

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
fastify.addHook("preHandler", async (request, reply) => {
  // Auth routes already have:
  // 1. Zod schema validation (very strict)
  // 2. Manual sanitization in handlers (sanitizeUsername, sanitizeEmail)
  // 3. Database constraints
  // Double sanitization breaks username matching
  if (request.url.startsWith("/api/auth")) {
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
