import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import rateLimit from '@fastify/rate-limit'
import { env } from './config/env.js'
import { authRoutes } from './routes/auth.routes.js'
import { protectedRoutes } from './routes/protected.routes.js'
import { usersRoutes } from './routes/users.routes.js'
import { messagesRoutes } from './routes/messages.routes.js'
import { sessionsRoutes } from './routes/sessions.routes'
import { errorHandler, notFoundHandler } from './middleware/error.middleware.js'
import { log } from './services/logger.service.js'
import { initializeSocketServer } from './sockets/socket.server.js'

const fastify = Fastify({
  logger: false,
  ignoreTrailingSlash: true,
})

// Plugins
await fastify.register(cors, {
  origin: (origin, cb) => {
    if (!origin) {
      cb(null, true)
      return
    }
    
    if (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.includes('file://')) {
      cb(null, true)
      return
    }
    
    if (origin === env.CORS_ORIGIN) {
      cb(null, true)
      return
    }
    
    cb(new Error('Not allowed by CORS'), false)
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
})

await fastify.register(helmet, {
  contentSecurityPolicy: false,
})

await fastify.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  cache: 10000,
  allowList: ['127.0.0.1'],
  redis: undefined,
  skipOnError: true,
  errorResponseBuilder: (request, context) => {
    return {
      success: false,
      error: 'Too many requests. Please try again later.',
      retryAfter: context.after,
    }
  },
})

// HTTP Request logging
fastify.addHook('onRequest', async (request, reply) => {
  log.http(`${request.method} ${request.url}`, {
    ip: request.ip,
    userAgent: request.headers['user-agent'],
  })
})

fastify.addHook('onResponse', async (request, reply) => {
  log.http(`${request.method} ${request.url} - ${reply.statusCode}`, {
    responseTime: reply.elapsedTime,
  })
})

// API Routes
await fastify.register(authRoutes, { prefix: '/api/auth' })
await fastify.register(protectedRoutes, { prefix: '/api' })
await fastify.register(usersRoutes, { prefix: '/api/users' })
await fastify.register(messagesRoutes, { prefix: '/api' })
await fastify.register(sessionsRoutes, { prefix: '/api' })

// Error handlers
fastify.setErrorHandler(errorHandler)
fastify.setNotFoundHandler(notFoundHandler)

// Health check route
fastify.get('/health', async () => {
  return { 
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: env.NODE_ENV,
  }
})

// Root route
fastify.get('/', async () => {
  return { 
    name: 'CryptoX API',
    version: '0.1.0',
    docs: '/docs',
  }
})

// Расширяем Fastify для добавления io
declare module 'fastify' {
  interface FastifyInstance {
    io: ReturnType<typeof initializeSocketServer>
  }
}

// Start server
const start = async () => {
  try {
    fastify.decorate('io', null as any)

    await fastify.listen({ 
      port: env.PORT, 
      host: env.HOST,
    })

    const io = initializeSocketServer(fastify.server)
    
    fastify.io = io
    
    log.info('🚀 CryptoX Server started!', {
      url: `http://localhost:${env.PORT}`,
      health: `http://localhost:${env.PORT}/health`,
      auth: `http://localhost:${env.PORT}/api/auth/register`,
      search: `http://localhost:${env.PORT}/api/users/search?q=username`,
      messages: `http://localhost:${env.PORT}/api/messages`,
      sessions: `http://localhost:${env.PORT}/api/sessions`,
      rateLimit: '100 requests per minute',
      socketio: 'enabled',
      environment: env.NODE_ENV,
    })
    
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
    `)
  } catch (err) {
    log.error('Failed to start server', err)
    process.exit(1)
  }
}

start()