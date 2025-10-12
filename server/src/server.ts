import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import rateLimit from '@fastify/rate-limit'
import { env } from './config/env.js'
import { authRoutes } from './routes/auth.routes.js'
import { protectedRoutes } from './routes/protected.routes.js'
import { usersRoutes } from './routes/users.routes.js'
import { errorHandler, notFoundHandler } from './middleware/error.middleware.js'

const fastify = Fastify({
  logger: {
    level: env.NODE_ENV === 'development' ? 'info' : 'warn',
  },
})

// Plugins
await fastify.register(cors, {
  origin: env.CORS_ORIGIN,
  credentials: true,
})

await fastify.register(helmet, {
  contentSecurityPolicy: false,
})

// Rate Limiting
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

// API Routes
await fastify.register(authRoutes, { prefix: '/api/auth' })
await fastify.register(protectedRoutes, { prefix: '/api' })
await fastify.register(usersRoutes, { prefix: '/api/users' })

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

// Start server
const start = async () => {
  try {
    await fastify.listen({ 
      port: env.PORT, 
      host: env.HOST,
    })
    
    console.log(`
🚀 CryptoX Server started!
    
📍 URL: http://localhost:${env.PORT}
🏥 Health: http://localhost:${env.PORT}/health
🔐 Auth: http://localhost:${env.PORT}/api/auth/register
🔍 Search: http://localhost:${env.PORT}/api/users/search?q=username
🛡️  Rate Limit: 100 requests per minute
🌍 Environment: ${env.NODE_ENV}
    `)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()