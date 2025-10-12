import Fastify from 'fastify'
import cors from '@fastify/cors'
import helmet from '@fastify/helmet'
import { env } from './config/env.js'
import { authRoutes } from './routes/auth.routes.js'
import { protectedRoutes } from './routes/protected.routes.js'
import { usersRoutes } from './routes/users.routes.js'

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

// API Routes
await fastify.register(authRoutes, { prefix: '/api/auth' })
await fastify.register(protectedRoutes, { prefix: '/api' })
await fastify.register(usersRoutes, { prefix: '/api/users' })

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
🌍 Environment: ${env.NODE_ENV}
    `)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()