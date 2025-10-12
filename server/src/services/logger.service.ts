import winston from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'
import { env } from '../config/env.js'

// Формат логов
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
)

// Формат для консоли (более читаемый)
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`
    }
    return msg
  })
)

// Транспорты (куда пишем логи)
const transports: winston.transport[] = [
  // Консоль (development)
  new winston.transports.Console({
    format: env.NODE_ENV === 'development' ? consoleFormat : logFormat,
    level: env.NODE_ENV === 'development' ? 'debug' : 'info',
  }),
]

// Файлы логов (только если не в production или явно включено)
if (env.NODE_ENV === 'production' || process.env.ENABLE_FILE_LOGS === 'true') {
  // Все логи
  transports.push(
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d', // Хранить 30 дней
      maxSize: '20m', // Максимальный размер файла
      format: logFormat,
      level: 'info',
    })
  )

  // Только ошибки
  transports.push(
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d',
      maxSize: '20m',
      format: logFormat,
      level: 'error',
    })
  )
}

// Создаём logger
export const logger = winston.createLogger({
  level: env.NODE_ENV === 'development' ? 'debug' : 'info',
  format: logFormat,
  transports,
  exitOnError: false,
})

// Логирование необработанных ошибок
process.on('unhandledRejection', (reason: any) => {
  logger.error('Unhandled Rejection:', reason)
})

process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception:', error)
  process.exit(1)
})

// Экспорт удобных методов
export const log = {
  info: (message: string, meta?: any) => logger.info(message, meta),
  error: (message: string, meta?: any) => logger.error(message, meta),
  warn: (message: string, meta?: any) => logger.warn(message, meta),
  debug: (message: string, meta?: any) => logger.debug(message, meta),
  http: (message: string, meta?: any) => logger.http(message, meta),
}