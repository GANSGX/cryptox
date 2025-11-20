# 💻 DEVELOPMENT GUIDE

## 🚀 БЫСТРЫЙ СТАРТ

### Первый запуск проекта

```bash
# 1. Клонировать репозиторий
git clone <repo-url>
cd cryptox

# 2. Установить зависимости
pnpm install

# 3. Запустить Docker контейнеры (PostgreSQL, Redis)
docker-compose up -d

# 4. Запустить development режим
pnpm dev:all

# Готово! 🎉
# Client: http://localhost:5173
# Server: http://localhost:3000
```

---

## 📁 СТРУКТУРА ПРОЕКТА

```
cryptox/
├── client/                 # Frontend (React + Vite)
│   ├── src/
│   │   ├── components/    # React компоненты
│   │   ├── pages/         # Страницы
│   │   ├── store/         # Zustand stores
│   │   ├── services/      # API clients, WebSocket
│   │   ├── utils/         # Утилиты
│   │   └── types/         # TypeScript типы
│   └── tests/             # Тесты
│
├── server/                # Backend (Fastify + Socket.io)
│   ├── src/
│   │   ├── routes/        # API endpoints
│   │   ├── services/      # Бизнес-логика
│   │   ├── db/            # Database
│   │   ├── sockets/       # WebSocket handlers
│   │   ├── middleware/    # Middleware
│   │   └── types/         # TypeScript типы
│   └── tests/             # Тесты
│
├── tests/                 # E2E тесты (Playwright)
├── docs/                  # Документация
├── scripts/               # Вспомогательные скрипты
└── docker-compose.yml     # Docker конфигурация
```

---

## 🛠️ РАЗРАБОТКА

### Hot Reload (автоперезагрузка)

После настройки Docker, всё работает автоматически:

```bash
pnpm dev:all
```

**Что происходит:**
1. PostgreSQL и Redis запускаются в Docker
2. Server запускается с `tsx watch` (мгновенная перезагрузка при изменениях)
3. Client запускается с Vite (HMR - изменения без перезагрузки страницы)

**Изменяешь код → Видишь результат мгновенно! 🚀**

### Работа с задачами

1. **Выбери задачу** из GitHub Projects Board
2. **Создай feature ветку:**
   ```bash
   git checkout develop
   git checkout -b feature/task-name
   ```

3. **Пиши код + тесты:**
   ```bash
   # Тесты в watch mode
   pnpm test:watch
   ```

4. **Проверь перед коммитом:**
   ```bash
   pnpm lint          # ESLint
   pnpm type-check    # TypeScript
   pnpm test          # Все тесты
   ```

5. **Коммит** (автопроверки запустятся):
   ```bash
   git add .
   git commit -m "feat: описание"
   ```

6. **Push и создай PR:**
   ```bash
   git push origin feature/task-name
   ```

### Команды для разработки

```bash
# === CLIENT ===
cd client
pnpm dev              # Запуск dev сервера
pnpm build            # Production build
pnpm preview          # Просмотр production build
pnpm lint             # ESLint проверка
pnpm type-check       # TypeScript проверка

# === SERVER ===
cd server
pnpm dev              # Запуск с hot reload
pnpm build            # Production build
pnpm start            # Запуск production
pnpm migrate          # Запуск миграций БД

# === ТЕСТЫ ===
pnpm test             # Все тесты
pnpm test:watch       # Watch mode
pnpm test:coverage    # С coverage
pnpm test:e2e         # E2E тесты

# === ВСЁ ВМЕСТЕ ===
pnpm dev:all          # Запуск всего проекта
pnpm test:all         # Все тесты (unit + integration + e2e)
```

---

## 🐳 DOCKER

### Основные команды

```bash
# Запустить контейнеры
docker-compose up -d

# Остановить
docker-compose down

# Посмотреть логи
docker-compose logs -f postgres
docker-compose logs -f redis

# Перезапустить
docker-compose restart

# Очистить всё (⚠️ удалит данные!)
docker-compose down -v
```

### Подключение к PostgreSQL

```bash
# Через Docker
docker exec -it cryptox_postgres psql -U cryptox_user -d cryptox

# Или через psql локально
psql -h localhost -U cryptox_user -d cryptox
```

### Подключение к Redis

```bash
# Через Docker
docker exec -it cryptox_redis redis-cli

# Команды Redis
PING          # Проверка
KEYS *        # Все ключи
GET key       # Получить значение
```

---

## 💾 БАЗА ДАННЫХ

### Миграции

```bash
cd server
pnpm migrate
```

### Схема БД

```sql
-- Users
CREATE TABLE users (
  username VARCHAR(30) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  email_verified BOOLEAN DEFAULT false,
  auth_token VARCHAR(64) NOT NULL,
  salt VARCHAR(64) NOT NULL,
  encrypted_master_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Messages
CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  sender_id VARCHAR(30) REFERENCES users(username),
  recipient_id VARCHAR(30) REFERENCES users(username),
  encrypted_content TEXT NOT NULL,
  sent_at TIMESTAMP DEFAULT NOW()
);

-- И другие таблицы...
```

### Backup и Restore

```bash
# Backup
docker exec cryptox_postgres pg_dump -U cryptox_user cryptox > backup.sql

# Restore
docker exec -i cryptox_postgres psql -U cryptox_user cryptox < backup.sql
```

---

## 🔐 ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ

### Server (.env)

```bash
# server/.env
NODE_ENV=development
PORT=3000

# Database
DATABASE_URL=postgresql://cryptox_user:cryptox_password_dev@localhost:5432/cryptox

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET=your-jwt-secret-here-min-32-chars

# Email (Resend)
RESEND_API_KEY=re_xxxxxxxxxxxxx

# Security
SERVER_PEPPER=your-server-pepper-here-min-32-bytes-hex
```

### Client (.env)

```bash
# client/.env
VITE_API_URL=http://localhost:3000
VITE_WS_URL=ws://localhost:3000
```

⚠️ **ВАЖНО:** `.env` файлы НЕ должны попадать в Git!

---

## 🧪 ТЕСТИРОВАНИЕ

См. подробный гайд: [TESTING.md](./TESTING.md)

### Быстрый запуск

```bash
# Watch mode (для разработки)
pnpm test:watch

# Один раз
pnpm test

# С coverage
pnpm test:coverage
```

### Структура тестов

```
tests/
├── unit/              # Модульные тесты
├── integration/       # Интеграционные тесты
└── e2e/              # End-to-End тесты
```

---

## 🎨 CODE STYLE

### ESLint

```bash
# Проверка
pnpm lint

# Автоисправление
pnpm lint --fix
```

### Prettier (встроен в ESLint)

Форматирование применяется автоматически при коммите.

### TypeScript

```bash
# Проверка типов
pnpm type-check

# В watch mode
pnpm type-check --watch
```

### Naming Conventions

```typescript
// Файлы
MyComponent.tsx          // React компоненты
auth.service.ts          // Сервисы
user.types.ts            // Типы
crypto.utils.ts          // Утилиты

// Переменные
const userName = 'Alice'          // camelCase
const MAX_RETRIES = 5             // SCREAMING_SNAKE_CASE для констант
type UserData = { ... }           // PascalCase для типов
interface IUserService { ... }    // PascalCase + I prefix для интерфейсов

// Функции
function getUserData() { ... }              // camelCase
async function fetchUserProfile() { ... }   // async функции тоже camelCase

// React
function UserProfile() { ... }              // PascalCase для компонентов
const useAuth = () => { ... }               // camelCase + use prefix для hooks
```

---

## 📦 ЗАВИСИМОСТИ

### Добавление новой зависимости

```bash
# Production зависимость
pnpm add package-name

# Dev зависимость
pnpm add -D package-name

# Обновление всех зависимостей
pnpm update
```

### Основные зависимости

**Client:**
- `react` - UI library
- `zustand` - State management
- `socket.io-client` - WebSocket
- `react-router-dom` - Routing

**Server:**
- `fastify` - Web framework
- `socket.io` - WebSocket
- `pg` - PostgreSQL client
- `ioredis` - Redis client
- `argon2` - Password hashing

---

## 🐛 DEBUGGING

### VS Code Launch Configuration

```json
// .vscode/launch.json
{
  "configurations": [
    {
      "name": "Debug Server",
      "type": "node",
      "request": "launch",
      "runtimeExecutable": "pnpm",
      "runtimeArgs": ["--prefix", "server", "dev"],
      "console": "integratedTerminal"
    },
    {
      "name": "Debug Client",
      "type": "chrome",
      "request": "launch",
      "url": "http://localhost:5173",
      "webRoot": "${workspaceFolder}/client/src"
    }
  ]
}
```

### Логирование

```typescript
// Server
import { logger } from '@/services/logger.service'

logger.info('User registered', { username })
logger.error('Auth failed', { error })
logger.warn('Rate limit exceeded', { ip })

// Client
console.log('[INFO]', 'Message sent')
console.error('[ERROR]', 'Connection failed')
```

### Chrome DevTools

- React DevTools
- Redux DevTools (для Zustand)
- Network tab (для API requests)
- WebSocket frames (для Socket.io)

---

## 🚀 PRODUCTION BUILD

### Client

```bash
cd client
pnpm build

# Результат в client/dist/
# Деплоится на Vercel, Netlify, etc.
```

### Server

```bash
cd server
pnpm build

# Результат в server/dist/
# Запуск production:
NODE_ENV=production node dist/server.js
```

### Docker Production

```bash
# Build
docker build -t cryptox-server ./server
docker build -t cryptox-client ./client

# Run
docker-compose -f docker-compose.prod.yml up -d
```

---

## 📊 МОНИТОРИНГ

### Логи

```bash
# Server логи
tail -f server/logs/combined.log
tail -f server/logs/error.log

# Docker логи
docker-compose logs -f
```

### Метрики

- Response time
- Error rate
- Active connections
- Database queries

---

## ❓ FAQ

### Порты заняты?

```bash
# Найти процесс на порту
lsof -i :3000
lsof -i :5173

# Убить процесс
kill -9 <PID>
```

### Hot reload не работает?

```bash
# Перезапустить Docker
docker-compose restart

# Очистить кэш
rm -rf node_modules
pnpm install
```

### Тесты падают?

```bash
# Проверить Docker контейнеры
docker-compose ps

# Очистить test БД
pnpm test:clean
```

### TypeScript ошибки?

```bash
# Перезапустить TypeScript server в VS Code
# Cmd+Shift+P → "TypeScript: Restart TS Server"

# Или переустановить зависимости
rm -rf node_modules
pnpm install
```

---

## 🔗 ПОЛЕЗНЫЕ ССЫЛКИ

- [Git Workflow](./GIT-WORKFLOW.md)
- [Testing Guide](./TESTING.md)
- [Architecture](./ARCHITECTURE.md)
- [API Documentation](./API.md)

---

**Последнее обновление:** 2025-11-20
