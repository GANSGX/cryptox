# ⚡ QUICK START

Быстрый старт для разработки CryptoX.

## 🎯 Одна команда запускает всё!

```bash
pnpm dev:all
```

**Это запустит:**
- ✅ PostgreSQL (Docker)
- ✅ Redis (Docker)
- ✅ Server с hot reload (localhost:3001)
- ✅ Client с HMR (localhost:5173)

**Изменения в коде применяются автоматически без перезапуска!**

---

## 📦 Первый раз?

### 1. Установить зависимости

```bash
pnpm install
```

### 2. Проверить .env файлы

Убедись что есть:
- `server/.env` (скопируй из `server/.env.example`)
- `client/.env` (скопируй из `client/.env.example`)

### 3. Запустить БД миграции

```bash
cd server
pnpm migrate
cd ..
```

### 4. Запустить проект

```bash
pnpm dev:all
```

---

## 🚀 Ежедневная работа

### Запуск разработки

```bash
pnpm dev:all
```

Откроется:
- **Client:** http://localhost:5173
- **Server API:** http://localhost:3001
- **Health check:** http://localhost:3001/health

### Работа с задачами

```bash
# 1. Переключиться на develop
git checkout develop
git pull origin develop

# 2. Создать feature ветку
git checkout -b feature/my-task

# 3. Работать (hot reload работает!)
# ... делаешь изменения ...

# 4. Коммит
git add .
git commit -m "feat: описание"

# 5. Push
git push origin feature/my-task

# 6. Создать PR на GitHub
```

---

## 🧪 Тестирование

```bash
# Все тесты
pnpm test

# Watch mode
pnpm test:watch

# С coverage
pnpm test:coverage
```

---

## 🐛 Решение проблем

### Порты заняты?

```bash
# Остановить Docker
pnpm docker:down

# Найти процесс на порту
lsof -i :3001  # или :5173

# Убить процесс
kill -9 <PID>
```

### Hot reload не работает?

```bash
# Перезапустить всё
Ctrl+C  # остановить pnpm dev:all
pnpm docker:down
pnpm dev:all
```

### Ошибки с БД?

```bash
# Проверить Docker
docker ps

# Перезапустить PostgreSQL
docker-compose restart postgres

# Пересоздать БД (⚠️ удалит данные!)
pnpm docker:clean
pnpm docker:up
cd server && pnpm migrate && cd ..
```

---

## 📝 Полезные команды

```bash
# === РАЗРАБОТКА ===
pnpm dev:all              # Запустить всё
pnpm dev:server           # Только server
pnpm dev:client           # Только client

# === DOCKER ===
pnpm docker:up            # Запустить БД
pnpm docker:down          # Остановить БД
pnpm docker:logs          # Посмотреть логи
pnpm docker:clean         # Очистить volumes (⚠️)

# === ТЕСТЫ ===
pnpm test                 # Все тесты
pnpm test:watch           # Watch mode
pnpm test:coverage        # С coverage

# === ЛИНТИНГ ===
pnpm lint                 # ESLint
pnpm type-check           # TypeScript

# === BUILD ===
pnpm build                # Production build
```

---

## 🎓 Дальше

- [📚 Development Guide](./DEVELOPMENT.md) - Полный гайд
- [🌳 Git Workflow](./GIT-WORKFLOW.md) - Работа с Git
- [🧪 Testing Guide](./TESTING.md) - Стратегия тестов

---

**Last updated:** 2025-11-20
