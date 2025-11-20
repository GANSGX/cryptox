# 🧪 TESTING GUIDE

## 📋 СОДЕРЖАНИЕ

1. [Стратегия тестирования](#стратегия-тестирования)
2. [Типы тестов](#типы-тестов)
3. [Настройка и запуск](#настройка-и-запуск)
4. [Написание тестов](#написание-тестов)
5. [Best Practices](#best-practices)
6. [Coverage](#coverage)

---

## 🎯 СТРАТЕГИЯ ТЕСТИРОВАНИЯ

### Пирамида тестов

```
         /\
        /  \       E2E Tests (5%)
       /----\      Проверяют полные сценарии
      /      \
     /--------\    Integration Tests (25%)
    /          \   Проверяют взаимодействие модулей
   /------------\
  /              \ Unit Tests (70%)
 /----------------\ Проверяют отдельные функции
```

### Целевые метрики

- **Unit Tests:** 70%+ функций покрыты
- **Integration Tests:** Все API endpoints
- **E2E Tests:** Критичные пользовательские сценарии
- **Overall Coverage:** 70%+ code coverage
- **Test Speed:** < 30 секунд для unit тестов

---

## 🔬 ТИПЫ ТЕСТОВ

### 1. Unit Tests (Модульные тесты)

**Что тестируем:**
- Отдельные функции
- Утилиты
- React hooks
- Валидаторы
- Crypto функции

**Инструменты:**
- `Vitest` (быстрее Jest, ESM support)
- `@testing-library/react` (для React компонентов)

**Пример структуры:**
```
server/tests/unit/
├── crypto/
│   ├── argon2.test.ts
│   └── encryption.test.ts
├── validators/
│   └── auth.validator.test.ts
└── utils/
    └── jwt.test.ts

client/tests/unit/
├── hooks/
│   ├── useAuth.test.ts
│   └── useSocket.test.ts
└── utils/
    └── crypto.test.ts
```

**Пример теста:**
```typescript
// server/tests/unit/crypto/encryption.test.ts
import { describe, it, expect } from 'vitest'
import { encrypt, decrypt } from '@/utils/crypto'

describe('Encryption', () => {
  it('should encrypt and decrypt data correctly', () => {
    const data = 'secret message'
    const key = 'encryption-key-32-bytes-long!!'

    const encrypted = encrypt(data, key)
    expect(encrypted).not.toBe(data)

    const decrypted = decrypt(encrypted, key)
    expect(decrypted).toBe(data)
  })

  it('should throw error on invalid key', () => {
    expect(() => encrypt('data', 'short')).toThrow()
  })
})
```

### 2. Integration Tests (Интеграционные тесты)

**Что тестируем:**
- API endpoints
- Database операции
- WebSocket события
- Взаимодействие сервисов

**Инструменты:**
- `Vitest`
- `Supertest` (HTTP requests)
- `testcontainers` (Docker для БД в тестах)

**Пример структуры:**
```
server/tests/integration/
├── api/
│   ├── auth.test.ts
│   ├── messages.test.ts
│   └── users.test.ts
└── websocket/
    └── chat.test.ts
```

**Пример теста:**
```typescript
// server/tests/integration/api/auth.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { build } from '@/app'
import { setupTestDB, cleanupTestDB } from '@/tests/helpers/db'

describe('Auth API', () => {
  let app: any

  beforeAll(async () => {
    await setupTestDB()
    app = await build()
  })

  afterAll(async () => {
    await app.close()
    await cleanupTestDB()
  })

  it('should register new user', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        username: 'testuser',
        email: 'test@example.com',
        password: 'SecurePass123!'
      }
    })

    expect(response.statusCode).toBe(201)
    expect(response.json()).toHaveProperty('token')
  })

  it('should reject duplicate username', async () => {
    // Регистрируем первого пользователя
    await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        username: 'testuser',
        email: 'test1@example.com',
        password: 'Pass123!'
      }
    })

    // Пытаемся зарегистрировать с тем же username
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        username: 'testuser', // дубликат!
        email: 'test2@example.com',
        password: 'Pass456!'
      }
    })

    expect(response.statusCode).toBe(409)
    expect(response.json().error).toContain('already exists')
  })
})
```

### 3. E2E Tests (End-to-End тесты)

**Что тестируем:**
- Полные пользовательские сценарии
- UI + Backend вместе
- Критичные флоу

**Инструменты:**
- `Playwright` (мощнее Cypress, multi-browser)

**Пример структуры:**
```
tests/e2e/
├── auth/
│   ├── registration.spec.ts
│   └── login.spec.ts
├── chat/
│   ├── send-message.spec.ts
│   └── create-group.spec.ts
└── settings/
    └── device-management.spec.ts
```

**Пример теста:**
```typescript
// tests/e2e/auth/registration.spec.ts
import { test, expect } from '@playwright/test'

test.describe('User Registration', () => {
  test('should register new user successfully', async ({ page }) => {
    // Перейти на страницу регистрации
    await page.goto('http://localhost:5173/register')

    // Заполнить форму
    await page.fill('input[name="username"]', 'newuser')
    await page.fill('input[name="email"]', 'new@example.com')
    await page.fill('input[name="password"]', 'SecurePass123!')

    // Отправить
    await page.click('button[type="submit"]')

    // Проверить редирект на главную
    await expect(page).toHaveURL('http://localhost:5173/')

    // Проверить появление баннера с подтверждением email
    await expect(page.locator('text=Confirm your email')).toBeVisible()
  })

  test('should show validation errors', async ({ page }) => {
    await page.goto('http://localhost:5173/register')

    // Короткий пароль
    await page.fill('input[name="password"]', 'short')
    await page.click('button[type="submit"]')

    // Проверить ошибку
    await expect(page.locator('text=at least 8 characters')).toBeVisible()
  })
})
```

---

## 🚀 НАСТРОЙКА И ЗАПУСК

### Установка зависимостей

```bash
# Server
cd server
pnpm add -D vitest @vitest/ui supertest @types/supertest testcontainers

# Client
cd client
pnpm add -D vitest @vitest/ui @testing-library/react @testing-library/jest-dom jsdom

# E2E
cd ..
pnpm add -D @playwright/test
pnpm dlx playwright install
```

### Конфигурация Vitest (Server)

```typescript
// server/vitest.config.ts
import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['node_modules/', 'dist/', 'tests/']
    },
    testTimeout: 10000,
    hookTimeout: 10000
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  }
})
```

### Конфигурация Vitest (Client)

```typescript
// client/vitest.config.ts
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './tests/setup.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html']
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  }
})
```

### Конфигурация Playwright

```typescript
// playwright.config.ts
import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure'
  },
  webServer: {
    command: 'pnpm dev:all',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI
  }
})
```

### Scripts в package.json

```json
{
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest run --coverage",
    "test:unit": "vitest run --dir tests/unit",
    "test:integration": "vitest run --dir tests/integration",
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui",
    "test:all": "pnpm test && pnpm test:e2e"
  }
}
```

### Запуск тестов

```bash
# Все тесты
pnpm test

# В watch mode (для разработки)
pnpm test:watch

# С UI (очень удобно!)
pnpm test:ui

# С coverage
pnpm test:coverage

# Только unit
pnpm test:unit

# Только integration
pnpm test:integration

# E2E тесты
pnpm test:e2e

# E2E с UI
pnpm test:e2e:ui
```

---

## ✍️ НАПИСАНИЕ ТЕСТОВ

### Паттерн AAA (Arrange-Act-Assert)

```typescript
it('should do something', () => {
  // Arrange (подготовка)
  const input = 'test data'
  const expected = 'expected result'

  // Act (действие)
  const result = myFunction(input)

  // Assert (проверка)
  expect(result).toBe(expected)
})
```

### Тестирование API endpoints

```typescript
import { describe, it, expect, beforeAll } from 'vitest'
import { build } from '@/app'

describe('Messages API', () => {
  let app: any
  let authToken: string

  beforeAll(async () => {
    app = await build()

    // Создать пользователя и получить токен
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { username: 'testuser', email: 'test@example.com', password: 'Pass123!' }
    })
    authToken = response.json().token
  })

  it('should send message', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/messages',
      headers: {
        authorization: `Bearer ${authToken}`
      },
      payload: {
        recipientId: 'user2',
        content: 'Hello!'
      }
    })

    expect(response.statusCode).toBe(201)
    expect(response.json()).toHaveProperty('messageId')
  })
})
```

### Тестирование React компонентов

```typescript
import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { LoginForm } from '@/components/LoginForm'

describe('LoginForm', () => {
  it('should render form', () => {
    render(<LoginForm />)

    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Login' })).toBeInTheDocument()
  })

  it('should call onSubmit with credentials', async () => {
    const onSubmit = vi.fn()
    render(<LoginForm onSubmit={onSubmit} />)

    // Заполнить форму
    fireEvent.change(screen.getByLabelText('Username'), {
      target: { value: 'testuser' }
    })
    fireEvent.change(screen.getByLabelText('Password'), {
      target: { value: 'password123' }
    })

    // Отправить
    fireEvent.click(screen.getByRole('button', { name: 'Login' }))

    // Проверить вызов
    expect(onSubmit).toHaveBeenCalledWith({
      username: 'testuser',
      password: 'password123'
    })
  })
})
```

### Мокирование

```typescript
import { vi } from 'vitest'

// Мокирование функции
const mockFetch = vi.fn()

// Мокирование модуля
vi.mock('@/services/api', () => ({
  fetchUser: vi.fn(() => Promise.resolve({ id: 1, name: 'Test' }))
}))

// Мокирование времени
vi.useFakeTimers()
vi.setSystemTime(new Date('2024-01-01'))

// Восстановление
vi.useRealTimers()
```

---

## 💡 BEST PRACTICES

### 1. Тестируй поведение, а не реализацию

❌ **Плохо:**
```typescript
it('should call setState', () => {
  const setState = vi.fn()
  component.setState = setState
  component.handleClick()
  expect(setState).toHaveBeenCalled()
})
```

✅ **Хорошо:**
```typescript
it('should show error message on invalid input', () => {
  render(<Form />)
  fireEvent.click(screen.getByRole('button'))
  expect(screen.getByText('Invalid input')).toBeVisible()
})
```

### 2. Используй описательные названия

❌ **Плохо:**
```typescript
it('test1', () => {})
it('works', () => {})
```

✅ **Хорошо:**
```typescript
it('should return 401 when token is expired', () => {})
it('should encrypt message with valid key', () => {})
```

### 3. Один тест = одна проверка

❌ **Плохо:**
```typescript
it('should handle everything', () => {
  // Тест регистрации
  // Тест логина
  // Тест отправки сообщения
  // ... 100 строк
})
```

✅ **Хорошо:**
```typescript
it('should register user', () => { /* ... */ })
it('should login user', () => { /* ... */ })
it('should send message', () => { /* ... */ })
```

### 4. Изолируй тесты

```typescript
import { beforeEach, afterEach } from 'vitest'

describe('My tests', () => {
  beforeEach(async () => {
    // Чистая база перед каждым тестом
    await cleanDatabase()
  })

  afterEach(async () => {
    // Очистка после теста
    await cleanup()
  })

  it('test 1', () => {
    // Не зависит от других тестов
  })

  it('test 2', () => {
    // Тоже независим
  })
})
```

### 5. Используй Test Helpers

```typescript
// tests/helpers/auth.ts
export async function createTestUser(username: string) {
  const response = await app.inject({
    method: 'POST',
    url: '/api/auth/register',
    payload: {
      username,
      email: `${username}@test.com`,
      password: 'TestPass123!'
    }
  })
  return response.json()
}

// В тесте:
it('should send message', async () => {
  const user1 = await createTestUser('alice')
  const user2 = await createTestUser('bob')
  // ...
})
```

---

## 📊 COVERAGE

### Проверка покрытия

```bash
pnpm test:coverage
```

Результат:
```
----------------------|---------|----------|---------|---------|
File                  | % Stmts | % Branch | % Funcs | % Lines |
----------------------|---------|----------|---------|---------|
All files             |   75.5  |   68.2   |   80.1  |   76.3  |
 src/utils            |   90.2  |   85.5   |   95.0  |   91.0  |
  crypto.ts           |   95.0  |   90.0   |  100.0  |   96.0  |
  jwt.ts              |   85.0  |   80.0   |   90.0  |   86.0  |
 src/routes           |   70.0  |   60.0   |   75.0  |   71.0  |
  auth.routes.ts      |   80.0  |   70.0   |   85.0  |   82.0  |
----------------------|---------|----------|---------|---------|
```

### Целевые метрики

- **Statements:** 70%+
- **Branches:** 65%+
- **Functions:** 75%+
- **Lines:** 70%+

### Игнорирование файлов

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    coverage: {
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.config.ts',
        '**/*.d.ts',
        '**/types.ts'
      ]
    }
  }
})
```

---

## 🎯 ЧЕКЛИСТ ДЛЯ НОВОЙ ФИЧИ

При добавлении новой функциональности:

- [ ] Написаны unit тесты для всех новых функций
- [ ] Написаны integration тесты для API endpoints
- [ ] Добавлен E2E тест для критичного сценария
- [ ] Все тесты проходят (`pnpm test`)
- [ ] Coverage не уменьшился
- [ ] Тесты изолированы и не зависят друг от друга
- [ ] Используются описательные названия тестов
- [ ] Добавлены test helpers если нужно

---

## 🐛 DEBUGGING ТЕСТОВ

### Vitest UI

```bash
pnpm test:ui
```

Откроется браузер с интерактивным интерфейсом:
- Видно какие тесты проходят/падают
- Можно запускать по одному
- Видно coverage в реальном времени

### Playwright UI

```bash
pnpm test:e2e:ui
```

Позволяет:
- Смотреть тесты в реальном времени
- Делать шаг за шагом
- Видеть скриншоты
- Инспектировать элементы

### Отладка в VS Code

```json
// .vscode/launch.json
{
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug Vitest Tests",
      "runtimeExecutable": "pnpm",
      "runtimeArgs": ["test"],
      "console": "integratedTerminal"
    }
  ]
}
```

---

## 📚 ПОЛЕЗНЫЕ ССЫЛКИ

- [Vitest Documentation](https://vitest.dev/)
- [Testing Library](https://testing-library.com/)
- [Playwright Documentation](https://playwright.dev/)
- [Supertest](https://github.com/ladjs/supertest)
- [Test Containers](https://testcontainers.com/)

---

**Последнее обновление:** 2025-11-20
