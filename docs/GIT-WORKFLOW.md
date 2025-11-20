# 🌳 GIT WORKFLOW GUIDE

## 📋 СОДЕРЖАНИЕ

1. [Обзор](#обзор)
2. [Структура веток](#структура-веток)
3. [Работа с задачами](#работа-с-задачами)
4. [Соглашения коммитов](#соглашения-коммитов)
5. [Pull Requests](#pull-requests)
6. [Типичные сценарии](#типичные-сценарии)
7. [Решение проблем](#решение-проблем)

---

## 🎯 ОБЗОР

В проекте используется **Git Flow** - проверенная временем стратегия ветвления для командной разработки.

### Почему это круто?
- ✅ Чистая история коммитов
- ✅ Легко откатить изменения
- ✅ Можно работать над несколькими фичами параллельно
- ✅ Production (`main`) всегда стабильный
- ✅ Code review перед merge

---

## 🌿 СТРУКТУРА ВЕТОК

```
main (производство)
  │
  └── develop (разработка)
       │
       ├── feature/auth-improvements      # Новая функция
       ├── feature/message-reactions      # Ещё одна функция
       ├── bugfix/socket-reconnect        # Исправление бага
       └── hotfix/critical-security-fix   # Срочный фикс для main
```

### `main` - Production ветка
- **Защищена:** нельзя push напрямую
- **Стабильна:** только рабочий код
- **Деплой:** отсюда идет на сервер
- **Merge:** только через PR из `develop`

### `develop` - Основная ветка разработки
- Здесь собираются все фичи
- Можно тестировать всё вместе
- Merge в `main` когда всё готово для релиза

### `feature/*` - Ветки для новых функций
- Создаются от `develop`
- Merge обратно в `develop` через PR

### `bugfix/*` - Ветки для исправления багов
- Создаются от `develop`
- Merge в `develop` через PR

### `hotfix/*` - Срочные исправления
- Создаются от `main` (!)
- Merge и в `main`, и в `develop`

---

## 💼 РАБОТА С ЗАДАЧАМИ

### Шаг 1: Выбрать задачу
Посмотри на GitHub Projects Board:
- Выбери задачу из колонки **"Todo"**
- Переместите её в **"In Progress"**
- Запомни номер Issue (например, #42)

### Шаг 2: Создать ветку

```bash
# Переключиться на develop
git checkout develop

# Получить последние изменения
git pull origin develop

# Создать feature ветку
git checkout -b feature/short-description

# Примеры хороших названий:
feature/device-approval-ui
feature/message-encryption
bugfix/socket-reconnect-loop
bugfix/email-validation
```

### Шаг 3: Работать над задачей

```bash
# Делаешь изменения в коде...
# Тесты пишешь сразу!

# Проверяешь что всё работает
pnpm test

# Коммитишь (см. ниже про соглашения)
git add .
git commit -m "feat: add device approval UI"

# Можно делать несколько коммитов
git commit -m "feat: add approve button"
git commit -m "feat: add reject button"
git commit -m "test: add device approval tests"
```

### Шаг 4: Push на GitHub

```bash
git push origin feature/short-description
```

### Шаг 5: Создать Pull Request

1. Зайди на GitHub
2. Увидишь желтый баннер "Compare & pull request"
3. Кликни на него
4. Заполни описание PR (шаблон появится автоматически)
5. Нажми "Create Pull Request"

### Шаг 6: Дождаться проверок

- GitHub Actions запустит тесты
- Если всё зелёное ✅ → можно мержить
- Если красное ❌ → надо исправить

### Шаг 7: Merge

```bash
# После merge, локально:
git checkout develop
git pull origin develop

# Удалить feature ветку (она больше не нужна)
git branch -d feature/short-description
```

---

## 📝 СОГЛАШЕНИЯ КОММИТОВ

Используем **Conventional Commits** - стандарт индустрии.

### Формат

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Использование | Пример |
|------|---------------|--------|
| `feat` | Новая функция | `feat: add device approval` |
| `fix` | Исправление бага | `fix: socket reconnection loop` |
| `test` | Добавление тестов | `test: add auth tests` |
| `docs` | Документация | `docs: update README` |
| `style` | Форматирование | `style: fix indentation` |
| `refactor` | Рефакторинг | `refactor: extract crypto utils` |
| `perf` | Оптимизация | `perf: improve message loading` |
| `chore` | Обслуживание | `chore: update dependencies` |
| `ci` | CI/CD | `ci: add test workflow` |
| `build` | Сборка | `build: optimize bundle size` |

### Scope (опционально)

Указывает где изменения:
```bash
feat(auth): add 2FA support
fix(socket): handle disconnection
test(crypto): add encryption tests
docs(api): update endpoints list
```

### Примеры хороших коммитов

```bash
# Хорошо ✅
git commit -m "feat: add device approval workflow"
git commit -m "fix: handle socket disconnection gracefully"
git commit -m "test: add unit tests for crypto functions"
git commit -m "docs: add testing guide"

# Плохо ❌
git commit -m "update"
git commit -m "fix bug"
git commit -m "changes"
git commit -m "wip"
```

### Длинное описание (опционально)

```bash
git commit -m "feat: add device approval workflow

Users can now approve/reject new device login attempts.
This adds a new UI panel in security settings showing
pending device requests with device info and location.

Closes #42"
```

### Связь с Issues

```bash
# Упоминание Issue
git commit -m "feat: add approval UI (ref #42)"

# Автозакрытие Issue при merge
git commit -m "fix: socket reconnection

Closes #38"
```

---

## 🔄 PULL REQUESTS

### Создание PR

1. **Заголовок:** Как коммит
   ```
   feat: add device approval workflow
   ```

2. **Описание:** Используй шаблон
   ```markdown
   ## Что изменилось
   - Добавлен UI для approval/reject
   - Добавлены новые API endpoints
   - Написаны тесты

   ## Как тестировать
   1. Зарегистрировать аккаунт
   2. Попробовать логин с другого устройства
   3. Проверить появление approval запроса

   ## Screenshots (если есть)
   [картинка]

   Closes #42
   ```

3. **Reviewers:** Пока сам себе
4. **Labels:** `feature`, `enhancement`, etc.

### Code Review

Если работаешь с кем-то, они проверят:
- ✅ Код читаемый
- ✅ Тесты написаны
- ✅ Нет багов
- ✅ Следуешь стилю проекта

### После approval

```bash
# На GitHub:
Merge Pull Request → Squash and merge (рекомендую)

# Локально:
git checkout develop
git pull origin develop
git branch -d feature/short-description
```

---

## 🎬 ТИПИЧНЫЕ СЦЕНАРИИ

### Сценарий 1: Новая фича

```bash
# 1. Подготовка
git checkout develop
git pull origin develop

# 2. Создать ветку
git checkout -b feature/message-reactions

# 3. Работа
# ... пишешь код ...
# ... пишешь тесты ...
pnpm test

# 4. Коммиты
git add .
git commit -m "feat: add reaction button UI"
git commit -m "feat: add reaction API endpoints"
git commit -m "test: add reaction tests"

# 5. Push
git push origin feature/message-reactions

# 6. Создать PR на GitHub
# 7. Дождаться CI
# 8. Merge
# 9. Вернуться на develop
git checkout develop
git pull origin develop
git branch -d feature/message-reactions
```

### Сценарий 2: Исправление бага

```bash
git checkout develop
git pull origin develop
git checkout -b bugfix/socket-reconnect

# Исправляешь баг
git add .
git commit -m "fix: prevent infinite socket reconnection

Added exponential backoff and max retry limit.

Closes #55"

git push origin bugfix/socket-reconnect
# PR → Merge → Cleanup
```

### Сценарий 3: Срочный hotfix

```bash
# ⚠️ Отличается! Создаем от main
git checkout main
git pull origin main
git checkout -b hotfix/critical-security

# Исправляешь
git add .
git commit -m "fix: patch SQL injection vulnerability

CRITICAL: Updates parameterized queries.

Closes #99"

git push origin hotfix/critical-security

# PR в main → Merge
# Потом merge в develop тоже!
git checkout develop
git merge main
git push origin develop
```

### Сценарий 4: Обновить свою ветку из develop

Если работаешь долго и develop ушёл вперёд:

```bash
# Находясь в feature ветке
git checkout feature/my-feature

# Вариант 1: Merge (проще)
git merge develop

# Вариант 2: Rebase (чище история)
git rebase develop

# Push (если уже был push до этого)
git push --force-with-lease
```

---

## 🚨 РЕШЕНИЕ ПРОБЛЕМ

### Проблема 1: Забыл переключиться на develop

```bash
# О нет! Сделал коммит в main
git status
# On branch main

# Решение:
git checkout develop
git cherry-pick <commit-hash>
git checkout main
git reset --hard origin/main
```

### Проблема 2: Нужно отменить последний коммит

```bash
# Отменить коммит, но оставить изменения
git reset --soft HEAD~1

# Отменить коммит и изменения (ОСТОРОЖНО!)
git reset --hard HEAD~1
```

### Проблема 3: Конфликты при merge

```bash
git merge develop
# CONFLICT в файле

# 1. Открыть файл
# 2. Найти маркеры конфликта:
<<<<<<< HEAD
твой код
=======
код из develop
>>>>>>> develop

# 3. Исправить вручную (убрать маркеры, оставить нужное)
# 4. Закоммитить
git add .
git commit -m "merge: resolve conflicts with develop"
```

### Проблема 4: Случайно удалил ветку

```bash
# Git хранит всё 30 дней!
git reflog
# Найти commit hash

git checkout -b feature/my-feature <commit-hash>
```

### Проблема 5: Нужно изменить последний коммит

```bash
# Изменить сообщение
git commit --amend -m "правильное сообщение"

# Добавить файлы в последний коммит
git add forgotten-file.ts
git commit --amend --no-edit

# ⚠️ Если уже был push:
git push --force-with-lease
```

---

## 📊 КОМАНДЫ ШПАРГАЛКА

```bash
# === ВЕТКИ ===
git branch                          # Список веток
git branch -a                       # Все ветки (включая remote)
git checkout develop                # Переключиться на develop
git checkout -b feature/name        # Создать и переключиться
git branch -d feature/name          # Удалить ветку (после merge)
git branch -D feature/name          # Удалить принудительно

# === СИНХРОНИЗАЦИЯ ===
git pull origin develop             # Получить изменения
git push origin feature/name        # Отправить ветку
git push --force-with-lease         # Force push (безопасно)

# === КОММИТЫ ===
git add .                           # Добавить все файлы
git add file.ts                     # Добавить конкретный файл
git commit -m "message"             # Коммит
git commit --amend                  # Изменить последний коммит

# === ИСТОРИЯ ===
git log                             # История коммитов
git log --oneline                   # Короткая история
git log --graph --all               # График веток

# === ОТМЕНА ===
git reset --soft HEAD~1             # Отменить коммит (сохранить изменения)
git reset --hard HEAD~1             # Отменить коммит (удалить изменения)
git checkout -- file.ts             # Отменить изменения в файле

# === ПОЛЕЗНОЕ ===
git status                          # Статус (всегда первая команда!)
git diff                            # Посмотреть изменения
git stash                           # Спрятать изменения
git stash pop                       # Вернуть спрятанное
```

---

## 🎓 ПОЛЕЗНЫЕ ССЫЛКИ

- [Git Flow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [GitHub Pull Requests](https://docs.github.com/en/pull-requests)
- [Git Branching](https://git-scm.com/book/en/v2/Git-Branching-Branching-Workflows)

---

## ✅ ЧЕКЛИСТ ПЕРЕД PR

Перед созданием Pull Request проверь:

- [ ] Код работает локально
- [ ] Все тесты проходят (`pnpm test`)
- [ ] TypeScript без ошибок (`pnpm type-check`)
- [ ] ESLint без ошибок (`pnpm lint`)
- [ ] Написаны тесты для новой функциональности
- [ ] Обновлена документация (если нужно)
- [ ] Коммиты следуют соглашению
- [ ] Ветка обновлена из develop
- [ ] Нет console.log и отладочного кода
- [ ] Нет закомментированного кода

---

**Последнее обновление:** 2025-11-20
