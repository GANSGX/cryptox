# K6 Load Testing Suite

Профессиональный набор нагрузочных тестов для CryptoX API.

## 🎯 Цели

- ✅ Убедиться что система стабильна под нагрузкой
- ✅ Найти **breaking point** (предел системы)
- ✅ Проверить устойчивость к **DDoS** атакам
- ✅ Обнаружить **memory leaks** и деградацию производительности
- ✅ Валидировать что система выдерживает production нагрузку

---

## 📦 Установка

```bash
# Установить k6
# Windows (с Chocolatey)
choco install k6

# macOS
brew install k6

# Linux
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb https://dl.k6.io/deb stable main" | sudo tee /dev/null sudo apt-get update
sudo apt-get install k6
```

---

## 🚀 Запуск тестов

### 1. Smoke Test (🧪 Baseline)

**Цель:** Убедиться что система работает под минимальной нагрузкой

```bash
k6 run k6/smoke-test.js --env BASE_URL=http://localhost:3000
```

**Параметры:**

- 5 VU (virtual users)
- 1 минута
- Ожидается: 0% ошибок, p95 < 200ms

---

### 2. Load Test (📈 Normal Load)

**Цель:** Проверить работу под обычной нагрузкой

```bash
k6 run k6/load-test.js --env BASE_URL=http://localhost:3000
```

**Параметры:**

- 0 → 100 → 200 VU
- 9 минут
- Ожидается: < 5% ошибок, p95 < 500ms, >100 req/sec

---

### 3. Stress Test (💥 Breaking Point)

**Цель:** НАЙТИ ПРЕДЕЛ! Нагружаем до тех пор пока не сломается

```bash
k6 run k6/stress-test.js --env BASE_URL=http://localhost:3000
```

**Параметры:**

- 0 → 200 → 500 → 1000 → 1500 VU
- 12 минут
- Ожидается: Найти breaking point, допустимо до 30% ошибок

**Цель:** Узнать при какой нагрузке система начинает падать

---

### 4. Spike Test (⚡ DDoS Simulation)

**Цель:** Внезапный ОГРОМНЫЙ скачок нагрузки

```bash
k6 run k6/spike-test.js --env BASE_URL=http://localhost:3000
```

**Параметры:**

- 50 VU → **1000 VU за 10 секунд!** → 50 VU
- 5 минут
- Проверяет: Реакцию на DDoS, rate limiting, recovery time

---

### 5. Endurance Test (🏃 30 минут)

**Цель:** Проверить стабильность под ДЛИТЕЛЬНОЙ нагрузкой

```bash
k6 run k6/endurance-test.js --env BASE_URL=http://localhost:3000
```

**Параметры:**

- 200 VU constant
- 30 минут
- Проверяет: Memory leaks, connection pool exhaustion, degradation

---

## 📊 Интерпретация результатов

### ✅ SUCCESS Критерии

| Тест      | Error Rate | P95 Response Time | Throughput    |
| --------- | ---------- | ----------------- | ------------- |
| Smoke     | < 1%       | < 200ms           | N/A           |
| Load      | < 5%       | < 500ms           | > 100 req/sec |
| Stress    | < 30%      | < 2000ms          | N/A           |
| Spike     | < 40%      | < 3000ms          | N/A           |
| Endurance | < 2%       | < 600ms           | > 80 req/sec  |

### ❌ Что делать если тесты падают?

**High Error Rate:**

- Проверить логи сервера
- Увеличить connection pool
- Добавить rate limiting
- Оптимизировать slow queries

**Slow Response Times:**

- Профилировать медленные endpoints
- Добавить кэширование (Redis)
- Оптимизировать DB queries (индексы)
- Проверить Argon2id настройки (слишком тяжёлые?)

**Memory Leaks (Endurance Test):**

- Проверить connection pools (не закрываются?)
- Event listeners (утечки?)
- Кэш (растёт бесконечно?)

**Breaking Point слишком низкий:**

- Horizontal scaling (больше серверов)
- Load balancing
- Database optimization
- CDN для статики

---

## 🔥 Продвинутые сценарии

### Запуск в облаке (k6 Cloud)

```bash
k6 cloud k6/load-test.js
```

### С custom параметрами

```bash
k6 run k6/load-test.js \
  --env BASE_URL=https://api.cryptox.com \
  --vus 500 \
  --duration 10m \
  --out json=results.json
```

### Запуск всех тестов последовательно

```bash
#!/bin/bash
echo "Running full k6 test suite..."

k6 run k6/smoke-test.js --env BASE_URL=http://localhost:3000
k6 run k6/load-test.js --env BASE_URL=http://localhost:3000
k6 run k6/stress-test.js --env BASE_URL=http://localhost:3000
k6 run k6/spike-test.js --env BASE_URL=http://localhost:3000
k6 run k6/endurance-test.js --env BASE_URL=http://localhost:3000

echo "✅ All k6 tests completed!"
```

---

## 📈 CI/CD Integration

### GitHub Actions

```yaml
name: Load Tests

on:
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: "0 2 * * *" # Каждую ночь в 2:00

jobs:
  k6-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run k6 smoke test
        uses: grafana/k6-action@v0.3.1
        with:
          filename: server/k6/smoke-test.js
          flags: --env BASE_URL=https://staging.cryptox.com
```

---

## 🎯 Best Practices

1. **Всегда начинать с Smoke Test** - убедиться что система вообще работает
2. **Load Test перед деплоем** - каждый PR должен проходить load test
3. **Stress Test раз в неделю** - чтобы знать свой предел
4. **Spike Test после изменений rate limiting** - проверить защиту от DDoS
5. **Endurance Test перед релизом** - найти memory leaks

---

## 🚨 Production Monitoring

После load testing добавить мониторинг:

- **Prometheus** + **Grafana** - метрики
- **Sentry** - error tracking
- **DataDog** / **New Relic** - APM
- **k6 Cloud** - регулярные load tests

---

## 📝 TODO

- [ ] Добавить GraphQL endpoints тестирование
- [ ] WebSocket load testing (для messaging)
- [ ] Database connection pool monitoring
- [ ] Memory profiling integration
- [ ] Auto-scaling triggers based on k6 results

---

**Автор:** Claude Code + CryptoX Team
**Дата:** 2025-11-23
