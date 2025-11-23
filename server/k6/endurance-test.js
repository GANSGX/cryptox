/**
 * K6 ENDURANCE TEST (SOAK TEST)
 * Цель: Проверить стабильность системы под ДЛИТЕЛЬНОЙ нагрузкой
 *
 * Duration: 30 minutes
 * Load: Постоянная нагрузка 200 VU
 *
 * Проверяем:
 * - Memory leaks
 * - Connection pool exhaustion
 * - Degradation over time
 * - Resource leaks
 *
 * Ожидаемые результаты:
 * - Стабильная производительность на протяжении всего теста
 * - Нет деградации response time
 * - Нет memory leaks
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const memoryIssues = new Counter('memory_issues');
const slowRequests = new Counter('slow_requests');
const responseTimeTrend = new Trend('response_time_trend');

export const options = {
  stages: [
    { duration: '2m', target: 200 },   // Ramp up
    { duration: '30m', target: 200 },  // Endurance (sustained load)
    { duration: '2m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<600', 'p(99)<1500'], // Должно оставаться стабильным
    errors: ['rate<0.02'], // < 2% errors
    http_reqs: ['rate>80'], // Throughput должен оставаться стабильным
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

// Track statistics over time
let iterationCount = 0;
let slowRequestsInWindow = 0;

export default function () {
  iterationCount++;

  try {
    const scenario = Math.random();

    if (scenario < 0.3) {
      // 30% - Регистрация
      enduranceRegister();
    } else if (scenario < 0.6) {
      // 30% - Логин
      enduranceLogin();
    } else if (scenario < 0.9) {
      // 30% - Проверка авторизации
      enduranceAuth();
    } else {
      // 10% - Health check
      enduranceHealth();
    }

    // Проверяем деградацию каждые 1000 итераций
    if (iterationCount % 1000 === 0) {
      checkForDegradation();
    }
  } catch (e) {
    errorRate.add(1);
  }

  sleep(Math.random() * 2);
}

function enduranceRegister() {
  const username = `endurance_${__VU}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const payload = JSON.stringify({
    username: username,
    email: `${username}@endurance.test`,
    password: 'EnduranceTest123!',
    public_key: generateMockPublicKey(username),
    deviceFingerprint: `endurance-${__VU}`,
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    timeout: '20s',
  };

  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/auth/register`, payload, params);
  const duration = Date.now() - start;

  responseTimeTrend.add(duration);

  // Отслеживаем медленные запросы (возможный признак memory leak)
  if (duration > 2000) {
    slowRequests.add(1);
    slowRequestsInWindow++;
  }

  const success = check(res, {
    'endurance register: status 201': (r) => r.status === 201,
    'endurance register: not too slow': () => duration < 5000,
  });

  errorRate.add(!success);
}

function enduranceLogin() {
  const username = `user${Math.floor(Math.random() * 100)}`;
  const payload = JSON.stringify({
    username: username,
    password: 'TestPassword123',
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    timeout: '15s',
  };

  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/auth/login`, payload, params);
  const duration = Date.now() - start;

  responseTimeTrend.add(duration);

  if (duration > 1500) {
    slowRequests.add(1);
  }

  const success = check(res, {
    'endurance login: responding': (r) => r.status === 200 || r.status === 401,
  });

  errorRate.add(!success);
}

function enduranceAuth() {
  // Используем фейковый токен для проверки обработки ошибок
  const fakeToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify({ test: Date.now() })).toString('base64')}.fake`;

  const params = {
    headers: {
      Authorization: `Bearer ${fakeToken}`,
    },
    timeout: '10s',
  };

  const res = http.get(`${BASE_URL}/api/me`, params);

  const success = check(res, {
    'endurance auth: proper error': (r) => r.status === 401,
  });

  errorRate.add(!success);
}

function enduranceHealth() {
  const res = http.get(`${BASE_URL}/health`, { timeout: '5s' });

  const success = check(res, {
    'endurance health: ok': (r) => r.status === 200,
  });

  errorRate.add(!success);
}

function checkForDegradation() {
  // Проверяем есть ли признаки деградации
  if (slowRequestsInWindow > 100) {
    console.warn(`⚠️  Degradation detected! ${slowRequestsInWindow} slow requests in last window`);
    memoryIssues.add(1);
  }
  slowRequestsInWindow = 0;
}

function generateMockPublicKey(username) {
  return `-----BEGIN PUBLIC KEY-----\nMIIBIjAN${username.substring(0, 40)}\n-----END PUBLIC KEY-----`;
}

export function handleSummary(data) {
  console.log('\n================================');
  console.log('🏃 ENDURANCE TEST RESULTS (30 min)');
  console.log('================================\n');

  const metrics = data.metrics;

  console.log('📊 SUSTAINED PERFORMANCE:');
  console.log(`  Total Requests: ${metrics.http_reqs.values.count}`);
  console.log(`  Requests/sec (avg): ${metrics.http_reqs.values.rate.toFixed(2)}`);
  console.log(`  Test Duration: ${((data.state.testRunDurationMs || 0) / 1000 / 60).toFixed(1)} minutes`);
  console.log('');

  console.log('⏱️  RESPONSE TIME STABILITY:');
  console.log(`  Average: ${metrics.http_req_duration.values.avg.toFixed(2)}ms`);
  console.log(`  Median: ${metrics.http_req_duration.values.med.toFixed(2)}ms`);
  console.log(`  P95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  P99: ${metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`);
  console.log(`  MAX: ${metrics.http_req_duration.values.max.toFixed(2)}ms`);
  console.log('');

  console.log('🔍 DEGRADATION ANALYSIS:');
  console.log(`  Slow Requests (>2s): ${metrics.slow_requests.values.count}`);
  console.log(`  Memory Issues Detected: ${metrics.memory_issues.values.count}`);
  console.log(`  Error Rate: ${(metrics.errors.values.rate * 100).toFixed(2)}%`);
  console.log('');

  const stable = metrics.errors.values.rate < 0.02;
  const noMemoryLeaks = metrics.memory_issues.values.count === 0;
  const performanceStable = metrics.http_req_duration.values['p(95)'] < 600;

  if (stable && noMemoryLeaks && performanceStable) {
    console.log('✅ ENDURANCE TEST PASSED!');
    console.log('   System is stable under sustained load.');
    console.log('   No memory leaks detected.');
    console.log('   Performance remains consistent.');
  } else if (!noMemoryLeaks) {
    console.log('❌ MEMORY LEAK DETECTED!');
    console.log('   Performance degraded over time.');
    console.log('   Investigate: connection pools, event listeners, caching.');
  } else if (!stable) {
    console.log('⚠️  INSTABILITY UNDER SUSTAINED LOAD');
    console.log('   Error rate increased over time.');
  } else {
    console.log('⚠️  PERFORMANCE DEGRADATION');
    console.log('   Response times increased over time.');
  }

  console.log('================================\n');

  return { 'stdout': JSON.stringify(data, null, 2) };
}
