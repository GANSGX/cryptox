/**
 * 🔥 EXTREME K6 STRESS TEST 🔥
 * Цель: НАЙТИ ПРЕДЕЛ СИСТЕМЫ! Нагружаем до BREAKING POINT
 *
 * Stages (Pentagon-level stress):
 * - 0 → 1,000 users (2 min) - Warm up
 * - 1,000 → 2,500 users (3 min) - Heavy load
 * - 2,500 → 5,000 users (3 min) - Extreme load
 * - 5,000 → 10,000 users (3 min) - BREAKING POINT
 * - 10,000 → 15,000 users (2 min) - BEYOND LIMITS
 * - 15,000 → 0 users (3 min) - Recovery
 *
 * Total: 16 minutes
 *
 * Цель: Найти АБСОЛЮТНЫЙ ПРЕДЕЛ системы при 10,000+ concurrent users
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const timeouts = new Counter('timeouts');
const serverErrors = new Counter('server_errors_5xx');
const authSuccess = new Counter('auth_success');

export const options = {
  stages: [
    { duration: '2m', target: 1000 },   // Warm up
    { duration: '3m', target: 2500 },   // Heavy load
    { duration: '3m', target: 5000 },   // Extreme load
    { duration: '3m', target: 10000 },  // BREAKING POINT
    { duration: '2m', target: 15000 },  // BEYOND LIMITS
    { duration: '3m', target: 0 },      // Recovery
  ],
  thresholds: {
    // Послабленные требования - хотим увидеть как система ломается
    http_req_duration: ['p(95)<5000', 'p(99)<10000'], // Допускаем очень медленные ответы
    errors: ['rate<0.50'], // До 50% ошибок допустимо при экстремальном стрессе
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const scenario = Math.random();

  try {
    if (scenario < 0.4) {
      // 40% - Регистрация (тяжёлая операция - Argon2id)
      stressRegister();
    } else if (scenario < 0.7) {
      // 30% - Логин (средняя нагрузка)
      stressLogin();
    } else if (scenario < 0.9) {
      // 20% - Проверка токена
      stressAuth();
    } else {
      // 10% - Health check
      stressHealth();
    }
  } catch (e) {
    console.error(`Error in iteration: ${e.message}`);
    errorRate.add(1);
  }

  // Короткий sleep чтобы создать МАКСИМАЛЬНУЮ нагрузку
  sleep(Math.random() * 0.5);
}

function stressRegister() {
  const username = `stress_${__VU}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const payload = JSON.stringify({
    username: username,
    email: `${username}@stress.test`,
    password: 'StressTest123!',
    public_key: generateMockPublicKey(username),
    deviceFingerprint: `stress-${__VU}`,
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s', // Даём больше времени
  };

  const res = http.post(`${BASE_URL}/api/auth/register`, payload, params);

  const success = check(res, {
    'register: not timeout': (r) => r.status !== 0,
    'register: server responding': (r) => r.status < 500 || r.status >= 600,
  });

  if (res.status === 201) {
    authSuccess.add(1);
  } else if (res.status >= 500) {
    serverErrors.add(1);
  } else if (res.status === 0) {
    timeouts.add(1);
  }

  errorRate.add(!success);
}

function stressLogin() {
  const username = `user${Math.floor(Math.random() * 100)}`;
  const payload = JSON.stringify({
    username: username,
    password: 'TestPassword123',
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
  };

  const res = http.post(`${BASE_URL}/api/auth/login`, payload, params);

  const success = check(res, {
    'login: not timeout': (r) => r.status !== 0,
    'login: server responding': (r) => r.status === 200 || r.status === 401,
  });

  if (res.status === 200) {
    authSuccess.add(1);
  } else if (res.status >= 500) {
    serverErrors.add(1);
  } else if (res.status === 0) {
    timeouts.add(1);
  }

  errorRate.add(!success);
}

function stressAuth() {
  // Создаём фейковый токен (проверяем обработку невалидных токенов под нагрузкой)
  const fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QifQ.fake';

  const params = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${fakeToken}`,
    },
    timeout: '5s',
  };

  const res = http.get(`${BASE_URL}/api/me`, params);

  const success = check(res, {
    'auth: not timeout': (r) => r.status !== 0,
    'auth: proper error': (r) => r.status === 401,
  });

  if (res.status >= 500) {
    serverErrors.add(1);
  } else if (res.status === 0) {
    timeouts.add(1);
  }

  errorRate.add(!success);
}

function stressHealth() {
  const res = http.get(`${BASE_URL}/health`, { timeout: '3s' });

  const success = check(res, {
    'health: responding': (r) => r.status === 200,
  });

  if (res.status === 0) {
    timeouts.add(1);
  }

  errorRate.add(!success);
}

function generateMockPublicKey(username) {
  return `-----BEGIN PUBLIC KEY-----\nMIIBIjAN${username.substring(0, 40)}\n-----END PUBLIC KEY-----`;
}

export function handleSummary(data) {
  console.log('\n================================');
  console.log('💥 STRESS TEST RESULTS');
  console.log('================================\n');

  const metrics = data.metrics;

  console.log('🔥 SYSTEM UNDER EXTREME LOAD:');
  console.log(`  Total Requests: ${metrics.http_reqs.values.count}`);
  console.log(`  Requests/sec (peak): ${metrics.http_reqs.values.rate.toFixed(2)}`);
  console.log(`  Error Rate: ${(metrics.errors.values.rate * 100).toFixed(2)}%`);
  console.log(`  Timeouts: ${metrics.timeouts.values.count}`);
  console.log(`  5xx Errors: ${metrics.server_errors_5xx.values.count}`);
  console.log('');

  console.log('⏱️  RESPONSE TIME DEGRADATION:');
  console.log(`  Average: ${metrics.http_req_duration.values.avg.toFixed(2)}ms`);
  console.log(`  Median: ${metrics.http_req_duration.values.med.toFixed(2)}ms`);
  console.log(`  P95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  P99: ${metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`);
  console.log(`  MAX: ${metrics.http_req_duration.values.max.toFixed(2)}ms`);
  console.log('');

  console.log('✅ SUCCESSFUL OPERATIONS:');
  console.log(`  Auth Success: ${metrics.auth_success.values.count}`);
  console.log('');

  // Анализ breaking point
  if (metrics.errors.values.rate > 0.30) {
    console.log('❌ BREAKING POINT FOUND!');
    console.log('   System cannot handle this load level.');
    console.log(`   Error rate exceeded 30%: ${(metrics.errors.values.rate * 100).toFixed(2)}%`);
  } else if (metrics.http_req_duration.values['p(95)'] > 2000) {
    console.log('⚠️  PERFORMANCE DEGRADATION DETECTED!');
    console.log('   System is slow but functional.');
  } else {
    console.log('💪 SYSTEM IS BEAST! Handled stress test well.');
  }

  console.log('================================\n');

  return { 'stdout': JSON.stringify(data, null, 2) };
}
