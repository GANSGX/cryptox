/**
 * K6 SMOKE TEST
 * Цель: Убедиться что система работает под минимальной нагрузкой
 *
 * Virtual Users: 5
 * Duration: 1 minute
 *
 * Ожидаемые результаты:
 * - 0% ошибок
 * - Response time < 200ms (p95)
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const registerDuration = new Trend('register_duration');
const loginDuration = new Trend('login_duration');

export const options = {
  vus: 5, // 5 виртуальных пользователей
  duration: '1m', // 1 минута
  thresholds: {
    errors: ['rate<0.01'], // Меньше 1% ошибок
    http_req_duration: ['p(95)<200'], // 95% запросов быстрее 200ms
    http_req_failed: ['rate<0.01'], // Меньше 1% failed запросов
    register_duration: ['p(95)<500'], // Регистрация быстрее 500ms
    login_duration: ['p(95)<400'], // Логин быстрее 400ms
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const username = `smokeuser_${__VU}_${Date.now()}`;
  const email = `${username}@smoke.test`;
  const password = 'TestPassword123!';

  // 1. РЕГИСТРАЦИЯ
  const registerPayload = JSON.stringify({
    username: username,
    email: email,
    password: password,
    public_key: generateMockPublicKey(username),
    deviceFingerprint: `smoke-device-${__VU}`,
  });

  const registerParams = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const registerStart = Date.now();
  const registerRes = http.post(
    `${BASE_URL}/api/auth/register`,
    registerPayload,
    registerParams
  );
  registerDuration.add(Date.now() - registerStart);

  const registerSuccess = check(registerRes, {
    'register: status 201': (r) => r.status === 201,
    'register: has token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && body.data.token;
      } catch {
        return false;
      }
    },
  });

  errorRate.add(!registerSuccess);

  if (!registerSuccess) {
    console.error(`Registration failed for ${username}: ${registerRes.status} ${registerRes.body}`);
    sleep(1);
    return;
  }

  const token = JSON.parse(registerRes.body).data.token;

  sleep(0.5); // Пауза между запросами

  // 2. ЛОГИН
  const loginPayload = JSON.stringify({
    username: username,
    password: password,
  });

  const loginStart = Date.now();
  const loginRes = http.post(
    `${BASE_URL}/api/auth/login`,
    loginPayload,
    registerParams
  );
  loginDuration.add(Date.now() - loginStart);

  const loginSuccess = check(loginRes, {
    'login: status 200': (r) => r.status === 200,
    'login: has token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && body.data.token;
      } catch {
        return false;
      }
    },
  });

  errorRate.add(!loginSuccess);

  sleep(0.5);

  // 3. ПРОВЕРКА АВТОРИЗАЦИИ
  const meParams = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  };

  const meRes = http.get(`${BASE_URL}/api/me`, meParams);

  const meSuccess = check(meRes, {
    'me: status 200': (r) => r.status === 200,
    'me: has username': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && body.data.username === username;
      } catch {
        return false;
      }
    },
  });

  errorRate.add(!meSuccess);

  sleep(1);
}

function generateMockPublicKey(username) {
  const base64 = Buffer.from(username).toString('base64');
  return `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA${base64}
-----END PUBLIC KEY-----`;
}

export function handleSummary(data) {
  console.log('\n================================');
  console.log('🔥 SMOKE TEST RESULTS');
  console.log('================================\n');

  const metrics = data.metrics;

  console.log('📊 REQUEST METRICS:');
  console.log(`  Total Requests: ${metrics.http_reqs.values.count}`);
  console.log(`  Failed Requests: ${metrics.http_req_failed.values.rate * 100}%`);
  console.log(`  Error Rate: ${metrics.errors.values.rate * 100}%`);
  console.log('');

  console.log('⏱️  RESPONSE TIME:');
  console.log(`  Average: ${metrics.http_req_duration.values.avg.toFixed(2)}ms`);
  console.log(`  P95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  P99: ${metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`);
  console.log(`  Max: ${metrics.http_req_duration.values.max.toFixed(2)}ms`);
  console.log('');

  console.log('🔐 AUTH METRICS:');
  console.log(`  Register P95: ${metrics.register_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  Login P95: ${metrics.login_duration.values['p(95)'].toFixed(2)}ms`);
  console.log('');

  const passed =
    metrics.errors.values.rate < 0.01 &&
    metrics.http_req_duration.values['p(95)'] < 200 &&
    metrics.register_duration.values['p(95)'] < 500 &&
    metrics.login_duration.values['p(95)'] < 400;

  if (passed) {
    console.log('✅ SMOKE TEST PASSED! System is stable under minimal load.');
  } else {
    console.log('❌ SMOKE TEST FAILED! System has issues even under minimal load.');
  }

  console.log('================================\n');

  return {
    'stdout': JSON.stringify(data, null, 2),
  };
}
