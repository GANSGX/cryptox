/**
 * K6 LOAD TEST
 * Цель: Проверить как система работает под обычной нагрузкой
 *
 * Stages:
 * - Warm up: 0 → 100 users (1 min)
 * - Steady load: 100 users (5 min)
 * - Peak: 100 → 200 users (2 min)
 * - Cool down: 200 → 0 users (1 min)
 *
 * Total duration: 9 minutes
 *
 * Ожидаемые результаты:
 * - Error rate < 5%
 * - P95 response time < 500ms
 * - Throughput > 100 req/sec
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const successfulRegistrations = new Counter('successful_registrations');
const successfulLogins = new Counter('successful_logins');
const authDuration = new Trend('auth_duration');

export const options = {
  stages: [
    { duration: '1m', target: 100 },   // Warm up
    { duration: '5m', target: 100 },   // Steady load
    { duration: '2m', target: 200 },   // Peak
    { duration: '1m', target: 0 },     // Cool down
  ],
  thresholds: {
    errors: ['rate<0.05'], // < 5% errors
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // P95 < 500ms, P99 < 1s
    http_req_failed: ['rate<0.05'],
    http_reqs: ['rate>100'], // > 100 req/sec
    auth_duration: ['p(95)<800'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const scenario = Math.random();

  if (scenario < 0.6) {
    // 60% - Register new user
    registerUser();
  } else if (scenario < 0.9) {
    // 30% - Login existing user
    loginUser();
  } else {
    // 10% - Check health endpoint
    checkHealth();
  }

  sleep(Math.random() * 3); // Random sleep 0-3 seconds
}

function registerUser() {
  const username = `loaduser_${__VU}_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const email = `${username}@load.test`;
  const password = 'LoadTest123!';

  const payload = JSON.stringify({
    username: username,
    email: email,
    password: password,
    public_key: generateMockPublicKey(username),
    deviceFingerprint: `load-device-${__VU}`,
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
  };

  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/auth/register`, payload, params);
  authDuration.add(Date.now() - start);

  const success = check(res, {
    'register: status 201': (r) => r.status === 201,
    'register: has token': (r) => {
      try {
        return JSON.parse(r.body).data?.token;
      } catch {
        return false;
      }
    },
  });

  if (success) {
    successfulRegistrations.add(1);
  } else {
    errorRate.add(1);
  }
}

function loginUser() {
  // Simulate login with random credentials (will likely fail, testing error handling)
  const username = `user${Math.floor(Math.random() * 1000)}`;
  const password = 'TestPassword123';

  const payload = JSON.stringify({ username, password });
  const params = {
    headers: { 'Content-Type': 'application/json' },
  };

  const start = Date.now();
  const res = http.post(`${BASE_URL}/api/auth/login`, payload, params);
  authDuration.add(Date.now() - start);

  const success = check(res, {
    'login: response received': (r) => r.status === 200 || r.status === 401,
  });

  if (res.status === 200) {
    successfulLogins.add(1);
  }

  errorRate.add(!success);
}

function checkHealth() {
  const res = http.get(`${BASE_URL}/health`);

  const success = check(res, {
    'health: status 200': (r) => r.status === 200,
  });

  errorRate.add(!success);
}

function generateMockPublicKey(username) {
  const base64 = Buffer.from(username).toString('base64').substring(0, 50);
  return `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA${base64}\n-----END PUBLIC KEY-----`;
}

export function handleSummary(data) {
  console.log('\n================================');
  console.log('🔥 LOAD TEST RESULTS');
  console.log('================================\n');

  const metrics = data.metrics;

  console.log('📊 THROUGHPUT:');
  console.log(`  Total Requests: ${metrics.http_reqs.values.count}`);
  console.log(`  Requests/sec: ${metrics.http_reqs.values.rate.toFixed(2)}`);
  console.log(`  Failed: ${(metrics.http_req_failed.values.rate * 100).toFixed(2)}%`);
  console.log('');

  console.log('⏱️  RESPONSE TIME:');
  console.log(`  Average: ${metrics.http_req_duration.values.avg.toFixed(2)}ms`);
  console.log(`  Median: ${metrics.http_req_duration.values.med.toFixed(2)}ms`);
  console.log(`  P95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  P99: ${metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`);
  console.log(`  Max: ${metrics.http_req_duration.values.max.toFixed(2)}ms`);
  console.log('');

  console.log('🔐 AUTH OPERATIONS:');
  console.log(`  Successful Registrations: ${metrics.successful_registrations.values.count}`);
  console.log(`  Successful Logins: ${metrics.successful_logins.values.count}`);
  console.log(`  Auth P95: ${metrics.auth_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  Error Rate: ${(metrics.errors.values.rate * 100).toFixed(2)}%`);
  console.log('');

  const passed =
    metrics.errors.values.rate < 0.05 &&
    metrics.http_req_duration.values['p(95)'] < 500 &&
    metrics.http_reqs.values.rate > 100;

  if (passed) {
    console.log('✅ LOAD TEST PASSED! System handles normal load well.');
  } else {
    console.log('❌ LOAD TEST FAILED! System struggles under normal load.');
  }

  console.log('================================\n');

  return { 'stdout': JSON.stringify(data, null, 2) };
}
