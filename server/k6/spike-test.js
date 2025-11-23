/**
 * K6 SPIKE TEST
 * Цель: Внезапный ОГРОМНЫЙ скачок нагрузки (DDoS simulation)
 *
 * Scenario:
 * - Нормальная нагрузка: 50 users (2 min)
 * - 🔥 SPIKE: 50 → 1000 users за 10 секунд!
 * - Удержание пика: 1000 users (1 min)
 * - Возврат к норме: 1000 → 50 users за 10 секунд
 * - Восстановление: 50 users (2 min)
 *
 * Total: ~5 minutes
 *
 * Цель: Проверить как система реагирует на ВНЕЗАПНУЮ нагрузку
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const spikeErrors = new Counter('spike_phase_errors');
const recoverySuccess = new Counter('recovery_success');

export const options = {
  stages: [
    { duration: '2m', target: 50 },      // Baseline
    { duration: '10s', target: 1000 },   // 🔥 SPIKE!
    { duration: '1m', target: 1000 },    // Hold spike
    { duration: '10s', target: 50 },     // Drop
    { duration: '2m', target: 50 },      // Recovery
  ],
  thresholds: {
    // Во время spike допускаем временные проблемы
    http_req_duration: ['p(95)<3000'],
    errors: ['rate<0.40'], // До 40% ошибок допустимо во время spike
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

let currentStage = 'baseline';

export default function () {
  // Определяем в какой фазе мы находимся по VU count
  const vu = __VU;
  if (vu <= 50) {
    currentStage = __ITER < 60 ? 'baseline' : 'recovery';
  } else {
    currentStage = 'spike';
  }

  try {
    const scenario = Math.random();

    if (scenario < 0.5) {
      // 50% - Регистрация (самая тяжёлая операция)
      spikeRegister();
    } else if (scenario < 0.8) {
      // 30% - Логин
      spikeLogin();
    } else {
      // 20% - Health check
      spikeHealth();
    }
  } catch (e) {
    errorRate.add(1);
    if (currentStage === 'spike') {
      spikeErrors.add(1);
    }
  }

  // Очень короткий sleep чтобы создать максимальный spike
  sleep(currentStage === 'spike' ? 0.1 : Math.random() * 0.5);
}

function spikeRegister() {
  const username = `spike_${__VU}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const payload = JSON.stringify({
    username: username,
    email: `${username}@spike.test`,
    password: 'SpikeTest123!',
    public_key: `-----BEGIN PUBLIC KEY-----\nMIIB${username.slice(0, 30)}\n-----END PUBLIC KEY-----`,
    deviceFingerprint: `spike-${__VU}`,
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    timeout: '15s',
  };

  const res = http.post(`${BASE_URL}/api/auth/register`, payload, params);

  const success = check(res, {
    'spike register: status ok': (r) => r.status === 201 || r.status === 429, // 429 = rate limited (acceptable)
  });

  if (res.status === 201 && currentStage === 'recovery') {
    recoverySuccess.add(1);
  }

  errorRate.add(!success && res.status !== 429); // Rate limiting не считаем ошибкой
}

function spikeLogin() {
  const payload = JSON.stringify({
    username: `user${Math.floor(Math.random() * 50)}`,
    password: 'TestPassword123',
  });

  const params = {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
  };

  const res = http.post(`${BASE_URL}/api/auth/login`, payload, params);

  const success = check(res, {
    'spike login: responding': (r) => r.status !== 0 && r.status < 500,
  });

  if (res.status === 200 && currentStage === 'recovery') {
    recoverySuccess.add(1);
  }

  errorRate.add(!success);
}

function spikeHealth() {
  const res = http.get(`${BASE_URL}/health`, { timeout: '5s' });

  const success = check(res, {
    'spike health: ok': (r) => r.status === 200,
  });

  errorRate.add(!success);
}

export function handleSummary(data) {
  console.log('\n================================');
  console.log('⚡ SPIKE TEST RESULTS');
  console.log('================================\n');

  const metrics = data.metrics;

  console.log('📈 SPIKE CHARACTERISTICS:');
  console.log(`  Total Requests: ${metrics.http_reqs.values.count}`);
  console.log(`  Peak Requests/sec: ${metrics.http_reqs.values.rate.toFixed(2)}`);
  console.log(`  Spike Phase Errors: ${metrics.spike_phase_errors.values.count}`);
  console.log('');

  console.log('⏱️  RESPONSE TIME DURING SPIKE:');
  console.log(`  Average: ${metrics.http_req_duration.values.avg.toFixed(2)}ms`);
  console.log(`  P95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  console.log(`  P99: ${metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`);
  console.log(`  MAX: ${metrics.http_req_duration.values.max.toFixed(2)}ms`);
  console.log('');

  console.log('🔄 RECOVERY:');
  console.log(`  Successful ops after spike: ${metrics.recovery_success.values.count}`);
  console.log(`  Overall Error Rate: ${(metrics.errors.values.rate * 100).toFixed(2)}%`);
  console.log('');

  const spikeHandled = metrics.errors.values.rate < 0.40;
  const fastRecovery = metrics.recovery_success.values.count > 10;

  if (spikeHandled && fastRecovery) {
    console.log('✅ SPIKE TEST PASSED!');
    console.log('   System handled sudden load spike and recovered quickly.');
  } else if (spikeHandled && !fastRecovery) {
    console.log('⚠️  SPIKE HANDLED BUT SLOW RECOVERY');
    console.log('   System survived but takes time to recover.');
  } else {
    console.log('❌ SPIKE TEST FAILED!');
    console.log('   System cannot handle sudden load spikes.');
    console.log('   Consider: Rate limiting, load balancing, auto-scaling.');
  }

  console.log('================================\n');

  return { 'stdout': JSON.stringify(data, null, 2) };
}
