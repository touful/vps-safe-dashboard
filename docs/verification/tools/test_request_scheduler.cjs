'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const appPath = process.argv[2] ? path.resolve(process.argv[2])
  : path.resolve(__dirname, '../../../internal/web/static/app.js');
const appSource = fs.readFileSync(appPath, 'utf8');
const beginMarker = '// PERF-FE-20260909:SCHEDULER-BEGIN';
const endMarker = '// PERF-FE-20260909:SCHEDULER-END';
const begin = appSource.indexOf(beginMarker);
const end = appSource.indexOf(endMarker);
assert(begin >= 0 && end > begin, 'app.js must expose the marked scheduler block');
const schedulerSource = appSource.slice(appSource.lastIndexOf('\n', begin) + 1, appSource.indexOf('\n', end) + 1);

class TestAbortController {
  constructor() {
    this.signal = { aborted: false, onabort: null };
  }

  abort() {
    this.signal.aborted = true;
    if (this.signal.onabort) this.signal.onabort();
  }
}

function makeClock(start = 0) {
  let current = start;
  let nextId = 1;
  const timers = [];
  function runDue() {
    let timer;
    while ((timer = timers.filter((item) => !item.cancelled && item.at <= current)
      .sort((a, b) => a.at - b.at)[0])) {
      timer.cancelled = true;
      timer.fn();
    }
  }
  return {
    now: () => current,
    setTimeout: (fn, delay) => {
      const timer = { id: nextId++, at: current + Math.max(0, delay), fn, cancelled: false };
      timers.push(timer);
      return timer;
    },
    clearTimeout: (timer) => { if (timer) timer.cancelled = true; },
    advance: (ms) => { current += ms; runDue(); }
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function response(status = 200, body = {}, retryAfter) {
  const headers = {
    get(name) { return name.toLowerCase() === 'retry-after' ? (retryAfter || '') : ''; }
  };
  return { ok: status >= 200 && status < 300, status, headers, json: async () => body };
}

function makeHarness(clock = makeClock(), rejectOnAbort = true, schedulerOptions = {}) {
  const requests = [];
  const fetchStub = (requestPath, options) => {
    const d = deferred();
    const request = { path: requestPath, options, ...d };
    requests.push(request);
    if (options && options.signal) {
      options.signal.onabort = () => {
        if (rejectOnAbort) {
          const err = new Error('aborted');
          err.name = 'AbortError';
          d.reject(err);
        }
      };
    }
    return d.promise;
  };
  const scheduler = createScheduler(Object.assign({
    fetch: fetchStub,
    now: clock.now,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    AbortController: TestAbortController
  }, schedulerOptions));
  return { clock, requests, scheduler };
}

function createScheduler(options) {
  const context = { AbortController: TestAbortController };
  vm.runInNewContext(schedulerSource, context, { filename: appPath });
  return context.createFetchJSONScheduler(options);
}

async function flush() {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
}

async function testSlowPollDeduplication() {
  const h = makeHarness();
  let obsoleteCallbacks = 0;
  let latestCallbacks = 0;
  const p = '/api/v1/firewall/timeline?range=30d';
  h.scheduler.enqueue(0, p, () => { obsoleteCallbacks += 1; });
  h.scheduler.enqueue(0, p, () => { latestCallbacks += 1; });
  assert.equal(h.requests.length, 1, 'same seq+path must share one network request');
  assert.equal(h.scheduler.snapshot().active, 1);
  h.requests[0].resolve(response(200, { buckets: [] }));
  await flush();
  assert.equal(obsoleteCallbacks, 0, 'slow-poll dedupe must replace the old callback');
  assert.equal(latestCallbacks, 1, 'only the latest callback may run');
}

async function testConcurrencyLimit() {
  const h = makeHarness(makeClock(), true, { maxConcurrency: 3 });
  for (let i = 0; i < 6; i += 1) h.scheduler.enqueue(0, `/api/v1/resources?i=${i}`, () => {});
  assert.equal(h.requests.length, 3, 'scheduler must start at most three requests');
  assert.equal(h.scheduler.snapshot().active, 3);
  for (let i = 0; i < 3; i += 1) {
    h.requests[i].resolve(response());
    await flush();
    assert(h.requests.length <= 3 + i + 1, 'completion may release only one slot');
  }
  assert.equal(h.requests.length, 6, 'queued requests should drain after slots complete');
  assert.equal(h.scheduler.snapshot().active, 3);
}

async function testProductionConcurrencyDefault() {
  const h = makeHarness();
  for (let i = 0; i < 3; i += 1) h.scheduler.enqueue(0, `/api/v1/resources?default=${i}`, () => {});
  assert.equal(h.requests.length, 2, 'production scheduler default must cap global concurrency at two');
  assert.equal(h.scheduler.snapshot().active, 2);
  h.requests[0].resolve(response());
  await flush();
  assert.equal(h.requests.length, 3, 'default two-slot queue must drain after settlement');
}

async function testSequenceCancellationAndReplacement() {
  const h = makeHarness();
  let oldSuccess = 0;
  let oldFailure = 0;
  let freshSuccess = 0;
  h.scheduler.enqueue(0, '/api/v1/resources?range=24h', () => { oldSuccess += 1; }, () => { oldFailure += 1; });
  const oldRequest = h.requests[0];
  h.scheduler.invalidate(1);
  assert.equal(oldRequest.options.signal.aborted, true, 'sequence change must abort in-flight work');
  h.scheduler.enqueue(1, oldRequest.path, () => { freshSuccess += 1; });
  assert.equal(h.requests.length, 2, 'new sequence must be allowed to replace cancelled work');
  h.requests[1].resolve(response());
  await flush();
  assert.equal(freshSuccess, 1);
  assert.equal(oldSuccess, 0);
  assert.equal(oldFailure, 0, 'Abort must not invoke a real failure callback');
}

async function testStaleFinallyDoesNotReleaseFreshTask() {
  const h = makeHarness(makeClock(), false);
  h.scheduler.enqueue(0, '/api/v1/resources?same=true', () => {});
  const oldRequest = h.requests[0];
  h.scheduler.invalidate(1);
  h.scheduler.enqueue(1, oldRequest.path, () => {});
  assert.equal(h.scheduler.snapshot().active, 2, 'without abort settlement, the old slot must remain counted');
  oldRequest.resolve(response());
  await flush();
  assert.equal(h.scheduler.snapshot().active, 1, 'stale finally must not release the fresh request slot');
  h.requests[1].resolve(response());
  await flush();
}

async function test429CooldownAndRecovery() {
  const h = makeHarness(makeClock(), true, { maxConcurrency: 3 });
  h.scheduler.enqueue(0, '/api/v1/summary?range=24h', () => {}, () => {});
  h.scheduler.enqueue(0, '/api/v1/resources?i=1', () => {});
  h.scheduler.enqueue(0, '/api/v1/resources?i=2', () => {});
  h.scheduler.enqueue(0, '/api/v1/resources?i=queued', () => {});
  assert.equal(h.requests.length, 3);
  h.requests[0].resolve(response(429, {}, '2'));
  await flush();
  assert.equal(h.requests.length, 3, '429 must not trigger a busy retry');
  h.clock.advance(1999);
  assert.equal(h.requests.length, 3, 'global cooldown must cover queued requests');
  h.clock.advance(1);
  assert.equal(h.requests.length, 4, 'queue must recover when Retry-After expires');
  assert.equal(h.requests[3].path, '/api/v1/resources?i=queued');
}

async function testRealErrorCallback() {
  const h = makeHarness();
  let failures = 0;
  let successes = 0;
  h.scheduler.enqueue(0, '/api/v1/resources?error=true', () => { successes += 1; }, () => { failures += 1; });
  h.requests[0].reject(new Error('network down'));
  await flush();
  assert.equal(failures, 1);
  assert.equal(successes, 0);
}

async function testErrorIterationRecovery() {
  const h = makeHarness();
  let failures = 0;
  let successes = 0;
  const p = '/api/v1/summary?range=24h';
  h.scheduler.enqueue(0, p, () => {}, () => { failures += 1; });
  h.requests[0].reject(new Error('temporary failure'));
  await flush();
  assert.equal(failures, 1);
  assert.equal(h.scheduler.snapshot().active, 0, 'real errors must release their active slot');
  h.clock.advance(1000); // summary is heavy and retains the global 1s start gap.
  h.scheduler.enqueue(0, p, () => { successes += 1; });
  assert.equal(h.requests.length, 2, 'failed tasks must be removed from the dedupe index');
  h.requests[1].resolve(response());
  await flush();
  assert.equal(successes, 1, 'a later poll must recover after a real error');
}

async function testInvalidationDoesNotFakeReleaseSlots() {
  const h = makeHarness(makeClock(), true, { maxConcurrency: 3 });
  for (let i = 0; i < 3; i += 1) h.scheduler.enqueue(0, `/api/v1/resources?old=${i}`, () => {});
  assert.equal(h.scheduler.snapshot().active, 3);
  h.scheduler.invalidate(1);
  h.scheduler.enqueue(1, '/api/v1/resources?fresh=true', () => {});
  assert.equal(h.requests.length, 3, 'new work must wait until aborted promises settle');
  await flush();
  assert.equal(h.requests.length, 4, 'Abort settlement then releases the old slots');
}

async function testTimeoutIncludesJsonAndNoAbortFallback() {
  const clock = makeClock();
  const h = makeHarness(clock, false, { AbortController: null, requestTimeoutMs: 50, maxConcurrency: 3 });
  let failures = 0;
  const json = deferred();
  h.scheduler.enqueue(0, '/api/v1/resources?json=slow', () => {}, () => { failures += 1; });
  h.scheduler.enqueue(0, '/api/v1/resources?pending=1', () => {}, () => { failures += 1; });
  h.scheduler.enqueue(0, '/api/v1/resources?pending=2', () => {}, () => { failures += 1; });
  h.requests[0].resolve({ ok: true, status: 200, headers: { get: () => '' }, json: () => json.promise });
  await flush();
  clock.advance(49);
  assert.equal(failures, 0, 'timeout must include the pending json read window');
  clock.advance(1);
  assert.equal(failures, 3, 'timeout is a real failure even without AbortController');
  assert.equal(h.scheduler.snapshot().active, 3, 'timeout must not fake-release non-abortable slots');
  h.scheduler.enqueue(0, '/api/v1/resources?queued=true', () => {});
  assert.equal(h.requests.length, 3, 'queued work must respect the true active count');
  json.resolve({});
  await flush();
  assert.equal(h.requests.length, 4, 'settling the timed-out json read releases one slot');
  assert.equal(h.scheduler.snapshot().active, 3);
  h.requests[1].resolve(response());
  h.requests[2].resolve(response());
  h.requests[3].resolve(response());
  await flush();
}

async function testHeavyThrottle() {
  const h = makeHarness();
  const starts = [];
  h.scheduler.enqueue(0, '/api/v1/summary?range=24h', () => {});
  starts.push({ path: h.requests[0].path, at: h.clock.now() });
  h.scheduler.enqueue(0, '/api/v1/ssh/timeline?range=24h', () => {});
  h.scheduler.enqueue(0, '/api/v1/resources?range=1h', () => {});
  assert.equal(h.requests.length, 2, 'non-heavy work may use a free slot while heavy work waits');
  h.requests[1].resolve(response());
  await flush();
  h.clock.advance(999);
  assert.equal(h.requests.length, 2, 'heavy requests must be separated by one second');
  h.clock.advance(1);
  starts.push({ path: h.requests[2].path, at: h.clock.now() });
  assert.equal(h.requests.length, 3);
  assert.deepEqual(starts.map((item) => item.at), [0, 1000]);
}

async function main() {
  await testSlowPollDeduplication();
  await testConcurrencyLimit();
  await testProductionConcurrencyDefault();
  await testSequenceCancellationAndReplacement();
  await testStaleFinallyDoesNotReleaseFreshTask();
  await test429CooldownAndRecovery();
  await testRealErrorCallback();
  await testErrorIterationRecovery();
  await testInvalidationDoesNotFakeReleaseSlots();
  await testTimeoutIncludesJsonAndNoAbortFallback();
  await testHeavyThrottle();
  assert.match(appSource, /if \(state\.activePanel === 'export'\) \{ return; \}/);
  assert.match(appSource, /fetch\('\/api\/v1\/export\/csv\?' \+ params\)/);
  assert.equal((appSource.match(/state\.reqSeq\+\+/g) || []).length, 1, 'all sequence increments must use the aborting helper');
  assert.equal((appSource.match(/nextReqSeq\(\);/g) || []).length, 5, 'all five sequence-change entry points must invalidate requests');
  assert.equal((appSource.match(/pollAttack\(\);/g) || []).length, 5, 'pollAttack entry points must remain covered by the scheduler');
  assert.match(appSource, /var minGap = \(state\.range === '7d' \|\| state\.range === '30d'\) \? 30000 : 5000;/);
  assert.match(appSource, /var FETCH_JSON_MAX_CONCURRENCY = 2;/);
  console.log('request scheduler tests: 11 passed');
}

main().catch((err) => { console.error(err.stack || err); process.exitCode = 1; });
