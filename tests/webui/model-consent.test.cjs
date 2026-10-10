const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const path = require('node:path');

const source = readFileSync(path.join(__dirname, '../../forensic_claw/webui/static/app.js'), 'utf8');

function browser(answers, local = false) {
  const visibleWarnings = [];
  let savedModel = 'original';
  const context = vm.createContext({
    window: { confirm(message) { visibleWarnings.push(message); return answers.shift(); } },
    async fetch(_url, options) {
      const payload = JSON.parse(options.body);
      const step = payload.consentToken === 'first' ? 2 : 1;
      const allowed = local || payload.consentToken === 'second';
      if (allowed) savedModel = payload.model;
      const data = allowed ? { modelConfig: { model: savedModel } } : {
        error: 'consent required', confirmation: {
          step, token: step === 1 ? 'first' : 'second', apiBase: payload.apiBase,
          message: step === 1 ? '로컬 모델이 아니어도 사용하시겠습니까?' : '증거가 외부로 전송될 수도 있습니다. 정말 사용하시겠습니까?',
        },
      };
      return { ok: allowed, status: allowed ? 200 : 409, text: async () => JSON.stringify(data) };
    },
  });
  vm.runInContext(source.slice(source.indexOf('async function apiJson('), source.indexOf('async function apiJsonOptional(')), context);
  return { context, visibleWarnings, saved: () => savedModel };
}

test('FAIL displays both warnings before the remote model is saved', async () => {
  const ui = browser([true, true]);
  await ui.context.applyModelWithConsent({ model: 'remote', apiBase: 'https://8.8.8.8/v1' });
  assert.equal(ui.saved(), 'remote');
  assert.equal(ui.visibleWarnings.length, 2);
  assert.match(ui.visibleWarnings[0], /로컬 모델이 아니어도/);
  assert.match(ui.visibleWarnings[1], /증거가 외부로 전송/);
});

test('cancelling either warning preserves the previous model', async () => {
  for (const answers of [[false], [true, false]]) {
    const ui = browser(answers);
    await assert.rejects(ui.context.applyModelWithConsent({ model: 'remote' }), /취소/);
    assert.equal(ui.saved(), 'original');
  }
});

test('PASS saves the local model without warnings', async () => {
  const ui = browser([], true);
  await ui.context.applyModelWithConsent({ model: 'lan-local' });
  assert.equal(ui.saved(), 'lan-local');
  assert.deepEqual(ui.visibleWarnings, []);
});
