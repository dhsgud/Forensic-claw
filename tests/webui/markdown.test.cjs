const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const path = require('node:path');

// Run the actual pure renderer without mounting the browser entry point.
const source = readFileSync(path.join(__dirname, '../../forensic_claw/webui/static/app.js'), 'utf8');
const renderer = vm.createContext({ URL, window: { location: { origin: 'http://localhost' } } });
vm.runInContext(source.slice(source.indexOf('function escapeHtml('), source.indexOf('function renderPlainText(')), renderer);

test('report metadata renders as an accessible table without swallowing adjacent paragraphs', () => {
  const html = renderer.renderMarkdown('설명\n\n| 항목 | 내용 |\n| --- | --- |\n| 사건명 | 조사 |\n\n다음 설명');
  assert.ok(html.startsWith('<p>설명</p>'));
  assert.ok(html.includes('<th scope="col">항목</th>'));
  assert.ok(html.includes('<td>조사</td>'));
  assert.ok(html.endsWith('<p>다음 설명</p>'));
});

test('escaped separators and untrusted HTML remain literal table contents', () => {
  const html = renderer.renderMarkdown('| 값 | 내용 |\n| --- | --- |\n| a\\|b | <script>alert(1)</script> |');
  assert.ok(html.includes('<td>a|b</td>'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!html.includes('<script>'));
});

test('table-shaped text inside a code block stays code', () => {
  const html = renderer.renderMarkdown('```\n| A | B |\n| --- | --- |\n```');
  assert.ok(html.startsWith('<pre'));
  assert.ok(!html.includes('<table>'));
});
