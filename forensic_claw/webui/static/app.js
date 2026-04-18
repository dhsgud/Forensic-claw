const state = {
  sessionId: null,
  activeSessionKey: null,
  socket: null,
  streamNodes: new Map(),
  pendingAssistant: null,
  isComposing: false,
  sessions: [],
  cases: [],
  commands: [],
  activeCase: null,
  activeWikiNoteId: null,
  shellTraces: [],
  shellTraceMap: new Map(),
  slashSelection: 0,
  isResettingSession: false,
};

const sessionBadge = document.querySelector("#session-badge");
const sessionMeta = document.querySelector("#session-meta");
const scopeSummary = document.querySelector("#scope-summary");
const activeScope = document.querySelector("#active-scope");
const activeSessionTitle = document.querySelector("#active-session-title");
const connectionStatus = document.querySelector("#connection-status");
const statusLine = document.querySelector("#status-line");
const slashMenu = document.querySelector("#slash-menu");
const sessionsList = document.querySelector("#sessions-list");
const casesList = document.querySelector("#cases-list");
const chatLog = document.querySelector("#chat-log");
const composer = document.querySelector("#composer");
const messageInput = document.querySelector("#message-input");
const sendButton = document.querySelector("#send-button");
const caseIdInput = document.querySelector("#case-id");
const artifactIdInput = document.querySelector("#artifact-id");
const caseSuggestions = document.querySelector("#case-suggestions");
const artifactSuggestions = document.querySelector("#artifact-suggestions");
const caseDetail = document.querySelector("#case-detail");
const artifactDetail = document.querySelector("#artifact-detail");
const caseSummary = document.querySelector("#case-summary");
const caseDetailStatus = document.querySelector("#case-detail-status");
const shellTraceCount = document.querySelector("#shell-trace-count");
const shellTraceSummary = document.querySelector("#shell-trace-summary");
const shellTraceList = document.querySelector("#shell-trace-list");
const wikiSummary = document.querySelector("#wiki-summary");
const wikiList = document.querySelector("#wiki-list");
const wikiPreview = document.querySelector("#wiki-preview");

function currentScope() {
  const caseId = caseIdInput.value.trim();
  const artifactId = artifactIdInput.value.trim();
  return { caseId, artifactId };
}

function scopeLabel({ caseId, artifactId }) {
  if (caseId && artifactId) return `${caseId} / ${artifactId}`;
  if (caseId) return caseId;
  if (artifactId) return artifactId;
  return "base";
}

function escapeHtml(text) {
  return String(text || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function setStatus(text) {
  statusLine.textContent = text;
}

function setConnection(online) {
  connectionStatus.textContent = online ? "online" : "offline";
  connectionStatus.classList.toggle("online", online);
}

function setEmpty(container, text) {
  container.innerHTML = `<div class="empty-state">${escapeHtml(text)}</div>`;
}

function setMessageMeta(node, text) {
  node.querySelector(".message-meta").textContent = text;
}

function setMessageContent(node, text) {
  node.querySelector(".message-content").textContent = text;
}

function messageContentText(node) {
  return node.querySelector(".message-content").textContent || "";
}

function hasVisibleAnswerContent(node) {
  const current = messageContentText(node).trim();
  return Boolean(current) && current !== "답변중..." && current !== "답변을 준비하는 중입니다...";
}

function ensureWaitingContent(node) {
  if (!hasVisibleAnswerContent(node)) {
    setMessageContent(node, "답변을 준비하는 중입니다...");
  }
}

function appendMessageContent(node, text) {
  const contentNode = node.querySelector(".message-content");
  const current = contentNode.textContent || "";
  const placeholder = current === "답변중..." || current === "답변을 준비하는 중입니다...";
  contentNode.textContent = placeholder ? text : current + text;
}

function ensureThinkingSection(node, initialText = "생각 중...") {
  let details = node.querySelector(".message-thinking");
  if (!details) {
    details = document.createElement("details");
    details.className = "message-thinking";
    const summary = document.createElement("summary");
    summary.textContent = "Thinking";
    const thought = document.createElement("pre");
    thought.className = "thinking-content";
    details.appendChild(summary);
    details.appendChild(thought);
    node.insertBefore(details, node.querySelector(".message-content"));
  }

  const thoughtNode = details.querySelector(".thinking-content");
  if (!thoughtNode.textContent) {
    thoughtNode.textContent = initialText;
  }

  return { details, thoughtNode };
}

function setThinkingText(node, text, { append = false, separator = "" } = {}) {
  if (!text) return;
  const { thoughtNode } = ensureThinkingSection(node, text);
  if (!append) {
    thoughtNode.textContent = text;
    return;
  }

  const current = thoughtNode.textContent || "";
  const normalized = current.trim();
  if (!normalized || normalized === "생각 중...") {
    thoughtNode.textContent = text;
    return;
  }
  if (current.endsWith(text)) {
    return;
  }
  thoughtNode.textContent = `${current}${separator}${text}`;
}

function finalizeAssistantNode(node) {
  node.classList.remove("pending");
  node.classList.remove("streaming");
}

function createPendingAssistantNode() {
  const node = makeMessage(
    "assistant",
    "답변중...",
    "assistant",
    "pending",
    { thinkingText: "생각 중..." }
  );
  state.pendingAssistant = node;
  return node;
}

function resolveAssistantNode({ replaceStreamId = "", createIfMissing = true, claimPending = true } = {}) {
  if (replaceStreamId && state.streamNodes.has(replaceStreamId)) {
    const node = state.streamNodes.get(replaceStreamId);
    state.streamNodes.delete(replaceStreamId);
    if (state.pendingAssistant === node) {
      state.pendingAssistant = null;
    }
    return node;
  }
  if (state.pendingAssistant) {
    const node = state.pendingAssistant;
    if (claimPending) {
      state.pendingAssistant = null;
    }
    return node;
  }
  return createIfMissing ? createPendingAssistantNode() : null;
}

function currentCommandMatches() {
  const value = messageInput.value.trimStart();
  if (!value.startsWith("/")) {
    return [];
  }
  const query = value.toLowerCase();
  return state.commands.filter((item) => item.command.toLowerCase().startsWith(query));
}

function closeSlashMenu() {
  slashMenu.hidden = true;
  slashMenu.innerHTML = "";
  state.slashSelection = 0;
}

function applySlashCommand(command) {
  messageInput.value = `${command} `;
  closeSlashMenu();
  messageInput.focus();
}

function renderSlashMenu() {
  const matches = currentCommandMatches();
  if (!matches.length) {
    closeSlashMenu();
    return;
  }

  if (state.slashSelection >= matches.length) {
    state.slashSelection = 0;
  }

  slashMenu.hidden = false;
  slashMenu.innerHTML = "";
  for (const [index, item] of matches.entries()) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "slash-item";
    if (index === state.slashSelection) {
      button.classList.add("active");
    }
    button.innerHTML = `
      <strong>${escapeHtml(item.command)}</strong>
      <small>${escapeHtml(item.description)}</small>
    `;
    button.addEventListener("click", () => applySlashCommand(item.command));
    slashMenu.appendChild(button);
  }
}

function summarizeToolContent(content) {
  const text = String(content || "");
  const lines = text.split(/\r?\n/);
  const nonEmpty = lines.map((line) => line.trim()).filter(Boolean);
  const first = nonEmpty[0] || "Tool output";
  const previewLine = nonEmpty.find((line) => line !== first) || "";
  const title =
    first === "Windows Event Log Summary"
      ? "Windows Event Log Summary"
      : first.length > 72
        ? `${first.slice(0, 69)}...`
        : first;
  const preview =
    previewLine.length > 120 ? `${previewLine.slice(0, 117)}...` : previewLine;
  return { title, preview, lineCount: lines.length };
}

function decorateToolMessage(node, content) {
  node.classList.add("tool");
  const summaryInfo = summarizeToolContent(content);
  const contentNode = node.querySelector(".message-content");
  const details = document.createElement("details");
  details.className = "tool-output";

  const summary = document.createElement("summary");
  summary.innerHTML = `
    <strong>${escapeHtml(summaryInfo.title)}</strong>
    <small>${escapeHtml(`${summaryInfo.lineCount} lines${summaryInfo.preview ? ` · ${summaryInfo.preview}` : ""}`)}</small>
  `;

  const raw = document.createElement("pre");
  raw.className = "message-content tool-content";
  raw.textContent = content;

  details.appendChild(summary);
  details.appendChild(raw);
  contentNode.replaceWith(details);
}

function makeMessage(role, content, metaText = "", extraClass = "", options = {}) {
  const template = document.querySelector("#message-template");
  const node = template.content.firstElementChild.cloneNode(true);
  node.classList.add(role);
  if (extraClass) node.classList.add(extraClass);
  node.querySelector(".message-meta").textContent = metaText || role;
  node.querySelector(".message-content").textContent = content;

  if (options.thinkingText) {
    setThinkingText(node, options.thinkingText);
  }

  if (role === "tool") {
    decorateToolMessage(node, content);
  }

  chatLog.appendChild(node);
  chatLog.scrollTop = chatLog.scrollHeight;
  return node;
}

function setCaseDetailStatus(text, tone = "") {
  caseDetailStatus.textContent = text;
  caseDetailStatus.className = "badge";
  if (tone) {
    caseDetailStatus.classList.add(tone);
  }
}

function updateScopeSummary() {
  const scope = currentScope();
  const label = scopeLabel(scope);
  scopeSummary.textContent =
    label === "base"
      ? "기본 브라우저 세션에 연결됩니다."
      : `현재 scope: ${label}`;
  activeScope.textContent = label;
}

function parseSessionScope(sessionKey) {
  if (!sessionKey) {
    return { caseId: "", artifactId: "" };
  }
  const caseMatch = sessionKey.match(/:case:([^:]+)(?::artifact:[^:]+)?$/);
  const artifactMatch = sessionKey.match(/:artifact:([^:]+)$/);
  return {
    caseId: caseMatch ? caseMatch[1] : "",
    artifactId: artifactMatch ? artifactMatch[1] : "",
  };
}

function formatTraceTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString("ko-KR", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function summarizeCommand(command) {
  const text = String(command || "").trim().replace(/\s+/g, " ");
  if (!text) return "(empty command)";
  return text.length > 88 ? `${text.slice(0, 85)}...` : text;
}

function shellTraceStatusLabel(status) {
  switch (status) {
    case "running":
      return "running";
    case "completed":
      return "completed";
    case "timed_out":
      return "timed out";
    case "blocked":
      return "blocked";
    case "error":
      return "error";
    default:
      return status || "pending";
  }
}

function renderShellTraces() {
  shellTraceCount.textContent = String(state.shellTraces.length);
  shellTraceSummary.textContent =
    state.shellTraces.length > 0
      ? `현재 브라우저 세션에서 ${state.shellTraces.length}개의 shell 실행 로그를 추적 중입니다.`
      : "LLM이 실행한 shell command를 실시간으로 보여줍니다.";

  shellTraceList.innerHTML = "";
  if (!state.shellTraces.length) {
    setEmpty(shellTraceList, "아직 shell 실행 로그가 없습니다.");
    return;
  }

  for (const trace of state.shellTraces) {
    const scope = scopeLabel(parseSessionScope(trace.sessionKey || ""));
    const traceStatus = trace.status || "pending";
    const item = document.createElement("details");
    item.className = "trace-entry";
    if (trace.status === "running") {
      item.open = true;
    }

    const summary = document.createElement("summary");
    summary.innerHTML = `
      <span class="trace-summary-row">
        <strong class="trace-command">${escapeHtml(summarizeCommand(trace.command))}</strong>
        <span class="trace-pill ${traceStatus}">${escapeHtml(shellTraceStatusLabel(trace.status))}</span>
      </span>
      <small class="trace-summary-meta">${escapeHtml([scope, trace.shell, formatTraceTime(trace.lastUpdatedAt || trace.startedAt)].filter(Boolean).join(" · "))}</small>
    `;
    item.appendChild(summary);

    const body = document.createElement("div");
    body.className = "trace-body";

    const meta = document.createElement("div");
    meta.className = "trace-meta-grid";
    const rows = [
      ["Scope", scope],
      ["Shell", trace.shellPath || trace.shell || ""],
      ["Working Dir", trace.workingDir || ""],
      ["Timeout", trace.timeout != null ? `${trace.timeout}s` : ""],
      ["Exit Code", trace.exitCode != null ? String(trace.exitCode) : ""],
      ["Duration", trace.durationMs != null ? `${trace.durationMs} ms` : ""],
      ["Updated", trace.lastUpdatedAt || trace.endedAt || trace.startedAt || ""],
    ].filter(([, value]) => value);
    for (const [label, value] of rows) {
      const row = document.createElement("div");
      row.className = "trace-meta-row";
      row.innerHTML = `
        <span>${escapeHtml(label)}</span>
        <code>${escapeHtml(String(value))}</code>
      `;
      meta.appendChild(row);
    }
    body.appendChild(meta);

    if (trace.summary) {
      const summaryBlock = document.createElement("p");
      summaryBlock.className = "trace-note";
      summaryBlock.textContent = trace.summary;
      body.appendChild(summaryBlock);
    }

    const commandBlock = document.createElement("pre");
    commandBlock.className = "detail-block trace-block";
    commandBlock.textContent = trace.command || "";
    body.appendChild(commandBlock);

    if (trace.launcher) {
      const launcherLabel = document.createElement("p");
      launcherLabel.className = "trace-label";
      launcherLabel.textContent = "Launcher";
      body.appendChild(launcherLabel);

      const launcherBlock = document.createElement("pre");
      launcherBlock.className = "detail-block trace-block";
      launcherBlock.textContent = trace.launcher;
      body.appendChild(launcherBlock);
    }

    if (trace.wrapper) {
      const wrapper = document.createElement("p");
      wrapper.className = "trace-note subtle";
      wrapper.textContent = trace.wrapper;
      body.appendChild(wrapper);
    }

    item.appendChild(body);
    shellTraceList.appendChild(item);
  }
}

function ingestShellTrace(event) {
  const incoming = event.trace || {};
  const storageKey = `${event.sessionKey || "base"}::${incoming.traceId || event.timestamp || Math.random()}`;
  let trace = state.shellTraceMap.get(storageKey);
  if (!trace) {
    trace = {
      key: storageKey,
      sessionKey: event.sessionKey || "",
      startedAt: incoming.phase === "start" ? event.timestamp : "",
      endedAt: "",
      lastUpdatedAt: event.timestamp || "",
    };
    state.shellTraceMap.set(storageKey, trace);
    state.shellTraces.unshift(trace);
  }

  Object.assign(trace, incoming);
  trace.sessionKey = event.sessionKey || trace.sessionKey || "";
  trace.lastUpdatedAt = event.timestamp || trace.lastUpdatedAt || "";
  if (incoming.phase === "start" && !trace.startedAt) {
    trace.startedAt = event.timestamp || trace.startedAt;
  }
  if (incoming.phase === "end") {
    trace.endedAt = event.timestamp || trace.endedAt;
  }

  state.shellTraces.sort((a, b) => String(b.lastUpdatedAt || "").localeCompare(String(a.lastUpdatedAt || "")));
  if (state.shellTraces.length > 120) {
    for (const stale of state.shellTraces.splice(120)) {
      state.shellTraceMap.delete(stale.key);
    }
  }
  renderShellTraces();
}

function refreshSuggestionLists() {
  const caseIds = new Set();
  for (const item of state.cases) {
    if (item.id) caseIds.add(item.id);
  }
  for (const session of state.sessions) {
    if (session.caseId) caseIds.add(session.caseId);
  }

  caseSuggestions.innerHTML = "";
  for (const caseId of [...caseIds].sort()) {
    const option = document.createElement("option");
    option.value = caseId;
    caseSuggestions.appendChild(option);
  }

  const artifactIds = new Set();
  if (state.activeCase) {
    for (const item of state.activeCase.evidenceIds || []) artifactIds.add(item);
    for (const item of state.activeCase.sourceIds || []) artifactIds.add(item);
  }
  for (const session of state.sessions) {
    const sameCase = !caseIdInput.value.trim() || caseIdInput.value.trim() === session.caseId;
    if (sameCase && session.artifactId) artifactIds.add(session.artifactId);
  }

  artifactSuggestions.innerHTML = "";
  for (const artifactId of [...artifactIds].sort()) {
    const option = document.createElement("option");
    option.value = artifactId;
    artifactSuggestions.appendChild(option);
  }
}

async function apiJson(url, options = {}) {
  const response = await fetch(url, options);
  let data = {};
  try {
    data = await response.json();
  } catch (_error) {
    data = {};
  }
  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

async function apiJsonOptional(url) {
  const response = await fetch(url);
  if (!response.ok) {
    return null;
  }
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

function renderCases() {
  casesList.innerHTML = "";
  if (!state.cases.length) {
    setEmpty(casesList, "아직 case 폴더가 없습니다.");
    return;
  }

  for (const item of state.cases) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "session-item";
    if (state.activeCase && state.activeCase.id === item.id) {
      button.classList.add("active");
    }
    button.innerHTML = `
      <strong>${escapeHtml(item.title || item.id)}</strong>
      <small>${escapeHtml(item.id)}</small>
      <small>${escapeHtml(item.summary || "요약 없음")}</small>
      <small>${escapeHtml(`evidence ${item.evidenceCount || 0} · source ${item.sourceCount || 0}`)}</small>
    `;
    button.addEventListener("click", () => selectCase(item.id));
    casesList.appendChild(button);
  }
}

function renderCaseDetail(caseData, reportContent = "", graph = null) {
  state.activeCase = caseData;
  refreshSuggestionLists();
  renderCases();

  caseSummary.textContent =
    caseData.summary || `${caseData.id} case를 읽었습니다. evidence ${caseData.evidenceIds.length}개, source ${caseData.sourceIds.length}개`;
  caseDetail.innerHTML = "";

  const headerCard = document.createElement("section");
  headerCard.className = "detail-card";
  headerCard.innerHTML = `
    <h3>${escapeHtml(caseData.title || caseData.id)}</h3>
    <p class="detail-meta">${escapeHtml(caseData.id)} · ${escapeHtml(caseData.status || "draft")}</p>
    <pre class="detail-block">${escapeHtml(JSON.stringify(caseData.manifest || {}, null, 2))}</pre>
  `;
  caseDetail.appendChild(headerCard);

  const evidenceCard = document.createElement("section");
  evidenceCard.className = "detail-card";
  evidenceCard.innerHTML = '<h3>Evidence</h3><div class="token-row"></div>';
  const evidenceRow = evidenceCard.querySelector(".token-row");
  if ((caseData.evidenceIds || []).length) {
    for (const evidenceId of caseData.evidenceIds) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "token-button";
      if (artifactIdInput.value.trim() === evidenceId) {
        button.classList.add("active");
      }
      button.textContent = evidenceId;
      button.addEventListener("click", () => selectArtifact(evidenceId));
      evidenceRow.appendChild(button);
    }
  } else {
    evidenceRow.innerHTML = '<span class="subtle">등록된 evidence가 없습니다.</span>';
  }
  caseDetail.appendChild(evidenceCard);

  const sourceCard = document.createElement("section");
  sourceCard.className = "detail-card";
  sourceCard.innerHTML = '<h3>Sources</h3><div class="token-row"></div>';
  const sourceRow = sourceCard.querySelector(".token-row");
  if ((caseData.sourceIds || []).length) {
    for (const sourceId of caseData.sourceIds) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "token-button";
      if (artifactIdInput.value.trim() === sourceId) {
        button.classList.add("active");
      }
      button.textContent = sourceId;
      button.addEventListener("click", () => selectArtifact(sourceId));
      sourceRow.appendChild(button);
    }
  } else {
    sourceRow.innerHTML = '<span class="subtle">등록된 source가 없습니다.</span>';
  }
  caseDetail.appendChild(sourceCard);

  if (reportContent) {
    const reportCard = document.createElement("section");
    reportCard.className = "detail-card";
    reportCard.innerHTML = `
      <h3>Report</h3>
      <pre class="detail-block">${escapeHtml(reportContent)}</pre>
    `;
    caseDetail.appendChild(reportCard);
  }

  if (graph) {
    const graphCard = document.createElement("section");
    graphCard.className = "detail-card";
    graphCard.innerHTML = `
      <h3>Graph</h3>
      <pre class="detail-block">${escapeHtml(JSON.stringify(graph, null, 2))}</pre>
    `;
    caseDetail.appendChild(graphCard);
  }
}

function clearCaseDetail(message = "선택된 case가 없습니다.") {
  state.activeCase = null;
  caseSummary.textContent = message;
  caseDetail.innerHTML = "";
  artifactDetail.innerHTML = "";
  setCaseDetailStatus("idle");
  renderCases();
  refreshSuggestionLists();
}

function renderArtifactDetail(kind, detail) {
  artifactDetail.innerHTML = "";

  const card = document.createElement("section");
  card.className = "detail-card";
  card.innerHTML = `
    <h3>${escapeHtml(kind === "source" ? "Selected Source" : "Selected Evidence")}</h3>
    <p class="detail-meta">${escapeHtml(kind === "source" ? detail.sourceId : detail.evidenceId)}</p>
    <pre class="detail-block">${escapeHtml(JSON.stringify(detail.metadata || {}, null, 2))}</pre>
  `;
  artifactDetail.appendChild(card);

  const filesCard = document.createElement("section");
  filesCard.className = "detail-card";
  filesCard.innerHTML = '<h3>Files</h3><div class="file-list"></div>';
  const fileList = filesCard.querySelector(".file-list");
  if ((detail.files || []).length) {
    for (const filePath of detail.files) {
      const row = document.createElement("code");
      row.className = "file-chip";
      row.textContent = filePath;
      fileList.appendChild(row);
    }
  } else {
    fileList.innerHTML = '<span class="subtle">관련 파일이 없습니다.</span>';
  }
  artifactDetail.appendChild(filesCard);
}

function renderWikiList(notes) {
  wikiList.innerHTML = "";
  if (!notes.length) {
    setEmpty(wikiList, "현재 scope에 저장된 wiki note가 없습니다.");
    wikiPreview.innerHTML =
      '<div class="empty-state">저장된 wiki note를 선택하면 여기서 본문을 볼 수 있습니다.</div>';
    return;
  }

  for (const note of notes) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "session-item note-item";
    if (note.id === state.activeWikiNoteId) {
      button.classList.add("active");
    }
    button.innerHTML = `
      <strong>${escapeHtml(note.title || note.relativePath)}</strong>
      <small>${escapeHtml(note.summary || "(empty)")}</small>
      <small>${escapeHtml(note.createdAt || "")}</small>
    `;
    button.addEventListener("click", () => loadWikiNote(note.id));
    wikiList.appendChild(button);
  }
}

function renderWikiNote(note) {
  wikiPreview.innerHTML = `
    <h3>${escapeHtml(note.title || "Untitled")}</h3>
    <p class="detail-meta">${escapeHtml(note.metadata?.created_at || "")}</p>
    <pre class="detail-block">${escapeHtml(note.content || "")}</pre>
  `;
}

function resetUiForFreshBrowserSession() {
  state.activeSessionKey = null;
  state.pendingAssistant = null;
  state.streamNodes.clear();
  state.activeWikiNoteId = null;
  chatLog.innerHTML = "";
  caseIdInput.value = "";
  artifactIdInput.value = "";
  activeSessionTitle.textContent = "새 브라우저 세션";
  clearCaseDetail();
  updateScopeSummary();
  wikiSummary.textContent = "새 WebUI 세션입니다.";
  wikiList.innerHTML = "";
  wikiPreview.innerHTML =
    '<div class="empty-state">저장된 wiki note를 선택하면 여기서 본문을 볼 수 있습니다.</div>';
}

async function bootstrap({ reset = false } = {}) {
  const data = await apiJson(reset ? "/api/bootstrap?reset=1" : "/api/bootstrap");
  state.sessionId = data.sessionId;
  state.commands = data.commands || [];
  state.shellTraces = [];
  state.shellTraceMap = new Map();
  if (reset) {
    resetUiForFreshBrowserSession();
  }
  for (const event of data.shellTraces || []) {
    ingestShellTrace(event);
  }
  renderShellTraces();
  sessionBadge.textContent = data.sessionId;
  sessionMeta.textContent = `브라우저 세션 ${data.sessionId}`;
  updateScopeSummary();
  await connectSocket();
  await Promise.all([refreshSessions(), refreshCases(), refreshWikiNotes()]);
  setStatus(reset ? "새 WebUI 세션을 시작했습니다." : "준비되었습니다.");
}

async function connectSocket() {
  if (state.socket) {
    try {
      state.socket.close();
    } catch (_error) {
      // Ignore stale socket shutdown errors during reconnect.
    }
    state.socket = null;
  }

  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${window.location.host}/ws?sessionId=${encodeURIComponent(state.sessionId)}`;
  state.socket = new WebSocket(wsUrl);

  state.socket.addEventListener("open", () => {
    setConnection(true);
    setStatus("WebSocket 연결 완료");
  });

  state.socket.addEventListener("close", () => {
    setConnection(false);
    if (state.isResettingSession) {
      return;
    }
    setStatus("연결이 끊어졌습니다. 새로고침 후 다시 시도하세요.");
  });

  state.socket.addEventListener("message", (event) => {
    const payload = JSON.parse(event.data);
    handleSocketEvent(payload);
  });
}

async function resetBrowserSession() {
  if (state.isResettingSession) {
    return;
  }

  state.isResettingSession = true;
  setStatus("새 WebUI 세션으로 전환하는 중입니다.");
  try {
    if (state.socket) {
      try {
        state.socket.close();
      } catch (_error) {
        // Ignore reconnect shutdown errors.
      }
      state.socket = null;
    }
    await bootstrap({ reset: true });
  } finally {
    state.isResettingSession = false;
  }
}

function handleSocketEvent(event) {
  if (event.type === "ready") {
    setConnection(true);
    return;
  }

  if (event.sessionId && event.sessionId !== state.sessionId) {
    return;
  }

  if (event.type === "shell_trace") {
    ingestShellTrace(event);
    setStatus(
      event.trace?.phase === "start"
        ? "쉘 명령 실행 로그를 기록했습니다."
        : "쉘 명령 실행 결과가 업데이트되었습니다."
    );
    return;
  }

  if (event.type === "progress" || event.type === "tool_hint") {
    if (!state.activeSessionKey || event.sessionKey === state.activeSessionKey) {
      const node = resolveAssistantNode({ claimPending: false });
      if (node) {
        setMessageMeta(node, "assistant");
        ensureWaitingContent(node);
        if (event.content) {
          setThinkingText(node, event.content, {
            append: true,
            separator: event.type === "tool_hint" ? "\n\n" : "",
          });
        } else {
          setThinkingText(node, event.type === "tool_hint" ? "도구를 준비하는 중입니다." : "생각 중...");
        }
      }
      setStatus(event.type === "tool_hint" ? "도구를 준비하는 중입니다." : "생각하는 중입니다.");
    }
    refreshSessions();
    return;
  }

  if (event.type === "stream_delta") {
    if (event.sessionKey) {
      state.activeSessionKey = event.sessionKey;
      activeSessionTitle.textContent = event.sessionKey;
    }
    let node = state.streamNodes.get(event.streamId);
    if (!node) {
      node = resolveAssistantNode({ claimPending: false });
      if (!node) {
        node = createPendingAssistantNode();
      }
      node.classList.add("streaming");
      setMessageMeta(node, "assistant");
      setMessageContent(node, "");
      state.streamNodes.set(event.streamId, node);
    }
    appendMessageContent(node, event.content || "");
    finalizeAssistantNode(node);
    setStatus("답변을 스트리밍하는 중입니다.");
    chatLog.scrollTop = chatLog.scrollHeight;
    return;
  }

  if (event.type === "stream_end") {
    if (event.resuming) {
      state.streamNodes.delete(event.streamId);
      setStatus("도구 실행 후 답변을 이어가는 중입니다.");
      return;
    }
    setStatus("답변을 마무리하는 중입니다.");
    refreshSessions();
    refreshWikiNotes();
    return;
  }

  if (event.type === "message") {
    if (event.sessionKey) {
      state.activeSessionKey = event.sessionKey;
      activeSessionTitle.textContent = event.sessionKey;
    }
    let node = resolveAssistantNode({ replaceStreamId: event.replaceStreamId || "" });
    if (!node) {
      node = makeMessage(event.role || "assistant", "", event.role || "assistant");
    }
    setMessageMeta(node, event.role || "assistant");
    setMessageContent(node, event.content || "");
    finalizeAssistantNode(node);
    if (event.thinkingText) {
      setThinkingText(node, event.thinkingText);
    }
    if (event.resetBrowserSession) {
      setStatus("새 WebUI 세션으로 전환하는 중입니다.");
      resetBrowserSession().catch((error) => {
        console.error(error);
        setStatus(`세션 초기화 실패: ${error.message}`);
      });
      return;
    }
    setStatus("응답이 완료되었습니다.");
    refreshSessions();
    refreshWikiNotes();
  }
}

async function refreshSessions() {
  if (!state.sessionId) return;

  const data = await apiJson(`/api/sessions?sessionId=${encodeURIComponent(state.sessionId)}`);
  state.sessions = data.sessions || [];
  refreshSuggestionLists();

  sessionsList.innerHTML = "";
  if (!state.sessions.length) {
    setEmpty(sessionsList, "아직 저장된 세션이 없습니다.");
    return;
  }

  for (const session of state.sessions) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "session-item";
    if (session.key === state.activeSessionKey) {
      button.classList.add("active");
    }
    const label = scopeLabel({ caseId: session.caseId || "", artifactId: session.artifactId || "" });
    button.innerHTML = `
      <strong>${escapeHtml(label)}</strong>
      <small>${escapeHtml(session.preview || "(no preview)")}</small>
      <small>${escapeHtml(session.updatedAt || "")}</small>
    `;
    button.addEventListener("click", () => loadSession(session));
    sessionsList.appendChild(button);
  }
}

async function refreshCases() {
  try {
    const data = await apiJson("/api/cases");
    state.cases = data.cases || [];
    renderCases();
    refreshSuggestionLists();

    const selectedCaseId = caseIdInput.value.trim();
    if (selectedCaseId) {
      await loadCase(selectedCaseId, { quiet: true });
    } else if (!state.cases.length) {
      clearCaseDetail("아직 case 폴더가 없습니다.");
    }
  } catch (error) {
    clearCaseDetail("case 목록을 읽지 못했습니다.");
    setStatus(`case 목록 로드 실패: ${error.message}`);
  }
}

async function loadCase(caseId, { quiet = false } = {}) {
  if (!caseId) {
    clearCaseDetail();
    return;
  }

  setCaseDetailStatus("loading");
  try {
    const detail = await apiJson(`/api/cases/${encodeURIComponent(caseId)}`);
    const [reportData, graphData] = await Promise.all([
      apiJsonOptional(`/api/cases/${encodeURIComponent(caseId)}/report`),
      apiJsonOptional(`/api/cases/${encodeURIComponent(caseId)}/graph`),
    ]);

    renderCaseDetail(detail.case, reportData?.content || "", graphData?.graph || null);
    setCaseDetailStatus("loaded", "success");

    const artifactId = artifactIdInput.value.trim();
    if (artifactId) {
      await loadArtifact(caseId, artifactId, detail.case);
    } else {
      artifactDetail.innerHTML = "";
    }
  } catch (error) {
    clearCaseDetail("선택된 case를 읽지 못했습니다.");
    setCaseDetailStatus("missing", "warn");
    if (!quiet) {
      setStatus(`case 로드 실패: ${error.message}`);
    }
  }
}

async function loadArtifact(caseId, artifactId, caseData = state.activeCase) {
  if (!caseId || !artifactId || !caseData) {
    artifactDetail.innerHTML = "";
    return;
  }

  const isEvidence = (caseData.evidenceIds || []).includes(artifactId);
  const isSource = (caseData.sourceIds || []).includes(artifactId);
  if (!isEvidence && !isSource) {
    artifactDetail.innerHTML = "";
    return;
  }

  const kind = isSource ? "source" : "evidence";
  const url =
    kind === "source"
      ? `/api/cases/${encodeURIComponent(caseId)}/sources/${encodeURIComponent(artifactId)}`
      : `/api/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(artifactId)}`;
  try {
    const detail = await apiJson(url);
    renderArtifactDetail(kind, detail);
  } catch (error) {
    artifactDetail.innerHTML = "";
    setStatus(`artifact 로드 실패: ${error.message}`);
  }
}

async function refreshWikiNotes() {
  if (!state.sessionId) return;

  const scope = currentScope();
  const params = new URLSearchParams({ sessionId: state.sessionId });
  if (scope.caseId) params.set("caseId", scope.caseId);
  if (scope.artifactId) params.set("artifactId", scope.artifactId);

  try {
    const data = await apiJson(`/api/wiki?${params.toString()}`);
    const notes = data.notes || [];
    wikiSummary.textContent =
      notes.length > 0
        ? `${scopeLabel(scope)} scope에 ${notes.length}개의 note가 있습니다.`
        : `${scopeLabel(scope)} scope에는 아직 note가 없습니다.`;
    renderWikiList(notes);
    if (notes.length && !notes.some((note) => note.id === state.activeWikiNoteId)) {
      await loadWikiNote(notes[0].id);
    }
    if (!notes.length) {
      state.activeWikiNoteId = null;
    }
  } catch (error) {
    wikiSummary.textContent = "wiki note를 읽지 못했습니다.";
    setEmpty(wikiList, "wiki note를 읽지 못했습니다.");
    wikiPreview.innerHTML = '<div class="empty-state">wiki preview를 불러오지 못했습니다.</div>';
    setStatus(`wiki 로드 실패: ${error.message}`);
  }
}

async function loadWikiNote(noteId) {
  try {
    const data = await apiJson(`/api/wiki/${encodeURIComponent(noteId)}`);
    state.activeWikiNoteId = noteId;
    renderWikiList(await currentWikiNotes());
    renderWikiNote(data.note);
  } catch (error) {
    setStatus(`wiki note 로드 실패: ${error.message}`);
  }
}

async function currentWikiNotes() {
  if (!state.sessionId) return [];
  const scope = currentScope();
  const params = new URLSearchParams({ sessionId: state.sessionId });
  if (scope.caseId) params.set("caseId", scope.caseId);
  if (scope.artifactId) params.set("artifactId", scope.artifactId);
  const data = await apiJson(`/api/wiki?${params.toString()}`);
  return data.notes || [];
}

async function loadSession(session) {
  const data = await apiJson(
    `/api/sessions/${encodeURIComponent(session.key)}?sessionId=${encodeURIComponent(state.sessionId)}`
  );
  if (!data.session) {
    setStatus("세션을 불러오지 못했습니다.");
    return;
  }

  state.activeSessionKey = data.session.key;
  activeSessionTitle.textContent = data.session.key;
  caseIdInput.value = data.session.caseId || "";
  artifactIdInput.value = data.session.artifactId || "";
  updateScopeSummary();

  state.pendingAssistant = null;
  state.streamNodes.clear();
  chatLog.innerHTML = "";
  for (const message of data.session.messages || []) {
    makeMessage(
      message.role || "assistant",
      message.content || "",
      message.role || "message",
      "",
      { thinkingText: message.thinkingText || "" }
    );
  }

  if (data.session.caseId) {
    await loadCase(data.session.caseId, { quiet: true });
  } else {
    clearCaseDetail();
  }
  await refreshWikiNotes();
  await refreshSessions();
}

async function sendMessage(event) {
  event.preventDefault();
  const rawText = messageInput.value;
  const text = rawText.trim();
  if (!text) return;

  const scope = currentScope();
  makeMessage("user", rawText.trim(), "user");
  if (state.pendingAssistant) {
    finalizeAssistantNode(state.pendingAssistant);
    state.pendingAssistant = null;
  }
  createPendingAssistantNode();
  setStatus("생각하는 중입니다.");
  sendButton.disabled = true;

  try {
    const data = await apiJson("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: state.sessionId,
        caseId: scope.caseId || null,
        artifactId: scope.artifactId || null,
        text: rawText,
      }),
    });

    state.activeSessionKey = data.sessionKey;
    activeSessionTitle.textContent = data.sessionKey;
    messageInput.value = "";
    closeSlashMenu();

    if (scope.caseId) {
      await loadCase(scope.caseId, { quiet: true });
    } else {
      clearCaseDetail();
    }

    await Promise.all([refreshSessions(), refreshWikiNotes()]);
  } catch (error) {
    if (state.pendingAssistant) {
      setMessageContent(state.pendingAssistant, `전송 실패: ${error.message}`);
      finalizeAssistantNode(state.pendingAssistant);
      state.pendingAssistant = null;
    }
    setStatus(`전송 실패: ${error.message}`);
  } finally {
    sendButton.disabled = false;
  }
}

async function selectCase(caseId) {
  caseIdInput.value = caseId;
  artifactIdInput.value = "";
  updateScopeSummary();
  await loadCase(caseId);
  await refreshWikiNotes();
}

async function selectArtifact(artifactId) {
  artifactIdInput.value = artifactId;
  updateScopeSummary();
  if (caseIdInput.value.trim()) {
    await loadArtifact(caseIdInput.value.trim(), artifactId);
  }
  await refreshWikiNotes();
}

document.querySelector("#refresh-sessions").addEventListener("click", () => {
  refreshSessions().catch((error) => setStatus(`세션 새로고침 실패: ${error.message}`));
});
document.querySelector("#refresh-cases").addEventListener("click", () => {
  refreshCases().catch((error) => setStatus(`case 새로고침 실패: ${error.message}`));
});
document.querySelector("#refresh-wiki").addEventListener("click", () => {
  refreshWikiNotes().catch((error) => setStatus(`wiki 새로고침 실패: ${error.message}`));
});
document.querySelector("#clear-scope").addEventListener("click", () => {
  caseIdInput.value = "";
  artifactIdInput.value = "";
  updateScopeSummary();
  clearCaseDetail();
  refreshWikiNotes().catch((error) => setStatus(`wiki 새로고침 실패: ${error.message}`));
});

caseIdInput.addEventListener("input", updateScopeSummary);
artifactIdInput.addEventListener("input", updateScopeSummary);
caseIdInput.addEventListener("change", () => {
  const caseId = caseIdInput.value.trim();
  if (!caseId) {
    clearCaseDetail();
    refreshWikiNotes().catch((error) => setStatus(`wiki 새로고침 실패: ${error.message}`));
    return;
  }
  loadCase(caseId)
    .then(() => refreshWikiNotes())
    .catch((error) => setStatus(`scope 반영 실패: ${error.message}`));
});
artifactIdInput.addEventListener("change", () => {
  const caseId = caseIdInput.value.trim();
  const artifactId = artifactIdInput.value.trim();
  if (!artifactId) {
    artifactDetail.innerHTML = "";
    refreshWikiNotes().catch((error) => setStatus(`wiki 새로고침 실패: ${error.message}`));
    return;
  }
  loadArtifact(caseId, artifactId)
    .then(() => refreshWikiNotes())
    .catch((error) => setStatus(`artifact 반영 실패: ${error.message}`));
});

messageInput.addEventListener("compositionstart", () => {
  state.isComposing = true;
});
messageInput.addEventListener("compositionend", () => {
  state.isComposing = false;
});
messageInput.addEventListener("input", () => {
  renderSlashMenu();
});
messageInput.addEventListener("keydown", (event) => {
  const matches = currentCommandMatches();
  if (matches.length) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      state.slashSelection = (state.slashSelection + 1) % matches.length;
      renderSlashMenu();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      state.slashSelection = (state.slashSelection - 1 + matches.length) % matches.length;
      renderSlashMenu();
      return;
    }
    if (event.key === "Tab") {
      event.preventDefault();
      applySlashCommand(matches[state.slashSelection].command);
      return;
    }
  }
  if (event.key !== "Enter" || event.shiftKey || state.isComposing || event.isComposing) {
    return;
  }
  event.preventDefault();
  composer.requestSubmit();
});

composer.addEventListener("submit", (event) => {
  sendMessage(event).catch((error) => {
    console.error(error);
    setStatus(`전송 중 오류: ${error.message}`);
    sendButton.disabled = false;
  });
});

bootstrap().catch((error) => {
  console.error(error);
  setStatus(`초기화 실패: ${error.message}`);
});
