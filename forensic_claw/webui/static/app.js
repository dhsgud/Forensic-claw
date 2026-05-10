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
  slashSelection: 0,
  isResettingSession: false,
  isGenerating: false,
  isStopping: false,
  stopRequested: false,
  stopTargetSessionKey: null,
  modelConfig: null,
  isApplyingModel: false,
  knowledgeConfig: null,
  isApplyingKnowledge: false,
  caseProfile: null,
  attachments: [],
  dragDepth: 0,
};

const SETUP_STORAGE_KEY = "forensic_claw_webui_setup_v1";

const setupScreen = document.querySelector("#setup-screen");
const appShell = document.querySelector("#app-shell");
const setupForm = document.querySelector("#setup-form");
const setupCaseName = document.querySelector("#setup-case-name");
const setupInvestigatorName = document.querySelector("#setup-investigator-name");
const setupProvider = document.querySelector("#setup-model-provider");
const setupModelId = document.querySelector("#setup-model-id");
const setupApiBase = document.querySelector("#setup-model-api-base");
const setupNeo4jEnabled = document.querySelector("#setup-neo4j-enabled");
const setupNeo4jUri = document.querySelector("#setup-neo4j-uri");
const setupNeo4jUsername = document.querySelector("#setup-neo4j-username");
const setupNeo4jPassword = document.querySelector("#setup-neo4j-password");
const setupNeo4jDatabase = document.querySelector("#setup-neo4j-database");
const setupTestModel = document.querySelector("#setup-test-model");
const setupTestNeo4j = document.querySelector("#setup-test-neo4j");
const setupStart = document.querySelector("#setup-start");
const setupStatus = document.querySelector("#setup-status");
const sessionBadge = document.querySelector("#session-badge");
const sessionMeta = document.querySelector("#session-meta");
const scopeSummary = document.querySelector("#scope-summary");
const activeScope = document.querySelector("#active-scope");
const activeSessionTitle = document.querySelector("#active-session-title");
const connectionStatus = document.querySelector("#connection-status");
const statusLine = document.querySelector("#status-line");
const dropHint = document.querySelector("#drop-hint");
const attachmentTray = document.querySelector("#attachment-tray");
const slashMenu = document.querySelector("#slash-menu");
const sessionsList = document.querySelector("#sessions-list");
const casesList = document.querySelector("#cases-list");
const chatLog = document.querySelector("#chat-log");
const composerShell = document.querySelector(".composer-shell");
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
const modelStatus = document.querySelector("#model-status");
const modelProvider = document.querySelector("#model-provider");
const modelId = document.querySelector("#model-id");
const modelApiBase = document.querySelector("#model-api-base");
const modelTest = document.querySelector("#model-test");
const modelSave = document.querySelector("#model-save");
const modelSummary = document.querySelector("#model-summary");
const knowledgeStatus = document.querySelector("#knowledge-status");
const knowledgeEnabled = document.querySelector("#knowledge-enabled");
const knowledgeBackend = document.querySelector("#knowledge-backend");
const knowledgeStoreDir = document.querySelector("#knowledge-store-dir");
const helixEnabled = document.querySelector("#helix-enabled");
const helixPort = document.querySelector("#helix-port");
const helixApiEndpoint = document.querySelector("#helix-api-endpoint");
const helixFallback = document.querySelector("#helix-fallback");
const neo4jEnabled = document.querySelector("#neo4j-enabled");
const neo4jUri = document.querySelector("#neo4j-uri");
const neo4jUsername = document.querySelector("#neo4j-username");
const neo4jPassword = document.querySelector("#neo4j-password");
const neo4jDatabase = document.querySelector("#neo4j-database");
const knowledgeTest = document.querySelector("#knowledge-test");
const knowledgeSave = document.querySelector("#knowledge-save");
const knowledgeSummary = document.querySelector("#knowledge-summary");

function currentScope() {
  return { caseId: "", artifactId: "" };
}

function scopeLabel({ caseId, artifactId }) {
  if (caseId && artifactId) return `${caseId} / ${artifactId}`;
  if (caseId) return caseId;
  if (artifactId) return artifactId;
  return "base";
}

function setModelStatus(text, kind = "") {
  if (!modelStatus) return;
  modelStatus.textContent = text;
  modelStatus.classList.toggle("success", kind === "success");
  modelStatus.classList.toggle("warn", kind === "warn");
}

function currentModelForm() {
  return {
    provider: modelProvider?.value || "",
    model: modelId?.value.trim() || "",
    apiBase: modelApiBase?.value.trim() || "",
  };
}

function renderModelConfig(config) {
  state.modelConfig = config || null;
  if (!modelProvider || !modelId || !modelApiBase || !modelSummary) return;
  if (!config) {
    setModelStatus("offline", "warn");
    modelSummary.textContent = "Model settings are unavailable.";
    return;
  }

  const providers = config.availableProviders || [];
  modelProvider.innerHTML = "";
  for (const provider of providers) {
    const option = document.createElement("option");
    option.value = provider.name;
    option.textContent = provider.label || provider.name;
    option.dataset.defaultApiBase = provider.defaultApiBase || "";
    modelProvider.appendChild(option);
  }
  modelProvider.value = config.provider || providers[0]?.name || "";
  modelId.value = config.model || "";
  modelApiBase.value = config.apiBase || "";
  modelSummary.textContent = `${config.providerLabel || config.provider || "provider"} - ${config.model || "model"} - ${config.apiBase || "apiBase unset"}`;
  setModelStatus("ready", "success");
}

function syncDefaultApiBaseFromProvider() {
  if (!modelProvider || !modelApiBase) return;
  const option = modelProvider.selectedOptions[0];
  const current = modelApiBase.value.trim();
  const previous = state.modelConfig?.apiBase || "";
  if ((!current || current === previous) && option?.dataset.defaultApiBase) {
    modelApiBase.value = option.dataset.defaultApiBase;
  }
}

function setKnowledgeStatus(text, kind = "") {
  if (!knowledgeStatus) return;
  knowledgeStatus.textContent = text;
  knowledgeStatus.classList.toggle("success", kind === "success");
  knowledgeStatus.classList.toggle("warn", kind === "warn");
}

function knowledgePayloadFromFields(fields) {
  const payload = {
    enabled: Boolean(fields.knowledgeEnabled?.checked),
    backend: fields.backend?.value || "sqlite",
    storeDir: fields.storeDir?.value.trim() || "knowledge",
    neo4jEnabled: Boolean(fields.neo4jEnabled?.checked),
    uri: fields.uri?.value.trim() || "",
    username: fields.username?.value.trim() || "",
    database: fields.database?.value.trim() || "neo4j",
    helixEnabled: Boolean(fields.helixEnabled?.checked),
    helixLocal: true,
    helixPort: Number(fields.helixPort?.value || 6969),
    helixApiEndpoint: fields.helixApiEndpoint?.value.trim() || "",
    helixFallbackToSqlite: fields.helixFallback?.checked ?? true,
  };
  const password = fields.password?.value || "";
  if (password) {
    payload.password = password;
  }
  return payload;
}

function currentKnowledgeForm() {
  return knowledgePayloadFromFields({
    knowledgeEnabled,
    backend: knowledgeBackend,
    storeDir: knowledgeStoreDir,
    helixEnabled,
    helixPort,
    helixApiEndpoint,
    helixFallback,
    neo4jEnabled,
    uri: neo4jUri,
    username: neo4jUsername,
    password: neo4jPassword,
    database: neo4jDatabase,
  });
}

function setupKnowledgeFormPayload() {
  return knowledgePayloadFromFields({
    knowledgeEnabled: { checked: true },
    backend: { value: state.knowledgeConfig?.backend || "sqlite" },
    storeDir: { value: state.knowledgeConfig?.storeDir || "knowledge" },
    helixEnabled: { checked: Boolean(state.knowledgeConfig?.helix?.enabled) },
    helixPort: { value: state.knowledgeConfig?.helix?.port || 6969 },
    helixApiEndpoint: { value: state.knowledgeConfig?.helix?.apiEndpoint || "" },
    helixFallback: { checked: state.knowledgeConfig?.helix?.fallbackToSqlite ?? true },
    neo4jEnabled: setupNeo4jEnabled,
    uri: setupNeo4jUri,
    username: setupNeo4jUsername,
    password: setupNeo4jPassword,
    database: setupNeo4jDatabase,
  });
}

function renderKnowledgeConfig(config) {
  state.knowledgeConfig = config || null;
  if (!knowledgeEnabled || !knowledgeBackend || !knowledgeStoreDir || !neo4jEnabled || !neo4jUri || !knowledgeSummary) return;
  if (!config) {
    setKnowledgeStatus("offline", "warn");
    knowledgeSummary.textContent = "Knowledge settings are unavailable.";
    return;
  }

  const neo4j = config.neo4j || {};
  const helix = config.helix || {};
  const neo4jStatus = neo4j.status || {};
  const helixStatus = helix.status || {};
  knowledgeEnabled.checked = Boolean(config.enabled);
  knowledgeBackend.value = config.backend || "sqlite";
  knowledgeStoreDir.value = config.storeDir || "knowledge";
  if (helixEnabled) helixEnabled.checked = Boolean(helix.enabled);
  if (helixPort) helixPort.value = helix.port || 6969;
  if (helixApiEndpoint) helixApiEndpoint.value = helix.apiEndpoint || "";
  if (helixFallback) helixFallback.checked = helix.fallbackToSqlite ?? true;
  neo4jEnabled.checked = Boolean(neo4j.enabled);
  neo4jUri.value = neo4j.uri || "";
  neo4jUsername.value = neo4j.username || "";
  neo4jDatabase.value = neo4j.database || "neo4j";
  if (neo4jPassword) {
    neo4jPassword.value = "";
    neo4jPassword.placeholder = neo4j.passwordConfigured ? "Saved password configured" : "";
  }

  const usingHelix = (config.backend || "sqlite") === "helix";
  const stateText = usingHelix
    ? (helixStatus.state || (helix.enabled ? "configured" : "disabled"))
    : neo4j.enabled ? (neo4jStatus.state || "not tested") : "disabled";
  const badgeKind = stateText === "connected" ? "success" : stateText === "disabled" ? "" : "warn";
  setKnowledgeStatus(stateText, badgeKind);
  knowledgeSummary.textContent = usingHelix
    ? `RAG ${config.enabled ? "enabled" : "disabled"} - HelixDB ${stateText} - port ${helix.port || 6969}`
    : `RAG ${config.enabled ? "enabled" : "disabled"} - ${config.storeDir || "knowledge"} - Neo4j ${stateText}`;
}

function renderSetupKnowledgeConfig(config) {
  if (!setupNeo4jEnabled || !setupNeo4jUri || !setupNeo4jUsername || !setupNeo4jDatabase) return;
  const neo4j = config?.neo4j || {};
  setupNeo4jEnabled.checked = Boolean(neo4j.enabled ?? true);
  setupNeo4jUri.value = neo4j.uri || "bolt://127.0.0.1:7687";
  setupNeo4jUsername.value = neo4j.username || "neo4j";
  setupNeo4jDatabase.value = neo4j.database || "neo4j";
  if (setupNeo4jPassword) {
    setupNeo4jPassword.value = "";
    setupNeo4jPassword.placeholder = neo4j.passwordConfigured ? "Saved password configured" : "";
  }
}

function getStoredSetup() {
  try {
    const raw = window.localStorage.getItem(SETUP_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    if (!parsed?.caseName || !parsed?.investigatorName) {
      return null;
    }
    return parsed;
  } catch (_error) {
    return null;
  }
}

function persistSetup(profile) {
  window.localStorage.setItem(SETUP_STORAGE_KEY, JSON.stringify(profile));
  state.caseProfile = profile;
}

function applySetupVisibility() {
  const ready = Boolean(state.caseProfile);
  setupScreen?.classList.toggle("is-hidden", ready);
  appShell?.classList.toggle("is-hidden", !ready);
  messageInput.disabled = !ready;
  updateComposerActions();
  if (state.caseProfile) {
    activeScope.textContent = state.caseProfile.caseName;
    sessionMeta.textContent = `${state.caseProfile.caseName} - ${state.caseProfile.investigatorName}`;
  }
}

function setupModelFormPayload() {
  return {
    provider: setupProvider?.value || "",
    model: setupModelId?.value.trim() || "",
    apiBase: setupApiBase?.value.trim() || "",
  };
}

function renderSetupModelConfig(config) {
  if (!setupProvider || !setupModelId || !setupApiBase) return;
  const providers = config?.availableProviders || [];
  setupProvider.innerHTML = "";
  for (const provider of providers) {
    const option = document.createElement("option");
    option.value = provider.name;
    option.textContent = provider.label || provider.name;
    option.dataset.defaultApiBase = provider.defaultApiBase || "";
    setupProvider.appendChild(option);
  }
  setupProvider.value = config?.provider || providers[0]?.name || "";
  setupModelId.value = config?.model || "";
  setupApiBase.value = config?.apiBase || "";

  const stored = getStoredSetup();
  if (stored) {
    setupCaseName.value = stored.caseName || "";
    setupInvestigatorName.value = stored.investigatorName || "";
  }
}

function syncSetupDefaultApiBaseFromProvider() {
  if (!setupProvider || !setupApiBase) return;
  const option = setupProvider.selectedOptions[0];
  if (option?.dataset.defaultApiBase) {
    setupApiBase.value = option.dataset.defaultApiBase;
  }
}

async function testSetupModelConfig() {
  setupStatus.textContent = "LLM endpoint를 확인하는 중입니다.";
  const data = await apiJson("/api/model-config/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(setupModelFormPayload()),
  });
  const result = data.result || {};
  setupStatus.textContent = result.ok
    ? `연결되었습니다. ${result.models?.length ? result.models.slice(0, 3).join(", ") : "Endpoint responded."}`
    : `연결 실패: ${result.error || "응답을 받지 못했습니다."}`;
}

async function testSetupKnowledgeConfig() {
  setupStatus.textContent = "Neo4j 연결을 확인하는 중입니다.";
  const data = await apiJson("/api/knowledge-config/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(setupKnowledgeFormPayload()),
  });
  const result = data.result || {};
  const stateText = result.state || "unknown";
  setupStatus.textContent = data.ok
    ? `Neo4j 상태: ${stateText}`
    : `Neo4j 연결 실패: ${result.error || stateText}`;
}

async function completeInitialSetup(event) {
  event.preventDefault();
  const caseName = setupCaseName.value.trim();
  const investigatorName = setupInvestigatorName.value.trim();
  const modelPayload = setupModelFormPayload();
  const knowledgePayload = setupKnowledgeFormPayload();
  if (!caseName || !investigatorName || !modelPayload.provider || !modelPayload.model || !modelPayload.apiBase) {
    setupStatus.textContent = "케이스 이름, 수사관 이름, Local LLM 설정을 모두 입력하세요.";
    return;
  }
  if (knowledgePayload.neo4jEnabled && !knowledgePayload.uri) {
    setupStatus.textContent = "Neo4j를 사용할 경우 URI를 입력하세요.";
    return;
  }

  setupStart.disabled = true;
  setupStatus.textContent = "설정을 저장하는 중입니다.";
  try {
    const data = await apiJson("/api/model-config", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(modelPayload),
    });
    const knowledgeData = await apiJson("/api/knowledge-config", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(knowledgePayload),
    });
    renderModelConfig(data.modelConfig);
    renderKnowledgeConfig(knowledgeData.knowledgeConfig);
    renderSetupKnowledgeConfig(knowledgeData.knowledgeConfig);
    persistSetup({ caseName, investigatorName });
    applySetupVisibility();
    activeSessionTitle.textContent = caseName;
    setStatus(`${caseName} 케이스를 시작했습니다.`);
  } catch (error) {
    setupStatus.textContent = `설정 저장 실패: ${error.message}`;
  } finally {
    setupStart.disabled = false;
  }
}

function escapeHtml(text) {
  return String(text || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function escapeAttribute(text) {
  return escapeHtml(text).replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function sanitizeMarkdownUrl(url) {
  const value = String(url || "").trim();
  if (!value) return null;
  if (value.startsWith("#") || value.startsWith("/")) {
    return value;
  }
  try {
    const parsed = new URL(value, window.location.origin);
    if (["http:", "https:", "mailto:"].includes(parsed.protocol)) {
      return parsed.href;
    }
  } catch (_error) {
    return null;
  }
  return null;
}

function restoreMarkdownTokens(text, replacements) {
  return text.replace(/@@MDTOKEN_(\d+)@@/g, (_match, index) => replacements[Number(index)] || "");
}

function renderInlineMarkdown(text) {
  let working = String(text || "");
  const replacements = [];
  const token = (html) => {
    const marker = `@@MDTOKEN_${replacements.length}@@`;
    replacements.push(html);
    return marker;
  };

  working = working.replace(/`([^`\n]+)`/g, (_match, code) => {
    return token(`<code>${escapeHtml(code)}</code>`);
  });

  working = working.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_match, label, url) => {
    const safeUrl = sanitizeMarkdownUrl(url);
    if (!safeUrl) {
      return `${label} (${url})`;
    }
    return token(
      `<a href="${escapeAttribute(safeUrl)}" target="_blank" rel="noreferrer noopener">${escapeHtml(label)}</a>`
    );
  });

  working = escapeHtml(working);
  working = working.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  working = working.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  working = working.replace(/~~([^~]+)~~/g, "<del>$1</del>");
  working = working.replace(
    /(^|[\s(>])((?:https?:\/\/)[^\s<]+)(?=$|[\s),.:;!?])/g,
    (_match, prefix, rawUrl) => {
      const safeUrl = sanitizeMarkdownUrl(rawUrl);
      if (!safeUrl) {
        return `${prefix}${rawUrl}`;
      }
      return `${prefix}${token(
        `<a href="${escapeAttribute(safeUrl)}" target="_blank" rel="noreferrer noopener">${escapeHtml(rawUrl)}</a>`
      )}`;
    }
  );

  return restoreMarkdownTokens(working, replacements);
}

function isMarkdownBlockBoundary(line) {
  const trimmed = String(line || "").trim();
  return (
    !trimmed ||
    /^```/.test(trimmed) ||
    /^(#{1,6})\s+/.test(trimmed) ||
    /^>\s?/.test(trimmed) ||
    /^[-*+]\s+/.test(trimmed) ||
    /^\d+\.\s+/.test(trimmed) ||
    /^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)
  );
}

function renderMarkdown(text) {
  const source = String(text || "").replace(/\r\n?/g, "\n").trim();
  if (!source) {
    return "";
  }

  const lines = source.split("\n");
  const blocks = [];

  for (let index = 0; index < lines.length;) {
    const rawLine = lines[index];
    const trimmed = rawLine.trim();

    if (!trimmed) {
      index += 1;
      continue;
    }

    const fence = trimmed.match(/^```([\w.-]+)?\s*$/);
    if (fence) {
      const language = fence[1] || "";
      index += 1;
      const codeLines = [];
      while (index < lines.length && !lines[index].trim().startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) {
        index += 1;
      }
      const languageAttr = language ? ` data-language="${escapeAttribute(language)}"` : "";
      blocks.push(
        `<pre class="markdown-code-block"${languageAttr}><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`
      );
      continue;
    }

    const heading = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      const level = heading[1].length;
      blocks.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
      index += 1;
      continue;
    }

    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      blocks.push("<hr>");
      index += 1;
      continue;
    }

    if (/^>\s?/.test(trimmed)) {
      const quoteLines = [];
      while (index < lines.length && /^>\s?/.test(lines[index].trim())) {
        quoteLines.push(lines[index].trim().replace(/^>\s?/, ""));
        index += 1;
      }
      blocks.push(`<blockquote>${renderMarkdown(quoteLines.join("\n"))}</blockquote>`);
      continue;
    }

    if (/^[-*+]\s+/.test(trimmed)) {
      const items = [];
      while (index < lines.length && /^[-*+]\s+/.test(lines[index].trim())) {
        items.push(lines[index].trim().replace(/^[-*+]\s+/, ""));
        index += 1;
      }
      blocks.push(`<ul>${items.map((item) => `<li>${renderInlineMarkdown(item)}</li>`).join("")}</ul>`);
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      const items = [];
      while (index < lines.length && /^\d+\.\s+/.test(lines[index].trim())) {
        items.push(lines[index].trim().replace(/^\d+\.\s+/, ""));
        index += 1;
      }
      blocks.push(`<ol>${items.map((item) => `<li>${renderInlineMarkdown(item)}</li>`).join("")}</ol>`);
      continue;
    }

    const paragraphLines = [];
    while (index < lines.length && !isMarkdownBlockBoundary(lines[index])) {
      paragraphLines.push(lines[index]);
      index += 1;
    }
    blocks.push(`<p>${paragraphLines.map((line) => renderInlineMarkdown(line)).join("<br>")}</p>`);
  }

  return blocks.join("");
}

function renderPlainText(text) {
  return escapeHtml(String(text || "")).replace(/\n/g, "<br>");
}

function contentNodeFor(node) {
  return node.querySelector(".message-content");
}

function roleForNode(node) {
  if (node.classList.contains("user")) return "user";
  if (node.classList.contains("tool")) return "tool";
  return "assistant";
}

function setStatus(text) {
  statusLine.textContent = text;
}

function setConnection(online) {
  connectionStatus.textContent = online ? "online" : "offline";
  connectionStatus.classList.toggle("online", online);
}

function updateComposerActions() {
  const hasBusyAttachment = state.attachments.some((item) => item.status === "uploading" || item.status === "processing");
  sendButton.disabled = !state.caseProfile || !state.sessionId || state.isStopping || hasBusyAttachment;
  sendButton.textContent = state.isStopping ? "Stopping..." : state.isGenerating ? "Stop" : "Send";
  sendButton.classList.toggle("is-stop", state.isGenerating || state.isStopping);
  sendButton.setAttribute(
    "aria-label",
    hasBusyAttachment
      ? "Wait for attachments to finish processing"
      : state.isStopping
        ? "Stopping response generation"
        : state.isGenerating
          ? "Stop response generation"
          : "Send message"
  );
}

function beginGeneration() {
  state.isGenerating = true;
  state.isStopping = false;
  state.stopRequested = false;
  state.stopTargetSessionKey = null;
  updateComposerActions();
}

function finishGeneration() {
  state.isGenerating = false;
  state.isStopping = false;
  state.stopRequested = false;
  state.stopTargetSessionKey = null;
  updateComposerActions();
}

function stopScope() {
  if (state.activeSessionKey) {
    return parseSessionScope(state.activeSessionKey);
  }
  return currentScope();
}

function freezeAssistantNode(node) {
  if (!node) return;

  finalizeAssistantNode(node);
  node.classList.remove("streaming");
  node.classList.add("stopped");

  const current = messageContentText(node).trim();
  if (!current || current === "답변중..." || current === "답변을 준비하는 중입니다...") {
    setMessageContent(node, "응답 생성이 중지되었습니다.");
  }
  setMessageMeta(node, "assistant / stopped");
}

function freezeLiveAssistantNodes() {
  const seen = new Set();
  for (const node of state.streamNodes.values()) {
    if (seen.has(node)) continue;
    freezeAssistantNode(node);
    seen.add(node);
  }
  if (state.pendingAssistant && !seen.has(state.pendingAssistant)) {
    freezeAssistantNode(state.pendingAssistant);
  }
  state.streamNodes.clear();
  state.pendingAssistant = null;
}

function clearPlaceholderThinking(node) {
  const details = node.querySelector(".message-thinking");
  const thoughtNode = details?.querySelector(".thinking-content");
  const text = String(thoughtNode?.textContent || "").trim();
  if (details && (!text || text === "생각 중...")) {
    details.remove();
  }
}

function setEmpty(container, text) {
  container.innerHTML = `<div class="empty-state">${escapeHtml(text)}</div>`;
}

function setMessageMeta(node, text) {
  node.querySelector(".message-meta").textContent = text;
}

function setMessageContent(node, text) {
  const contentNode = contentNodeFor(node);
  if (!contentNode) return;
  const role = roleForNode(node);
  const rawText = String(text || "");
  contentNode.dataset.rawText = rawText;

  if (role === "assistant") {
    contentNode.innerHTML = renderMarkdown(rawText);
    contentNode.classList.remove("message-plain");
    contentNode.classList.add("message-markdown", "markdown-rendered");
    return;
  }

  contentNode.innerHTML = renderPlainText(rawText);
  contentNode.classList.remove("message-markdown", "markdown-rendered");
  contentNode.classList.add("message-plain");
}

function messageContentText(node) {
  const contentNode = contentNodeFor(node);
  if (!contentNode) return "";
  return contentNode.dataset.rawText || contentNode.textContent || "";
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
  const current = messageContentText(node);
  const placeholder = current === "답변중..." || current === "답변을 준비하는 중입니다...";
  setMessageContent(node, placeholder ? text : current + text);
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
  const contentNode = contentNodeFor(node);
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

  if (options.thinkingText) {
    setThinkingText(node, options.thinkingText);
  }

  if (role === "tool") {
    const contentNode = contentNodeFor(node);
    if (contentNode) {
      contentNode.dataset.rawText = String(content || "");
      contentNode.textContent = String(content || "");
    }
    decorateToolMessage(node, content);
  } else {
    setMessageContent(node, content);
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
  const raw = await response.text();
  let data = {};
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch (_error) {
      data = { error: raw.trim() };
    }
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

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function attachmentLabel(item) {
  if (item.error) return `failed: ${item.error}`;
  if (item.status === "uploading") return "uploading";
  if (item.status === "processing") return "processing";
  if (item.status === "ready") return "RAG ready";
  if (item.status === "vision_metadata_indexed") return "vision indexed";
  if (item.status === "vision_metadata_ready") return "vision metadata";
  if (item.status === "stored_pending_parser") return "stored";
  if (item.status === "stored_unsupported") return "unsupported";
  return item.status || "stored";
}

function renderAttachments() {
  if (!attachmentTray) return;
  attachmentTray.hidden = state.attachments.length === 0;
  attachmentTray.innerHTML = "";
  for (const item of state.attachments) {
    const chip = document.createElement("div");
    chip.className = "attachment-chip";
    chip.classList.toggle("is-error", Boolean(item.error));
    chip.classList.toggle("is-busy", item.status === "uploading" || item.status === "processing");
    chip.innerHTML = `
      <div class="attachment-main">
        <strong>${escapeHtml(item.fileName || item.name || "file")}</strong>
        <small>${escapeHtml(item.kind || "file")} - ${escapeHtml(formatBytes(item.sizeBytes || item.size || 0))} - ${escapeHtml(attachmentLabel(item))}</small>
      </div>
      <button class="attachment-remove" type="button" aria-label="Remove attachment">x</button>
    `;
    chip.querySelector(".attachment-remove").addEventListener("click", () => {
      state.attachments = state.attachments.filter((candidate) => candidate.clientId !== item.clientId);
      renderAttachments();
      updateComposerActions();
    });
    attachmentTray.appendChild(chip);
  }
}

function updateAttachment(clientId, patch) {
  state.attachments = state.attachments.map((item) =>
    item.clientId === clientId ? { ...item, ...patch } : item
  );
  renderAttachments();
  updateComposerActions();
}

async function uploadAttachment(file) {
  if (!file) return;
  if (!state.caseProfile) {
    applySetupVisibility();
    setupStatus.textContent = "파일을 첨부하려면 먼저 초기 설정을 완료하세요.";
    return;
  }

  const clientId = `local_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  state.attachments.push({
    clientId,
    fileName: file.name,
    sizeBytes: file.size,
    kind: file.type || "file",
    status: "uploading",
  });
  renderAttachments();
  updateComposerActions();
  setStatus(`${file.name} 업로드를 시작했습니다.`);

  const form = new FormData();
  form.append("sessionId", state.sessionId || "");
  form.append("caseName", state.caseProfile.caseName);
  form.append("investigatorName", state.caseProfile.investigatorName);
  form.append("file", file, file.name);

  try {
    updateAttachment(clientId, { status: "processing" });
    const data = await apiJson("/api/uploads", { method: "POST", body: form });
    updateAttachment(clientId, {
      ...(data.upload || {}),
      clientId,
      error: "",
    });
    setStatus(`${file.name} 처리 완료: ${attachmentLabel(data.upload || {})}`);
  } catch (error) {
    updateAttachment(clientId, {
      status: "failed",
      error: error.message || "upload failed",
    });
    setStatus(`파일 처리 실패: ${error.message}`);
  }
}

function handleDroppedFiles(fileList) {
  const files = Array.from(fileList || []).filter((file) => file && file.name);
  if (!files.length) return;
  for (const file of files) {
    uploadAttachment(file).catch((error) => {
      console.error(error);
      setStatus(`파일 업로드 중 오류: ${error.message}`);
    });
  }
}

function setDropActive(active) {
  composerShell?.classList.toggle("drag-active", active);
  if (dropHint) {
    dropHint.hidden = !active;
  }
}

async function loadModelConfig() {
  try {
    const data = await apiJson("/api/model-config");
    renderModelConfig(data.modelConfig);
  } catch (error) {
    setModelStatus("offline", "warn");
    if (modelSummary) {
      modelSummary.textContent = error.message || "Model settings are unavailable.";
    }
  }
}

async function testModelConfig() {
  const payload = currentModelForm();
  setModelStatus("testing");
  try {
    const data = await apiJson("/api/model-config/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = data.result || {};
    const models = result.models || [];
    setModelStatus(result.ok ? "ok" : "failed", result.ok ? "success" : "warn");
    modelSummary.textContent = result.ok
      ? `Connected. ${models.length ? `Models: ${models.slice(0, 3).join(", ")}` : "Endpoint responded."}`
      : `Connection failed. ${result.error || "No response."}`;
  } catch (error) {
    setModelStatus("failed", "warn");
    modelSummary.textContent = error.message || "Connection test failed.";
  }
}

async function saveModelConfig() {
  const payload = currentModelForm();
  state.isApplyingModel = true;
  setModelStatus("applying");
  modelSave.disabled = true;
  try {
    const data = await apiJson("/api/model-config", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderModelConfig(data.modelConfig);
  } catch (error) {
    setModelStatus("failed", "warn");
    modelSummary.textContent = error.message || "Could not apply model settings.";
  } finally {
    state.isApplyingModel = false;
    modelSave.disabled = false;
  }
}

async function loadKnowledgeConfig() {
  try {
    const data = await apiJson("/api/knowledge-config");
    renderKnowledgeConfig(data.knowledgeConfig);
    renderSetupKnowledgeConfig(data.knowledgeConfig);
  } catch (error) {
    setKnowledgeStatus("offline", "warn");
    if (knowledgeSummary) {
      knowledgeSummary.textContent = error.message || "Knowledge settings are unavailable.";
    }
  }
}

async function testKnowledgeConfig() {
  const payload = currentKnowledgeForm();
  setKnowledgeStatus("testing");
  try {
    const data = await apiJson("/api/knowledge-config/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = data.result || {};
    const stateText = result.state || "unknown";
    setKnowledgeStatus(stateText, data.ok ? "success" : "warn");
    knowledgeSummary.textContent = data.ok
      ? `Neo4j test succeeded. State: ${stateText}`
      : `Neo4j test failed. ${result.error || stateText}`;
  } catch (error) {
    setKnowledgeStatus("failed", "warn");
    knowledgeSummary.textContent = error.message || "Neo4j test failed.";
  }
}

async function saveKnowledgeConfig() {
  const payload = currentKnowledgeForm();
  state.isApplyingKnowledge = true;
  setKnowledgeStatus("applying");
  knowledgeSave.disabled = true;
  try {
    const data = await apiJson("/api/knowledge-config", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderKnowledgeConfig(data.knowledgeConfig);
    renderSetupKnowledgeConfig(data.knowledgeConfig);
  } catch (error) {
    setKnowledgeStatus("failed", "warn");
    knowledgeSummary.textContent = error.message || "Could not apply knowledge settings.";
  } finally {
    state.isApplyingKnowledge = false;
    knowledgeSave.disabled = false;
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
      <div class="markdown-rendered detail-markdown">${renderMarkdown(reportContent)}</div>
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

function resetUiForFreshBrowserSession() {
  state.activeSessionKey = null;
  state.pendingAssistant = null;
  state.streamNodes.clear();
  finishGeneration();
  chatLog.innerHTML = "";
  caseIdInput.value = "";
  artifactIdInput.value = "";
  activeSessionTitle.textContent = "새 브라우저 세션";
  clearCaseDetail();
  updateScopeSummary();
}

async function bootstrap({ reset = false } = {}) {
  const data = await apiJson(reset ? "/api/bootstrap?reset=1" : "/api/bootstrap");
  state.sessionId = data.sessionId;
  state.commands = data.commands || [];
  state.caseProfile = getStoredSetup();
  finishGeneration();
  if (reset) {
    resetUiForFreshBrowserSession();
  }
  renderModelConfig(data.modelConfig);
  renderSetupModelConfig(data.modelConfig);
  renderKnowledgeConfig(data.knowledgeConfig);
  renderSetupKnowledgeConfig(data.knowledgeConfig);
  sessionBadge.textContent = data.sessionId;
  sessionMeta.textContent = state.caseProfile
    ? `${state.caseProfile.caseName} - ${state.caseProfile.investigatorName}`
    : `브라우저 세션 ${data.sessionId}`;
  updateScopeSummary();
  updateComposerActions();
  applySetupVisibility();
  await connectSocket();
  await refreshSessions();
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
    finishGeneration();
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
  const stoppingThisSession =
    state.stopRequested &&
    (!state.stopTargetSessionKey || !event.sessionKey || event.sessionKey === state.stopTargetSessionKey);

  if (event.type === "ready") {
    setConnection(true);
    return;
  }

  if (event.sessionId && event.sessionId !== state.sessionId) {
    return;
  }

  if (event.type === "shell_trace") {
    return;
  }

  if (event.type === "progress" || event.type === "tool_hint") {
    if (stoppingThisSession) {
      return;
    }
    if (!state.activeSessionKey || event.sessionKey === state.activeSessionKey) {
      state.isGenerating = true;
      updateComposerActions();
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
    if (stoppingThisSession) {
      return;
    }
    if (event.sessionKey) {
      state.activeSessionKey = event.sessionKey;
      activeSessionTitle.textContent = event.sessionKey;
    }
    state.isGenerating = true;
    updateComposerActions();
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
    if (stoppingThisSession) {
      return;
    }
    if (event.resuming) {
      state.streamNodes.delete(event.streamId);
      setStatus("도구 실행 후 답변을 이어가는 중입니다.");
      return;
    }
    setStatus("답변을 마무리하는 중입니다.");
    refreshSessions();
    return;
  }

  if (event.type === "message") {
    if (event.sessionKey) {
      state.activeSessionKey = event.sessionKey;
      activeSessionTitle.textContent = event.sessionKey;
    }
    const wasStopRequested = state.stopRequested;
    if (state.isGenerating || state.isStopping) {
      finishGeneration();
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
    } else {
      clearPlaceholderThinking(node);
    }
    if (event.resetBrowserSession) {
      setStatus("새 WebUI 세션으로 전환하는 중입니다.");
      resetBrowserSession().catch((error) => {
        console.error(error);
        setStatus(`세션 초기화 실패: ${error.message}`);
      });
      return;
    }
    setStatus(wasStopRequested ? "응답 생성이 중지되었습니다." : "응답이 완료되었습니다.");
    refreshSessions();
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
  finishGeneration();
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

  await refreshSessions();
}

async function requestStop() {
  if (!state.sessionId || (!state.isGenerating && !state.isStopping)) {
    return;
  }

  state.isStopping = true;
  state.stopRequested = true;
  state.stopTargetSessionKey = state.activeSessionKey || null;
  updateComposerActions();
  freezeLiveAssistantNodes();
  setStatus("중지 요청을 보내는 중입니다.");

  try {
    await apiJson("/api/stop", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: state.sessionId,
        caseName: state.caseProfile?.caseName || null,
        investigatorName: state.caseProfile?.investigatorName || null,
      }),
    });
    setStatus("중지 요청을 전송했습니다.");
  } catch (error) {
    state.isStopping = false;
    state.stopRequested = false;
    state.stopTargetSessionKey = null;
    updateComposerActions();
    setStatus(`중지 실패: ${error.message}`);
  }
}

async function sendMessage(event) {
  event.preventDefault();
  if (!state.caseProfile) {
    applySetupVisibility();
    setupStatus.textContent = "채팅을 시작하려면 먼저 초기 설정을 완료하세요.";
    return;
  }
  if (state.isGenerating || state.isStopping) return;

  const rawText = messageInput.value;
  const text = rawText.trim();
  const readyAttachments = state.attachments.filter((item) => item.uploadId && !item.error);
  if (!text && !readyAttachments.length) return;

  const attachmentText = readyAttachments.length
    ? `첨부 파일:\n${readyAttachments.map((item) => `- ${item.fileName} (${attachmentLabel(item)})`).join("\n")}`
    : "";
  makeMessage("user", [rawText.trim(), attachmentText].filter(Boolean).join("\n\n"), "user");
  if (state.pendingAssistant) {
    finalizeAssistantNode(state.pendingAssistant);
    state.pendingAssistant = null;
  }
  createPendingAssistantNode();
  beginGeneration();
  setStatus("생각하는 중입니다.");

  try {
    const data = await apiJson("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: state.sessionId,
        caseName: state.caseProfile.caseName,
        investigatorName: state.caseProfile.investigatorName,
        text: rawText,
        attachments: readyAttachments.map((item) => ({ uploadId: item.uploadId })),
      }),
    });

    state.activeSessionKey = data.sessionKey;
    activeSessionTitle.textContent = state.caseProfile.caseName;
    messageInput.value = "";
    state.attachments = [];
    renderAttachments();
    closeSlashMenu();

    await refreshSessions();
  } catch (error) {
    if (state.pendingAssistant) {
      setMessageContent(state.pendingAssistant, `전송 실패: ${error.message}`);
      finalizeAssistantNode(state.pendingAssistant);
      state.pendingAssistant = null;
    }
    finishGeneration();
    setStatus(`전송 실패: ${error.message}`);
  }
}

async function selectCase(caseId) {
  caseIdInput.value = caseId;
  artifactIdInput.value = "";
  updateScopeSummary();
  await loadCase(caseId);
}

async function selectArtifact(artifactId) {
  artifactIdInput.value = artifactId;
  updateScopeSummary();
  if (caseIdInput.value.trim()) {
    await loadArtifact(caseIdInput.value.trim(), artifactId);
  }
}

document.querySelector("#refresh-sessions").addEventListener("click", () => {
  refreshSessions().catch((error) => setStatus(`세션 새로고침 실패: ${error.message}`));
});
document.querySelector("#refresh-cases").addEventListener("click", () => {
  refreshCases().catch((error) => setStatus(`case 새로고침 실패: ${error.message}`));
});
document.querySelector("#clear-scope").addEventListener("click", () => {
  caseIdInput.value = "";
  artifactIdInput.value = "";
  updateScopeSummary();
  clearCaseDetail();
});

modelProvider?.addEventListener("change", syncDefaultApiBaseFromProvider);
modelTest?.addEventListener("click", () => {
  testModelConfig().catch((error) => {
    setModelStatus("failed", "warn");
    modelSummary.textContent = error.message || "Connection test failed.";
  });
});
modelSave?.addEventListener("click", () => {
  saveModelConfig().catch((error) => {
    setModelStatus("failed", "warn");
    modelSummary.textContent = error.message || "Could not apply model settings.";
  });
});

knowledgeTest?.addEventListener("click", () => {
  testKnowledgeConfig().catch((error) => {
    setKnowledgeStatus("failed", "warn");
    knowledgeSummary.textContent = error.message || "Neo4j test failed.";
  });
});
knowledgeSave?.addEventListener("click", () => {
  saveKnowledgeConfig().catch((error) => {
    setKnowledgeStatus("failed", "warn");
    knowledgeSummary.textContent = error.message || "Could not apply knowledge settings.";
  });
});

setupProvider?.addEventListener("change", syncSetupDefaultApiBaseFromProvider);
setupTestModel?.addEventListener("click", () => {
  testSetupModelConfig().catch((error) => {
    setupStatus.textContent = `LLM 테스트 실패: ${error.message}`;
  });
});
setupTestNeo4j?.addEventListener("click", () => {
  testSetupKnowledgeConfig().catch((error) => {
    setupStatus.textContent = `Neo4j 테스트 실패: ${error.message}`;
  });
});
setupForm?.addEventListener("submit", (event) => {
  completeInitialSetup(event).catch((error) => {
    setupStatus.textContent = `설정 저장 실패: ${error.message}`;
  });
});

caseIdInput.addEventListener("input", updateScopeSummary);
artifactIdInput.addEventListener("input", updateScopeSummary);
caseIdInput.addEventListener("change", () => {
  const caseId = caseIdInput.value.trim();
  if (!caseId) {
    clearCaseDetail();
    return;
  }
  loadCase(caseId).catch((error) => setStatus(`scope 반영 실패: ${error.message}`));
});
artifactIdInput.addEventListener("change", () => {
  const caseId = caseIdInput.value.trim();
  const artifactId = artifactIdInput.value.trim();
  if (!artifactId) {
    artifactDetail.innerHTML = "";
    return;
  }
  loadArtifact(caseId, artifactId).catch((error) => setStatus(`artifact 반영 실패: ${error.message}`));
});

composerShell?.addEventListener("dragenter", (event) => {
  if (!Array.from(event.dataTransfer?.types || []).includes("Files")) return;
  event.preventDefault();
  state.dragDepth += 1;
  setDropActive(true);
});
composerShell?.addEventListener("dragover", (event) => {
  if (!Array.from(event.dataTransfer?.types || []).includes("Files")) return;
  event.preventDefault();
  if (event.dataTransfer) {
    event.dataTransfer.dropEffect = "copy";
  }
  setDropActive(true);
});
composerShell?.addEventListener("dragleave", (event) => {
  if (!Array.from(event.dataTransfer?.types || []).includes("Files")) return;
  state.dragDepth = Math.max(0, state.dragDepth - 1);
  if (state.dragDepth === 0) {
    setDropActive(false);
  }
});
composerShell?.addEventListener("drop", (event) => {
  if (!Array.from(event.dataTransfer?.types || []).includes("Files")) return;
  event.preventDefault();
  state.dragDepth = 0;
  setDropActive(false);
  handleDroppedFiles(event.dataTransfer?.files);
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
    finishGeneration();
    setStatus(`전송 중 오류: ${error.message}`);
  });
});

sendButton.addEventListener("click", () => {
  if (!state.sessionId || state.isStopping) {
    return;
  }

  if (state.isGenerating) {
    requestStop().catch((error) => {
      console.error(error);
      state.isStopping = false;
      state.stopRequested = false;
      state.stopTargetSessionKey = null;
      updateComposerActions();
      setStatus(`중지 중 오류: ${error.message}`);
    });
    return;
  }

  composer.requestSubmit();
});

updateComposerActions();

bootstrap().catch((error) => {
  console.error(error);
  finishGeneration();
  setStatus(`초기화 실패: ${error.message}`);
});
