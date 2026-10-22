import { RISKS, riskOf, parseRepository, filterSessions, formatBytes, reportEntries, riskDistribution, algorithmCounts } from './model.mjs';
import { analyzeSource, listSources, exportSourceCbom, exportSourceReport } from './source-api.mjs';
import { REPORT_KINDS } from './report-kinds.mjs';
import { droppedFiles, prepareFiles, uploadPath } from './file-input.mjs';
import { MOCK_ACCOUNTS, createMockWorkspace } from './mock-workspace.mjs';

const $ = selector => document.querySelector(selector);
let browserStorage;
try { browserStorage = window.localStorage; } catch { /* Browser storage may be disabled. */ }
const workspace = createMockWorkspace(browserStorage);
const sources = [];
let sourcesLoaded = false;
let workspaceError = '';
let workspaceRequest = 0;
let selectedSourceId = null;
const activeSource = () => sources.find(source => source.id === selectedSourceId);
const emptyMessage = () => workspaceError || (sourcesLoaded
  ? 'No sources yet. Add files, a folder, or a repository to get started.' : 'Loading saved sources…');
let report = null;
let detailTrigger;
const VERDICT_STYLES = { 'NOT QUANTUM SAFE': 'not-safe', 'PARTIALLY QUANTUM SAFE': 'partial', 'QUANTUM SAFE (for detected cryptography)': 'safe', 'NO CRYPTOGRAPHY DETECTED': 'none' };
let reportKind = Object.keys(REPORT_KINDS)[0];
let reportRequest = 0;
const chartReports = new Map();
const chartErrors = new Map();
let chartsLoading = true;
let chartRequest = 0;
const RISK_COLORS = Object.fromEntries(RISKS.map(risk => [risk, `var(--risk-${risk.toLowerCase()})`]));

async function readReport(kind, source = activeSource()) {
  return source.reports?.[kind] || { metadata: { source: source.name }, components: [] };
}

async function loadChartReports() {
  const request = ++chartRequest;
  const source = activeSource();
  if (source?.status !== 'ready') { chartsLoading = false; renderCharts(); return; }
  chartsLoading = true;
  $('#retry-charts').disabled = true;
  renderCharts();
  const kinds = Object.keys(REPORT_KINDS);
  const results = await Promise.allSettled(kinds.map(kind => readReport(kind, source)));
  if (request !== chartRequest || source !== activeSource()) return;
  results.forEach((result, index) => {
    const kind = kinds[index];
    if (result.status === 'fulfilled') { chartReports.set(kind, result.value); chartErrors.delete(kind); }
    else { chartReports.delete(kind); chartErrors.set(kind, result.reason.message); }
  });
  chartsLoading = false;
  $('#retry-charts').disabled = false;
  renderCharts();
}

function renderCharts() {
  const source = activeSource();
  $('#visualizations').setAttribute('aria-busy', String(chartsLoading && source?.status === 'ready'));
  if (source?.status !== 'ready') {
    $('#chart-status').textContent = source ? `${source.name} · ${source.message}` : emptyMessage();
    $('#chart-content').hidden = true;
    $('#retry-charts').hidden = true;
    return;
  }
  const scope = $('#chart-scope').value;
  const kinds = scope === 'all' ? Object.keys(REPORT_KINDS) : [scope];
  const available = kinds.filter(kind => chartReports.has(kind));
  const missing = kinds.filter(kind => chartErrors.has(kind));
  $('#chart-status').textContent = chartsLoading ? 'Loading report visualizations…' : missing.length ? `Partial data: ${missing.map(kind => REPORT_KINDS[kind].label).join(', ')} unavailable. Charts include only loaded reports.` : `${source.name} · ${available.map(kind => REPORT_KINDS[kind].label).join(' + ')} · independent of inventory filters.`;
  $('#retry-charts').hidden = missing.length === 0;
  $('#chart-content').hidden = chartsLoading || available.length === 0;
  if (chartsLoading || available.length === 0) return;
  const entries = reportEntries(available.map(kind => chartReports.get(kind)));
  const basis = $('#risk-basis').value;
  const distribution = riskDistribution(entries, basis);
  $('#donut-title').textContent = basis === 'files' ? 'Files represented in reports' : 'Risk across findings';
  $('#donut-total').textContent = distribution.total;
  $('#donut-unit').textContent = basis === 'files' ? 'source files' : 'findings';
  $('#risk-chart-summary').textContent = `${distribution.total} ${basis === 'files' ? 'source files represented in reports' : 'reported findings'} in this risk distribution.`;
  $('#risk-basis-note').textContent = basis === 'files'
    ? 'Each source file counts once within the selected source. Critical findings take precedence; otherwise unknown evidence takes precedence over medium or safe ratings. Files with no reported findings are not included.'
    : 'Each finding counts once. These are reported findings, not unique files. Scanner ratings are used as supplied.';
  if (distribution.omitted) $('#risk-basis-note').textContent += ` ${distribution.omitted} findings have no source path and are excluded.`;
  const segments = [];
  const legend = [];
  let position = 0;
  for (const risk of RISKS) {
    const count = distribution.counts[risk];
    if (!count && !['CRITICAL', 'MEDIUM', 'SAFE', 'UNKNOWN'].includes(risk)) continue;
    const percent = distribution.total ? count / distribution.total * 100 : 0;
    if (count) { segments.push(`${RISK_COLORS[risk]} ${position}% ${position + percent}%`); position += percent; }
    const item = element('li');
    const label = element('span', '', 'legend-label');
    const dot = element('i', '', 'legend-dot');
    dot.style.background = RISK_COLORS[risk];
    label.append(dot, document.createTextNode(title(risk)));
    item.append(label, element('strong', `${percent.toFixed(1)}%`), element('span', `${count}`, 'legend-count'));
    legend.push(item);
  }
  $('#risk-donut').style.background = segments.length ? `conic-gradient(${segments.join(', ')})` : 'var(--surface-raised)';
  $('#risk-legend').replaceChildren(...legend);
  $('#risk-chart-empty').hidden = distribution.total > 0;
  for (const purpose of ['encryption', 'keyExchange', 'other']) {
    const { included, rows } = algorithmCounts(entries, purpose);
    const target = $(`#bars-${purpose}`);
    target.replaceChildren(...rows.map(([name, count], index) => {
      const row = element('li');
      const heading = element('div', '', 'bar-heading');
      heading.append(element('span', name), element('strong', String(count)));
      const track = element('div', '', 'bar-track');
      track.setAttribute('aria-hidden', 'true');
      const fill = element('div', '', 'bar-fill');
      fill.style.width = `${count / rows[0][1] * 100}%`;
      track.append(fill);
      const tooltip = element('span', `${name}: ${count} of ${included} recorded occurrences (${(count / included * 100).toFixed(1)}%)`, 'chart-tooltip');
      tooltip.id = `tooltip-${purpose}-${index}`;
      tooltip.setAttribute('role', 'tooltip');
      row.tabIndex = 0;
      row.setAttribute('aria-describedby', tooltip.id);
      row.addEventListener('keydown', event => { if (event.key === 'Escape') row.dataset.dismissed = 'true'; });
      for (const event of ['mouseleave', 'blur']) row.addEventListener(event, () => delete row.dataset.dismissed);
      row.append(heading, track, tooltip);
      return row;
    }));
    $(`#empty-${purpose}`).hidden = rows.length > 0;
    $(`#coverage-${purpose}`).textContent = `${included} of ${entries.length} findings contain ${purpose === 'other' ? 'an algorithm label' : `${purpose === 'keyExchange' ? 'key-exchange' : 'encryption'} data`}. Counts are occurrences, not unique files.`;
  }
}

// Read each scanner's existing report without altering its data or risk policy.
async function loadReport() {
  const request = ++reportRequest;
  const source = activeSource();
  const config = REPORT_KINDS[reportKind];
  report = null;
  renderVerdict();
  $('.inventory-panel').setAttribute('aria-busy', 'true');
  $('.metrics').setAttribute('aria-busy', 'true');
  $('#report-error').hidden = true;
  $('#export-report').disabled = true;
  $('#export-markdown').disabled = true;
  $('#sessions').replaceChildren();
  $('#risk-summary').replaceChildren();
  $('#no-results').hidden = true;
  $('#source-filter-label').hidden = true;
  $('#source-filter').replaceChildren();
  for (const id of ['total-count', 'critical-count', 'safe-count', 'unknown-count']) $(`#${id}`).textContent = '—';
  $('#total-label').textContent = `Total ${config.unit}`;
  $('.metric-icon use').setAttribute('href', `#icon-${config.icon}`);
  $('#safe-label').textContent = `Safe ${config.unit}`;
  $('#dataset-status').textContent = `Loading ${config.label.toLowerCase()}…`;
  $('#result-count').textContent = 'Loading report…';
  $('#report-file').textContent = source ? config.label : 'No source selected';
  $('#inventory-description').textContent = config.description;
  $('#report-policy').textContent = config.policy;
  $('#search').placeholder = config.searchPlaceholder;
  $('#report-columns').replaceChildren(...config.columns.map((label, index) => {
    const heading = element('th', label, index === config.columns.length - 2 ? 'overall-risk' : '');
    heading.scope = 'col';
    return heading;
  }));
  $('.table-scroll').setAttribute('aria-label', `${config.label} risk assessments`);
  $('caption').textContent = `${config.label}: findings and risk assessments`;
  if (source?.status !== 'ready') {
    $('.inventory-panel').setAttribute('aria-busy', 'false');
    $('.metrics').setAttribute('aria-busy', 'false');
    $('#dataset-status').textContent = source ? `${source.name} · ${source.message}` : emptyMessage();
    $('#result-count').textContent = 'No analysis results yet';
    $('#no-results').textContent = source?.message || emptyMessage();
    $('#no-results').hidden = false;
    renderCharts();
    return;
  }
  $('#no-results').textContent = 'No findings match these filters, or this source has no results in this report.';
  try {
    const data = await readReport(reportKind, source);
    if (request !== reportRequest) return;
    report = data;
    chartReports.set(reportKind, data);
    chartErrors.delete(reportKind);
    renderCharts();
    const counts = Object.fromEntries(RISKS.map(risk => [risk, data.components.filter(c => riskOf(c) === risk).length]));
    $('#total-count').textContent = data.components.length;
    $('#critical-count').textContent = counts.CRITICAL;
    $('#safe-count').textContent = counts.SAFE;
    $('#unknown-count').textContent = counts.UNKNOWN;
    $('#dataset-status').textContent = `${source.name} · ${data.components.length} ${config.unit}`;
    $('#risk-summary').replaceChildren(...RISKS.map(risk => {
      const label = element('span');
      label.append(element('i', '', `risk-dot ${risk.toLowerCase()}`), document.createTextNode(`${title(risk)} ${counts[risk]}`));
      return label;
    }));
    const score = data.metadata?.quantumRiskSummary?.codeQuantumRiskScore ?? data.metadata?.quantumRiskSummary?.quantumRiskScore;
    if (score !== undefined) $('#risk-summary').append(element('span', `Scanner risk score: ${score}`, 'scanner-score'));
    if (config.category) {
      $('#source-filter-label').hidden = false;
      $('#source-filter-name').textContent = config.categoryName;
      $('#source-filter').append(new Option('All', 'ALL'));
      for (const value of [...new Set(data.components.map(sourceCategory).filter(Boolean))].sort()) {
        $('#source-filter').append(new Option(categoryLabel(value), value));
      }
    }
    $('#export-report').disabled = false;
    $('#export-markdown').disabled = false;
    renderSessions();
  } catch (error) {
    if (request !== reportRequest) return;
    chartReports.delete(reportKind);
    chartErrors.set(reportKind, error.message);
    renderCharts();
    $('#dataset-status').textContent = 'Source report unavailable';
    $('#report-error').hidden = false;
    $('#report-error-message').textContent = `${error.message} Could not load the ${config.label.toLowerCase()} report. Retry the source connection.`;
    $('#result-count').textContent = 'Report unavailable';
  } finally {
    if (request === reportRequest) {
      $('.inventory-panel').setAttribute('aria-busy', 'false');
      $('.metrics').setAttribute('aria-busy', 'false');
    }
  }
}

function sourceCategory(component) { return REPORT_KINDS[reportKind].category?.(component); }
function categoryLabel(value) { return REPORT_KINDS[reportKind].categoryLabel?.(value) || title(value); }

function renderVerdict() {
  const source = activeSource();
  const summary = source?.status === 'ready' ? source.summary : null;
  $('#verdict-banner').hidden = !summary;
  if (!summary) return;
  $('#verdict-text').textContent = summary.verdict;
  $('#verdict-description').textContent = summary.verdictDescription;
  $('#verdict-banner').dataset.verdict = VERDICT_STYLES[summary.verdict] || 'none';
}

function scannerAlgorithm(component) {
  const crypto = component.cryptoProperties || {};
  return crypto.detectedAlgorithm || crypto.keySpec || crypto.keyAlgorithm || crypto.sslPolicy || 'Not recorded';
}

function element(tag, text = '', className = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function title(value) { return value[0].toUpperCase() + value.slice(1).toLowerCase(); }
function badge(component) { const risk = riskOf(component); return element('span', `● ${title(risk)}`, `risk ${risk.toLowerCase()}`); }

function detailButton(component) {
  const button = element('button', '', 'detail-arrow');
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#icon-arrow');
  svg.append(use);
  button.append(svg);
  button.setAttribute('aria-label', `Inspect ${component.name || 'finding'}`);
  button.addEventListener('click', () => showDetails(component, button));
  return button;
}

function renderSessions() {
  if (!report) return;
  const config = REPORT_KINDS[reportKind];
  const sessions = filterSessions(report.components, $('#search').value, $('#risk-filter').value).filter(component =>
    !config.category || $('#source-filter').value === 'ALL' || sourceCategory(component) === $('#source-filter').value);
  $('#sessions').replaceChildren(...sessions.map(component => config.row ? config.row(component, ui) : scannerRow(component)));
  $('#no-results').hidden = sessions.length > 0;
  $('#result-count').textContent = `Showing ${sessions.length} of ${report.components.length} ${config.unit}`;
}

function scannerRow(component) {
  const row = element('tr', '', 'scanner-row');
  const source = element('td', '', 'finding-source');
  const name = element('button', component.name || 'Unnamed finding', 'session-button');
  name.addEventListener('click', () => showDetails(component, name));
  source.append(name, element('small', component.source || 'Source not recorded'));
  if (component.codeSnippet) source.append(element('code', component.codeSnippet, 'snippet-preview'));
  const category = sourceCategory(component);
  const kind = element('td', category ? categoryLabel(category) : 'Not recorded');
  const algorithm = element('td', scannerAlgorithm(component), 'scanner-algorithm');
  const threat = element('td', component.quantumRiskAssessment?.threat || 'Not recorded');
  const risk = element('td', '', 'overall-risk');
  risk.append(badge(component));
  const action = element('td');
  action.append(detailButton(component));
  row.append(source, kind, algorithm, threat, risk, action);
  return row;
}

function showDetails(component, trigger) {
  detailTrigger = trigger;
  const config = REPORT_KINDS[reportKind];
  $('#detail-title').textContent = component.name || 'Unnamed finding';
  const content = $('#session-detail');
  content.replaceChildren();
  $('#detail-kind').textContent = config.detailKind || 'SCANNER FINDING';
  if (config.details) config.details(component, content, ui);
  else {
    const assessment = component.quantumRiskAssessment || {};
    const conclusion = element('section', '', 'risk-conclusion');
    const explanation = element('div');
    explanation.append(element('h3', scannerAlgorithm(component)), element('p', `Scanner assessment · ${assessment.threat || 'Threat not recorded'}`));
    conclusion.append(explanation, badge(component));
    content.append(conclusion);
    appendDetails(content, {
      'Scanner explanation': assessment.reason || 'No explanation provided.',
      'Source evidence': { file: component.source, line: component.line, arn: component.arn, type: component.type },
    });
    if (component.codeSnippet) {
      const snippet = element('section', '', 'detail-block');
      snippet.append(element('h3', 'Code evidence'), element('pre', component.codeSnippet));
      content.append(snippet);
    }
    appendDetails(content, { 'Cryptographic properties': component.cryptoProperties });
  }
  $('#session-dialog').showModal();
}

function appendDetails(content, sections) {
  for (const [section, data] of Object.entries(sections)) {
    if (data === undefined) continue;
    const block = element('section', '', 'detail-block');
    block.append(element('h3', section.replace(/([A-Z])/g, ' $1')));
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const list = element('dl');
      for (const [key, value] of Object.entries(data)) {
        if (value === undefined) continue;
        list.append(element('dt', key.replace(/([A-Z])/g, ' $1')), element('dd', typeof value === 'object' && value !== null ? JSON.stringify(value, null, 2) : String(value ?? 'Not recorded')));
      }
      block.append(list);
    } else block.append(element('p', Array.isArray(data) ? data.join(', ') : String(data ?? 'Not recorded')));
    content.append(block);
  }
}

// Helpers handed to report kinds that render their own rows or details.
const ui = { element, badge, title, detailButton, showDetails, appendDetails };

function renderReportSwitcher() {
  $('#report-switcher').replaceChildren(...Object.entries(REPORT_KINDS).map(([kind, config]) => {
    const button = element('button');
    button.type = 'button';
    button.dataset.report = kind;
    button.setAttribute('aria-pressed', String(kind === reportKind));
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'icon');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#icon-${config.icon}`);
    svg.append(use);
    const label = element('span', config.label);
    label.append(element('small', config.detail));
    button.append(svg, label);
    button.addEventListener('click', () => {
      reportKind = kind;
      for (const choice of $('#report-switcher').children) choice.setAttribute('aria-pressed', String(choice === button));
      $('#search').value = '';
      $('#risk-filter').value = 'ALL';
      loadReport();
    });
    return button;
  }));
  $('#chart-scope').replaceChildren(new Option('All reports in this source', 'all'),
    ...Object.entries(REPORT_KINDS).map(([kind, config]) => new Option(config.label, kind)));
}

function download(text, name, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = element('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function notice(message) { $('#input-notice').textContent = message; }

function renderSources() {
  const current = activeSource();
  $('#mock-account').value = workspace.account.id;
  $('#workspace-owner').textContent = `${workspace.account.name}’s sources`;
  $('#file-input').disabled = !sourcesLoaded;
  $('#folder-input').disabled = !sourcesLoaded;
  $('#repo-form button[type="submit"]').disabled = !sourcesLoaded;
  const labels = { ready: 'Ready', processing: 'Analyzing', error: 'Needs attention' };
  $('#workspace-source').replaceChildren(...(sources.length
    ? sources.map(source => new Option(`${source.name} · ${labels[source.status]}`, source.id))
    : [new Option(sourcesLoaded ? 'No sources yet' : 'Sources unavailable', '')]));
  $('#workspace-source').value = selectedSourceId || '';
  $('#workspace-source').disabled = sources.length === 0;
  $('#source-status').textContent = current?.message || emptyMessage();
  $('#source-status').dataset.state = current?.status || (workspaceError ? 'error' : sourcesLoaded ? 'empty' : 'processing');
  $('#remove-source').disabled = !current;
  $('#retry-source').hidden = current ? current.status !== 'error' : !workspaceError;
  $('#retry-source').textContent = current?.analysisFailed ? 'Retry analysis' : 'Retry connection';
  for (const label of document.querySelectorAll('[data-report-origin]')) label.hidden = !current;
  $('#added-source-count').textContent = sources.length;
  $('#remove-all-sources').disabled = !sourcesLoaded || sources.length === 0;
  $('#source-list').replaceChildren(...sources.map(source => {
    const item = element('li', '', 'source-item');
    const button = element('button', '', 'source-choice');
    button.setAttribute('aria-pressed', String(source.id === selectedSourceId));
    const description = element('span', source.name);
    description.append(element('small', source.kind === 'repository' ? source.url : source.kind === 'database' ? 'Previously stored analysis' : `${source.files.length} files · ${formatBytes(source.files.reduce((size, file) => size + file.size, 0))}`));
    button.append(description, element('span', labels[source.status], `source-state ${source.status}`));
    button.addEventListener('click', () => {
      selectSource(source.id);
      location.hash = '/analysis';
    });
    const remove = element('button', 'Remove', 'button subtle remove-added-source');
    remove.type = 'button';
    remove.setAttribute('aria-label', `Remove ${source.name} from ${workspace.account.name}’s view`);
    remove.title = 'Hide from this account. Saved analysis is kept.';
    remove.addEventListener('click', () => removeSources([source]));
    item.append(button, remove);
    return item;
  }));
  $('#sources-empty').hidden = !sourcesLoaded || sources.length > 0;
}

function refreshScope() {
  ++chartRequest;
  chartReports.clear();
  chartErrors.clear();
  if ($('#session-dialog').open) $('#session-dialog').close();
  loadReport();
  loadChartReports();
}

function selectSource(id) {
  selectedSourceId = id;
  $('#search').value = '';
  $('#risk-filter').value = 'ALL';
  renderSources();
  refreshScope();
}

function startAnalysis(source, retry = false) {
  const owner = workspace.account.id;
  workspace.remember(source, owner);
  return analyzeSource(source, () => {
    // Capture the server ID even if the user switches accounts or removes a pending upload.
    workspace.remember(source, owner);
    if (!sources.includes(source)) {
      if (source.serverId) source.controller?.abort();
      return;
    }
    renderSources();
    if (source === activeSource()) refreshScope();
  }, { retry });
}

async function loadWorkspace() {
  const request = ++workspaceRequest;
  for (const source of sources) if (source.serverId) source.controller?.abort();
  sources.splice(0, sources.length);
  selectedSourceId = null;
  sourcesLoaded = false;
  workspaceError = '';
  $('#search').value = '';
  $('#risk-filter').value = 'ALL';
  $('#retry-sources').hidden = true;
  renderSources();
  refreshScope();
  notice('Loading saved sources…');
  try {
    const saved = await listSources();
    if (request !== workspaceRequest) return;
    sources.splice(0, sources.length, ...workspace.visible(saved));
    selectedSourceId = sources[0]?.id || null;
    sourcesLoaded = true;
    notice(`${workspace.account.name}’s workspace is ready. New sources will be added to this account.`);
    renderSources();
    refreshScope();
    for (const source of sources) startAnalysis(source);
  } catch (error) {
    if (request !== workspaceRequest) return;
    workspaceError = error.message;
    notice(`Could not load saved sources. ${error.message}`);
    $('#retry-sources').hidden = false;
    renderSources();
    refreshScope();
  }
}

function removeSources(removed) {
  const added = removed.filter(source => source && sources.includes(source));
  if (!added.length) return;
  for (const source of added) {
    workspace.hide(source);
    // Let an initial submission return its identity; stop polling as soon as it does.
    if (source.serverId) source.controller?.abort();
    sources.splice(sources.indexOf(source), 1);
  }
  selectSource(sources.some(source => source.id === selectedSourceId) ? selectedSourceId : sources[0]?.id || null);
  notice(`${added.length === 1 ? added[0].name : `${added.length} sources`} removed from ${workspace.account.name}’s view. Saved analyses are kept.`);
  (location.hash === '#/analysis' && sources.length ? $('#workspace-source')
    : $('#remove-all-sources').disabled ? $('#mock-account') : $('#remove-all-sources')).focus();
}

$('#mock-account').replaceChildren(...MOCK_ACCOUNTS.map(account => new Option(account.name, account.id)));
$('#mock-account').addEventListener('change', event => {
  workspace.select(event.target.value);
  $('#repo-url').value = '';
  $('#repo-error').textContent = '';
  $('#repo-url').removeAttribute('aria-invalid');
  loadWorkspace();
});
$('#remove-all-sources').addEventListener('click', () => removeSources([...sources]));

function addFiles(fileList) {
  if (!sourcesLoaded) { notice('Connect to the server before adding files.'); return; }
  let files;
  try { files = prepareFiles(fileList); }
  catch (error) { notice(error.message); return; }
  if (!files.length) { notice('No files were added. The selection is empty or contains only excluded folders.'); return; }
  const fingerprint = files.map(file => `${uploadPath(file)}:${file.size}:${file.lastModified}`).sort().join('|');
  const existing = sources.find(source => source.fingerprint === fingerprint);
  if (existing) { selectSource(existing.id); notice('This file collection is already added. Its results are now selected.'); return; }
  const folder = uploadPath(files[0]).split('/')[0];
  const name = files.every(file => uploadPath(file).startsWith(folder + '/')) ? folder : files.length === 1 ? files[0].name : `${files[0].name} + ${files.length - 1} files`;
  const source = { id: crypto.randomUUID(), name, kind: 'files', files, fingerprint };
  sources.push(source);
  selectedSourceId = source.id;
  $('#search').value = '';
  $('#risk-filter').value = 'ALL';
  notice(`${files.length} file${files.length === 1 ? '' : 's'} added as a new source. Analysis starts automatically.`);
  startAnalysis(source);
}

for (const selector of ['#file-input', '#folder-input']) {
  $(selector).addEventListener('change', event => { addFiles(event.target.files); event.target.value = ''; });
}
let dragDepth = 0;
$('#drop-zone').addEventListener('dragenter', event => { event.preventDefault(); dragDepth++; $('#drop-zone').classList.add('dragging'); });
$('#drop-zone').addEventListener('dragover', event => { event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; });
$('#drop-zone').addEventListener('dragleave', () => { if (--dragDepth <= 0) $('#drop-zone').classList.remove('dragging'); });
$('#drop-zone').addEventListener('drop', async event => {
  event.preventDefault();
  dragDepth = 0;
  $('#drop-zone').classList.remove('dragging');
  if (!sourcesLoaded) { notice('Connect to the server before adding files.'); return; }
  notice('Reading dropped files and folders…');
  const request = workspaceRequest;
  try {
    const files = await droppedFiles(event.dataTransfer);
    if (request === workspaceRequest) addFiles(files);
  } catch (error) {
    if (request === workspaceRequest) notice(`Could not read the dropped files. ${error.message}`);
  }
});
// Prevent file drops outside the target from navigating away and losing the current sources.
for (const type of ['dragover', 'drop']) document.addEventListener(type, event => {
  if ([...event.dataTransfer.types].includes('Files')) event.preventDefault();
});

$('#repo-form').addEventListener('submit', event => {
  event.preventDefault();
  if (!sourcesLoaded) return;
  const field = $('#repo-url');
  try {
    const repo = parseRepository(field.value);
    const existing = sources.find(source => source.url === repo.url);
    field.value = '';
    field.removeAttribute('aria-invalid');
    $('#repo-error').textContent = '';
    if (existing) { selectSource(existing.id); notice('This repository is already added. Its results are now selected.'); return; }
    const source = { ...repo, id: crypto.randomUUID(), kind: 'repository' };
    sources.push(source);
    selectedSourceId = source.id;
    $('#search').value = '';
    $('#risk-filter').value = 'ALL';
    notice(`${repo.name} added. Cloning and analysis are requested automatically.`);
    startAnalysis(source);
  } catch (error) { $('#repo-error').textContent = error.message; field.setAttribute('aria-invalid', 'true'); field.focus(); }
});
$('#repo-url').addEventListener('input', () => { $('#repo-error').textContent = ''; $('#repo-url').removeAttribute('aria-invalid'); });
$('#workspace-source').addEventListener('change', event => selectSource(event.target.value));
$('#retry-source').addEventListener('click', () => activeSource() ? startAnalysis(activeSource(), true) : loadWorkspace());
$('#retry-sources').addEventListener('click', loadWorkspace);
$('#remove-source').addEventListener('click', () => removeSources([activeSource()]));
$('#search').addEventListener('input', renderSessions);
$('#risk-filter').addEventListener('change', renderSessions);
$('#source-filter').addEventListener('change', renderSessions);
$('#chart-scope').addEventListener('change', renderCharts);
$('#risk-basis').addEventListener('change', renderCharts);
$('#retry-charts').addEventListener('click', loadChartReports);
$('#retry-report').addEventListener('click', loadReport);
$('#close-dialog').addEventListener('click', () => $('#session-dialog').close());
$('#session-dialog').addEventListener('close', () => {
  if (detailTrigger?.checkVisibility()) detailTrigger.focus();
});
$('#export-report').addEventListener('click', async () => {
  const source = activeSource();
  if (source?.status !== 'ready') return;
  $('#export-report').disabled = true;
  try {
    const cbom = await exportSourceCbom(source.serverId);
    if (source !== activeSource()) return;
    download(JSON.stringify(cbom, null, 2) + '\n', `${source.name.replace(/[^\w.-]+/g, '-')}-cbom.cdx.json`, 'application/vnd.cyclonedx+json');
  } catch (error) {
    if (source === activeSource()) $('#source-status').textContent = `Export failed: ${error.message}`;
  } finally {
    $('#export-report').disabled = activeSource()?.status !== 'ready';
  }
});
$('#export-markdown').addEventListener('click', async () => {
  const source = activeSource();
  if (source?.status !== 'ready') return;
  $('#export-markdown').disabled = true;
  try {
    const markdown = await exportSourceReport(source.serverId);
    if (source !== activeSource()) return;
    download(markdown, `${source.name.replace(/[^\w.-]+/g, '-')}-quantum-report.md`, 'text/markdown');
  } catch (error) {
    if (source === activeSource()) $('#source-status').textContent = `Export failed: ${error.message}`;
  } finally {
    $('#export-markdown').disabled = activeSource()?.status !== 'ready';
  }
});

const pages = { inputs: 'Input sources', analysis: 'Risk analysis' };
let currentPage;
function showPage() {
  const requested = location.hash.slice(2);
  const page = Object.hasOwn(pages, requested) ? requested : 'inputs';
  if (location.hash !== `#/${page}`) history.replaceState(null, '', `#/${page}`);
  if (page === currentPage) return;
  const navigating = currentPage !== undefined;
  currentPage = page;
  if ($('#session-dialog').open) $('#session-dialog').close();
  for (const section of document.querySelectorAll('[data-page]')) section.hidden = section.dataset.page !== page;
  for (const link of document.querySelectorAll('.nav-link')) {
    if (link.hash === `#/${page}`) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  $('#page-name').textContent = pages[page];
  document.title = `QuantumTrace · ${pages[page]}`;
  if (navigating) $(`[data-page="${page}"] h1`).focus({ preventScroll: true });
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', showPage);
$('.skip-link').addEventListener('click', event => {
  event.preventDefault();
  $('#main').focus();
});
showPage();
renderReportSwitcher();
renderSources();
refreshScope();
loadWorkspace();
