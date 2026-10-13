from __future__ import annotations


DASHBOARD_HTML = """
<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Inbox Sentry Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    canvas { width: 100%; height: 220px; }
    .fallback-card { border: 1px solid #d8dee8; border-radius: 8px; background: white; }
  </style>
</head>
<body class="bg-slate-50 text-slate-950">
  <header class="sticky top-0 z-20 border-b border-slate-200 bg-white/95 backdrop-blur">
    <div class="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
      <div>
        <h1 class="text-2xl font-black tracking-normal">Inbox Sentry Dashboard</h1>
        <p id="updated" class="mt-1 text-sm text-slate-500">loading</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button class="rounded-md bg-blue-600 px-3 py-2 text-sm font-bold text-white hover:bg-blue-700" data-action="scan-dry">Dry-run 掃描</button>
        <button class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-bold hover:border-blue-500 hover:text-blue-700" data-action="scan-real">正式掃描</button>
        <button class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-bold hover:border-blue-500 hover:text-blue-700" data-action="renew-watch">續約 Gmail watch</button>
        <button class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-bold hover:border-blue-500 hover:text-blue-700" data-action="set-token">API Token</button>
        <button class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-bold hover:border-blue-500 hover:text-blue-700" data-action="refresh">重新整理</button>
      </div>
    </div>
  </header>

  <main class="mx-auto grid max-w-7xl gap-5 px-5 py-5">
    <section id="metrics" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6"></section>

    <section class="grid gap-5 lg:grid-cols-[1.35fr_.85fr]">
      <div class="fallback-card p-4 shadow-sm">
        <div class="mb-3 flex items-baseline justify-between gap-3">
          <h2 class="text-lg font-extrabold">掃描趨勢</h2>
          <span class="text-sm text-slate-500">最近 14 天</span>
        </div>
        <canvas id="trendChart" height="220"></canvas>
      </div>
      <div class="fallback-card p-4 shadow-sm">
        <div class="mb-3 flex items-baseline justify-between gap-3">
          <h2 class="text-lg font-extrabold">誤判與確認</h2>
          <span id="fpLabel" class="text-sm text-slate-500">0%</span>
        </div>
        <canvas id="feedbackChart" height="220"></canvas>
      </div>
    </section>

    <section class="grid gap-5 lg:grid-cols-[1.2fr_.8fr]">
      <div class="fallback-card p-4 shadow-sm">
        <div class="mb-3 flex items-baseline justify-between gap-3">
          <h2 class="text-lg font-extrabold">最近事件</h2>
          <span class="text-sm text-slate-500">新增人工標註後會進入審核流程</span>
        </div>
        <div id="events" class="overflow-x-auto"></div>
        <div id="eventDetail" class="mt-4 hidden rounded-md border border-slate-200 bg-slate-50 p-4"></div>
      </div>
      <div class="grid gap-5">
        <div class="fallback-card p-4 shadow-sm">
          <div class="mb-3 flex items-baseline justify-between gap-3">
            <h2 class="text-lg font-extrabold">Cache / Queue</h2>
            <span class="text-sm text-slate-500">外部情資查核</span>
          </div>
          <div id="cacheQueue"></div>
        </div>
        <div class="fallback-card p-4 shadow-sm">
          <div class="mb-3 flex items-baseline justify-between gap-3">
            <h2 class="text-lg font-extrabold">Watch 狀態</h2>
            <span class="text-sm text-slate-500">Gmail Push</span>
          </div>
          <pre id="state" class="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md bg-slate-950 p-3 text-xs text-slate-100"></pre>
        </div>
      </div>
    </section>

    <section class="grid gap-5 lg:grid-cols-2">
      <div class="fallback-card p-4 shadow-sm">
        <div class="mb-3 flex items-baseline justify-between gap-3">
          <h2 class="text-lg font-extrabold">待審核標註</h2>
          <span class="text-sm text-slate-500">批准後才會進入學習資料庫</span>
        </div>
        <div id="pendingFeedback" class="overflow-x-auto"></div>
      </div>
      <div class="fallback-card p-4 shadow-sm">
        <div class="mb-3 flex items-baseline justify-between gap-3">
          <h2 class="text-lg font-extrabold">標註資料庫</h2>
          <span class="text-sm text-slate-500">已批准樣本</span>
        </div>
        <div id="labels" class="overflow-x-auto"></div>
      </div>
    </section>

    <section class="fallback-card p-4 shadow-sm">
      <div class="mb-3 flex items-baseline justify-between gap-3">
        <h2 class="text-lg font-extrabold">近期人工回饋</h2>
        <span class="text-sm text-slate-500">最新 20 筆</span>
      </div>
      <div id="feedback" class="overflow-x-auto"></div>
    </section>
  </main>

  <script>
    let latestEvents = new Map();

    const api = async (path, options = {}, allowTokenPrompt = true) => {
      const headers = new Headers(options.headers || {});
      const token = currentApiToken();
      if (token && !headers.has('X-FINALX-API-TOKEN')) {
        headers.set('X-FINALX-API-TOKEN', token);
      }
      const res = await fetch(path, {...options, headers});
      if (res.status === 401 && allowTokenPrompt) {
        const nextToken = prompt('請輸入 Inbox Sentry API Token', currentApiToken());
        if (nextToken !== null) {
          saveApiToken(nextToken);
          return api(path, options, false);
        }
      }
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    };

    function currentApiToken() {
      return localStorage.getItem('finalxApiToken') || '';
    }

    function saveApiToken(value) {
      const token = (value || '').trim();
      if (token) localStorage.setItem('finalxApiToken', token);
      else localStorage.removeItem('finalxApiToken');
    }

    function setApiToken() {
      const nextToken = prompt('設定 Inbox Sentry API Token；留空會清除。', currentApiToken());
      if (nextToken === null) return;
      saveApiToken(nextToken);
      loadAll().catch((err) => {
        document.getElementById('state').textContent = err.message;
      });
    }

    const tableClass = 'min-w-full border-collapse text-left text-sm';
    const thClass = 'border-b border-slate-200 bg-slate-100 px-3 py-2 text-xs font-black uppercase tracking-wide text-slate-600';
    const tdClass = 'border-b border-slate-100 px-3 py-2 align-top';

    document.addEventListener('click', async (event) => {
      const target = event.target.closest('button');
      if (!target) return;
      const action = target.dataset.action;
      if (!action) return;
      target.disabled = true;
      target.classList.add('opacity-60');
      try {
        if (action === 'refresh') await loadAll();
        if (action === 'scan-dry') await scanNow(true);
        if (action === 'scan-real') await scanNow(false);
        if (action === 'renew-watch') await renewWatch();
        if (action === 'set-token') setApiToken();
        if (action === 'detail') renderEventDetail(latestEvents.get(target.dataset.gmailId));
        if (action === 'feedback') await submitFeedback(target.dataset.gmailId, target.dataset.verdict);
        if (action === 'review') await reviewFeedback(target.dataset.feedbackId, target.dataset.status);
      } finally {
        target.disabled = false;
        target.classList.remove('opacity-60');
      }
    });

    async function loadAll() {
      const [metrics, events, feedback, pending, labels, queue] = await Promise.all([
        api('/api/dashboard/metrics'),
        api('/api/events?limit=25'),
        api('/api/feedback?limit=20'),
        api('/api/feedback?limit=20&review_status=pending'),
        api('/api/labeled-dataset?limit=20'),
        api('/api/threat-queue?limit=20'),
      ]);
      document.getElementById('updated').textContent = '更新時間 ' + new Date().toLocaleString();
      renderMetrics(metrics);
      renderEvents(events.items || []);
      renderFeedback(feedback.items || [], 'feedback', true);
      renderFeedback(pending.items || [], 'pendingFeedback', false);
      renderLabels(labels.items || []);
      renderCacheQueue(metrics, queue.items || []);
      renderState(metrics);
      drawTrendChart(metrics.trends?.daily || []);
      drawFeedbackChart(metrics.trends?.daily || []);
    }

    function renderMetrics(data) {
      const actions = data.events?.actions || {};
      const feedback = data.feedback || {};
      const cache = data.cache || {};
      const queue = data.queue || {};
      const labels = data.labels || {};
      const fpRate = Math.round((feedback.false_positive_rate || 0) * 1000) / 10;
      const items = [
        ['掃描事件', data.events?.total ?? 0, '全部 MongoDB scan_events'],
        ['高風險標記', actions.marked ?? 0, '已套用 Inbox Sentry 高風險'],
        ['中風險警告', actions.warned ?? 0, '已套用 Inbox Sentry 中風險'],
        ['誤判率', fpRate + '%', `${feedback.false_positive_count || 0}/${feedback.reviewed_count || 0} approved`],
        ['Cache', `${cache.total ?? 0}/${cache.max_entries ?? 0}`, `hit ${cache.hit_count ?? 0}`],
        ['Queue', `${queue.total ?? 0}/${queue.max_entries ?? 0}`, `seen ${queue.seen_count ?? 0}`],
        ['待審核', feedback.pending ?? 0, 'pending feedback'],
        ['標註樣本', labels.total ?? 0, 'approved labeled dataset'],
      ];
      document.getElementById('metrics').innerHTML = items.map(([label, value, hint]) => `
        <div class="fallback-card p-4 shadow-sm">
          <div class="text-xs font-bold uppercase tracking-wide text-slate-500">${escapeHtml(label)}</div>
          <div class="mt-2 text-2xl font-black">${escapeHtml(value)}</div>
          <div class="mt-1 truncate text-xs text-slate-500">${escapeHtml(hint)}</div>
        </div>
      `).join('');
      document.getElementById('fpLabel').textContent = `誤判率 ${fpRate}%`;
    }

    function renderEvents(items) {
      latestEvents = new Map(items.map((item) => [String(item.gmail_id || ''), item]).filter(([key]) => key));
      const rows = items.map((item) => `
        <tr>
          <td class="${tdClass}">${riskPill(item.risk_level)}<div class="mt-1 text-xs text-slate-500">${escapeHtml(item.risk_score ?? 0)} / ${escapeHtml(item.label_reason || '')}</div></td>
          <td class="${tdClass}"><div class="font-bold">${escapeHtml(item.subject || '(無主旨)')}</div><div class="mt-1 text-xs text-slate-500">${escapeHtml(item.sender || item.sender_email || '')}</div></td>
          <td class="${tdClass}">${escapeHtml(item.action || '')}<div class="mt-1 text-xs text-slate-500">${escapeHtml(formatTime(item.created_at))}</div></td>
          <td class="${tdClass}">
            <div class="flex flex-wrap gap-1">
              ${detailButton(item.gmail_id)}
              ${feedbackButton(item.gmail_id, 'false_positive', '誤判安全')}
              ${feedbackButton(item.gmail_id, 'confirmed_threat', '確認威脅')}
              ${feedbackButton(item.gmail_id, 'false_negative', '漏判威脅')}
            </div>
          </td>
        </tr>
      `).join('');
      document.getElementById('events').innerHTML = table(['風險', '郵件', '動作', '人工標註'], rows, 4);
    }

    function renderEventDetail(item) {
      const target = document.getElementById('eventDetail');
      if (!item) {
        target.classList.add('hidden');
        target.innerHTML = '';
        return;
      }
      target.classList.remove('hidden');
      const evidence = (item.evidence || [])
        .filter((entry) => Number(entry.score_delta || 0) !== 0 || ['malicious', 'suspicious', 'safe'].includes(entry.status))
        .sort((a, b) => Math.abs(Number(b.score_delta || 0)) - Math.abs(Number(a.score_delta || 0)))
        .slice(0, 10);
      const rules = item.rule_hits || [];
      const indicators = item.indicators || [];
      target.innerHTML = `
        <div class="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div class="flex flex-wrap items-center gap-2">${riskPill(item.risk_level)}<span class="text-sm font-black">${escapeHtml(item.risk_score ?? 0)} 分</span><span class="text-sm text-slate-500">信心 ${escapeHtml(item.confidence_score ?? 0)}</span></div>
            <h3 class="mt-2 text-base font-black">${escapeHtml(item.subject || '(無主旨)')}</h3>
            <p class="mt-1 text-sm text-slate-600">${escapeHtml(item.summary || '')}</p>
          </div>
          <button class="rounded-md border border-slate-300 px-2 py-1 text-xs font-bold hover:border-slate-500" onclick="renderEventDetail(null)">關閉</button>
        </div>
        <div class="mt-4 grid gap-4 lg:grid-cols-2">
          <div>
            <h4 class="mb-2 text-sm font-black">分數拆解</h4>
            ${breakdownBars(item.score_breakdown || {})}
          </div>
          <div>
            <h4 class="mb-2 text-sm font-black">主要建議</h4>
            ${(item.recommendations || []).slice(0, 4).map((text) => `<div class="mb-1 rounded-md bg-white px-3 py-2 text-sm">${escapeHtml(text)}</div>`).join('') || '<div class="text-sm text-slate-500">沒有建議</div>'}
          </div>
        </div>
        <div class="mt-4 grid gap-4 lg:grid-cols-3">
          <div>
            <h4 class="mb-2 text-sm font-black">命中規則</h4>
            ${rules.length ? rules.slice(0, 8).map((rule) => `<div class="mb-2 rounded-md bg-white p-2 text-sm"><div class="font-bold">${escapeHtml(rule.name || rule.rule_id)}</div><div class="text-xs text-slate-500">+${escapeHtml(rule.score_delta || 0)} / ${escapeHtml(rule.category || '')}</div><div class="mt-1 text-xs text-slate-600">${escapeHtml(rule.explanation || '')}</div></div>`).join('') : '<div class="text-sm text-slate-500">沒有規則命中</div>'}
          </div>
          <div>
            <h4 class="mb-2 text-sm font-black">證據</h4>
            ${evidence.length ? evidence.map((entry) => evidenceCard(entry)).join('') : '<div class="text-sm text-slate-500">沒有額外證據</div>'}
          </div>
          <div>
            <h4 class="mb-2 text-sm font-black">抽取指標</h4>
            ${indicators.length ? indicators.slice(0, 12).map((entry) => `<div class="mb-1 rounded-md bg-white px-2 py-1 text-xs"><span class="font-bold">${escapeHtml(entry.type)}</span> ${escapeHtml(entry.value)}</div>`).join('') : '<div class="text-sm text-slate-500">沒有指標</div>'}
          </div>
        </div>
      `;
      target.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    }

    function renderFeedback(items, targetId, includeStatus) {
      const rows = items.map((item) => `
        <tr>
          <td class="${tdClass}"><span class="rounded-full bg-slate-100 px-2 py-1 text-xs font-bold">${escapeHtml(item.verdict)}</span>${includeStatus ? `<div class="mt-1 text-xs text-slate-500">${escapeHtml(item.review_status || 'pending')}</div>` : ''}</td>
          <td class="${tdClass}"><div class="font-bold">${escapeHtml(item.subject || item.gmail_id)}</div><div class="mt-1 text-xs text-slate-500">${escapeHtml(item.org_domain || item.sender_domain || '')}</div></td>
          <td class="${tdClass}">${escapeHtml(formatTime(item.created_at))}</td>
          <td class="${tdClass}">${reviewButtons(item)}</td>
        </tr>
      `).join('');
      document.getElementById(targetId).innerHTML = table(['標註', '郵件', '時間', '審核'], rows, 4);
    }

    function renderLabels(items) {
      const rows = items.map((item) => `
        <tr>
          <td class="${tdClass}"><span class="${item.label === 'threat' ? 'text-red-700' : 'text-emerald-700'} font-black">${escapeHtml(item.label)}</span><div class="mt-1 text-xs text-slate-500">${escapeHtml(item.verdict || '')}</div></td>
          <td class="${tdClass}"><div class="font-bold">${escapeHtml(item.subject || item.gmail_id)}</div><div class="mt-1 text-xs text-slate-500">${escapeHtml(item.sender_email || item.org_domain || '')}</div></td>
          <td class="${tdClass}">${escapeHtml(item.previous_risk_score ?? '')}</td>
          <td class="${tdClass}">${escapeHtml(formatTime(item.approved_at || item.created_at))}</td>
        </tr>
      `).join('');
      document.getElementById('labels').innerHTML = table(['Label', '郵件', '原分數', '批准時間'], rows, 4);
    }

    function renderCacheQueue(metrics, queueItems) {
      const cache = metrics.cache || {};
      const queue = metrics.queue || {};
      const cacheRate = cache.max_entries ? Math.min(100, Math.round((cache.total || 0) / cache.max_entries * 100)) : 0;
      const queueRate = queue.max_entries ? Math.min(100, Math.round((queue.total || 0) / queue.max_entries * 100)) : 0;
      const rows = queueItems.map((item) => `
        <tr>
          <td class="${tdClass}">${escapeHtml(item.source || '')}</td>
          <td class="${tdClass}">${escapeHtml(item.indicator || '')}<div class="mt-1 text-xs text-slate-500">${escapeHtml(item.reason || '')}</div></td>
          <td class="${tdClass}">${escapeHtml(item.status || '')}</td>
        </tr>
      `).join('');
      document.getElementById('cacheQueue').innerHTML = `
        ${limitBar('Cache 使用量', cacheRate, `${cache.total || 0}/${cache.max_entries || 0}`)}
        ${limitBar('Queue 使用量', queueRate, `${queue.total || 0}/${queue.max_entries || 0}`)}
        <div class="mt-4 overflow-x-auto">${table(['來源', 'Indicator', '狀態'], rows, 3)}</div>
      `;
    }

    function renderState(metrics) {
      document.getElementById('state').textContent = JSON.stringify({
        watch: metrics.state,
        cache: metrics.cache,
        queue: metrics.queue,
        feedback: metrics.feedback,
      }, null, 2);
    }

    function feedbackButton(gmailId, verdict, label) {
      if (!gmailId) return '';
      return `<button class="rounded-md border border-slate-300 px-2 py-1 text-xs font-bold hover:border-blue-500 hover:text-blue-700" data-action="feedback" data-gmail-id="${escapeAttr(gmailId)}" data-verdict="${escapeAttr(verdict)}">${escapeHtml(label)}</button>`;
    }

    function detailButton(gmailId) {
      if (!gmailId) return '';
      return `<button class="rounded-md bg-slate-900 px-2 py-1 text-xs font-bold text-white hover:bg-slate-700" data-action="detail" data-gmail-id="${escapeAttr(gmailId)}">詳情</button>`;
    }

    function breakdownBars(breakdown) {
      const items = [
        ['message_intent', '訊息意圖'],
        ['url_structure', 'URL 結構'],
        ['external_reputation', '外部情資'],
        ['llm_intent', 'LLM 意圖'],
        ['sensitive_indicators', '敏感指標'],
        ['uncertainty', '不確定性'],
        ['calibration_adjustment', '校準調整'],
      ];
      return items.map(([key, label]) => {
        const value = Number(breakdown[key] || 0);
        const width = Math.min(100, Math.abs(value));
        const color = value < 0 ? 'bg-emerald-600' : 'bg-blue-600';
        return `
          <div class="mb-2">
            <div class="mb-1 flex justify-between text-xs"><span class="font-bold">${escapeHtml(label)}</span><span class="${value < 0 ? 'text-emerald-700' : 'text-slate-600'}">${escapeHtml(value)}</span></div>
            <div class="h-2 overflow-hidden rounded-full bg-slate-200"><div class="h-2 ${color}" style="width:${width}%"></div></div>
          </div>
        `;
      }).join('');
    }

    function evidenceCard(entry) {
      const score = Number(entry.score_delta || 0);
      const tone = score < 0 ? 'text-emerald-700' : score > 0 ? 'text-red-700' : 'text-slate-600';
      return `
        <div class="mb-2 rounded-md bg-white p-2 text-sm">
          <div class="flex justify-between gap-2"><span class="font-bold">${escapeHtml(entry.title || entry.source)}</span><span class="${tone} font-black">${score > 0 ? '+' : ''}${escapeHtml(score)}</span></div>
          <div class="mt-1 break-words text-xs text-slate-500">${escapeHtml(entry.indicator || '')}</div>
          <div class="mt-1 text-xs text-slate-600">${escapeHtml(entry.detail || '')}</div>
        </div>
      `;
    }

    function reviewButtons(item) {
      if (!item.feedback_id || item.review_status !== 'pending') return '<span class="text-xs text-slate-500">已處理</span>';
      return `
        <div class="flex flex-wrap gap-1">
          <button class="rounded-md bg-emerald-600 px-2 py-1 text-xs font-bold text-white hover:bg-emerald-700" data-action="review" data-feedback-id="${escapeAttr(item.feedback_id)}" data-status="approved">批准</button>
          <button class="rounded-md border border-slate-300 px-2 py-1 text-xs font-bold hover:border-red-500 hover:text-red-700" data-action="review" data-feedback-id="${escapeAttr(item.feedback_id)}" data-status="rejected">拒絕</button>
        </div>
      `;
    }

    async function submitFeedback(gmailId, verdict) {
      if (!gmailId) return;
      const notes = prompt('備註', '') || '';
      await api('/api/feedback', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({gmail_id: gmailId, verdict, notes, actor: 'dashboard'})
      });
      await loadAll();
    }

    async function reviewFeedback(feedbackId, status) {
      if (!feedbackId || !status) return;
      const reviewNotes = prompt(status === 'approved' ? '批准備註' : '拒絕原因', '') || '';
      await api(`/api/feedback/${encodeURIComponent(feedbackId)}/review`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({review_status: status, reviewer: 'dashboard', review_notes: reviewNotes})
      });
      await loadAll();
    }

    async function scanNow(dryRun) {
      await api('/api/scan-now?dry_run=' + String(dryRun), {method: 'POST'});
      await loadAll();
    }

    async function renewWatch() {
      await api('/api/gmail/watch', {method: 'POST'});
      await loadAll();
    }

    function table(headers, rows, colspan) {
      return `<table class="${tableClass}"><thead><tr>${headers.map((item) => `<th class="${thClass}">${escapeHtml(item)}</th>`).join('')}</tr></thead><tbody>${rows || `<tr><td class="${tdClass}" colspan="${colspan}">尚無資料</td></tr>`}</tbody></table>`;
    }

    function limitBar(label, percent, value) {
      const color = percent >= 90 ? 'bg-red-600' : percent >= 70 ? 'bg-amber-500' : 'bg-blue-600';
      return `
        <div class="mb-3">
          <div class="mb-1 flex justify-between text-sm"><span class="font-bold">${escapeHtml(label)}</span><span class="text-slate-500">${escapeHtml(value)}</span></div>
          <div class="h-2 overflow-hidden rounded-full bg-slate-200"><div class="h-2 ${color}" style="width:${percent}%"></div></div>
        </div>
      `;
    }

    function riskPill(level) {
      const map = {critical: 'bg-red-700 text-white', high: 'bg-red-600 text-white', medium: 'bg-amber-500 text-white', low: 'bg-emerald-600 text-white'};
      return `<span class="rounded-full px-2 py-1 text-xs font-black ${map[level] || 'bg-slate-200 text-slate-700'}">${escapeHtml(level || 'unknown')}</span>`;
    }

    function drawTrendChart(days) {
      drawBars('trendChart', days, [
        ['marked', '#dc2626'],
        ['warned', '#d97706'],
        ['skipped', '#059669'],
        ['error', '#475569'],
      ]);
    }

    function drawFeedbackChart(days) {
      drawBars('feedbackChart', days, [
        ['false_positive', '#2563eb'],
        ['confirmed_threat', '#dc2626'],
        ['false_negative', '#7c3aed'],
      ]);
    }

    function drawBars(canvasId, days, series) {
      const canvas = document.getElementById(canvasId);
      const ctx = canvas.getContext('2d');
      const ratio = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = Math.max(1, Math.floor(rect.width * ratio));
      canvas.height = Math.floor(220 * ratio);
      ctx.scale(ratio, ratio);
      const width = rect.width;
      const height = 220;
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = '#f8fafc';
      ctx.fillRect(0, 0, width, height);
      const pad = {left: 34, right: 10, top: 12, bottom: 30};
      const plotW = width - pad.left - pad.right;
      const plotH = height - pad.top - pad.bottom;
      const maxValue = Math.max(1, ...days.map((day) => series.reduce((sum, [key]) => sum + Number(day[key] || 0), 0)));
      ctx.strokeStyle = '#d8dee8';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = pad.top + plotH * i / 4;
        ctx.beginPath();
        ctx.moveTo(pad.left, y);
        ctx.lineTo(width - pad.right, y);
        ctx.stroke();
      }
      const gap = 4;
      const barW = Math.max(6, plotW / Math.max(1, days.length) - gap);
      days.forEach((day, index) => {
        const x = pad.left + index * (plotW / Math.max(1, days.length)) + gap / 2;
        let y = pad.top + plotH;
        series.forEach(([key, color]) => {
          const value = Number(day[key] || 0);
          const h = value / maxValue * plotH;
          y -= h;
          ctx.fillStyle = color;
          ctx.fillRect(x, y, barW, h);
        });
        if (index === 0 || index === days.length - 1 || index % 4 === 0) {
          ctx.fillStyle = '#64748b';
          ctx.font = '11px sans-serif';
          ctx.fillText((day.date || '').slice(5), x - 3, height - 10);
        }
      });
    }

    function formatTime(value) {
      if (!value) return '';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return String(value);
      return date.toLocaleString();
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    }

    function escapeAttr(value) {
      return escapeHtml(value).replace(/`/g, '&#96;');
    }

    loadAll().catch((err) => {
      document.getElementById('state').textContent = err.message;
    });
    window.addEventListener('resize', () => loadAll().catch(() => {}));
    setInterval(() => loadAll().catch(() => {}), 30000);
  </script>
</body>
</html>
"""
