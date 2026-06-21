const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8008';

function buildHomepage() {
  return buildCard_('FINALX Gmail Auto', '開啟 Dashboard 或設定 API 位址。', false);
}

function buildContextualCard(e) {
  const message = currentMessage_(e);
  const analysis = analyzeMessage_(message);
  return buildCard_('FINALX 郵件審核', '目前郵件的即時風險分析與人工標註。', true, e, message, analysis);
}

function buildCard_(title, subtitle, includeFeedback, e, message, analysis) {
  const section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(subtitle));

  if (includeFeedback) {
    section.addWidget(CardService.newTextParagraph().setText(analysisSummary_(message, analysis)));
  }

  if (includeFeedback) {
    section
      .addWidget(CardService.newTextInput().setFieldName('notes').setTitle('備註').setMultiline(true))
      .addWidget(button_('誤判安全', 'submitFalsePositive'))
      .addWidget(button_('確認威脅', 'submitConfirmedThreat'))
      .addWidget(button_('漏判威脅', 'submitFalseNegative'));
  }

  section.addWidget(
    CardService.newTextButton()
      .setText('開啟 Dashboard')
      .setOpenLink(CardService.newOpenLink().setUrl(apiBaseUrl_() + '/dashboard'))
  );

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title).setSubtitle(apiBaseUrl_()))
    .addSection(section)
    .build();
}

function submitFalsePositive(e) {
  return submitFeedback_(e, 'false_positive');
}

function submitConfirmedThreat(e) {
  return submitFeedback_(e, 'confirmed_threat');
}

function submitFalseNegative(e) {
  return submitFeedback_(e, 'false_negative');
}

function submitFeedback_(e, verdict) {
  const message = currentMessage_(e);
  if (!message) {
    return notify_('找不到目前 Gmail 郵件。');
  }

  const payload = {
    gmail_id: message.getId(),
    verdict: verdict,
    notes: (e.formInput && e.formInput.notes) || '',
    actor: 'gmail_addon'
  };

  const response = UrlFetchApp.fetch(apiBaseUrl_() + '/api/feedback', {
    method: 'post',
    headers: authHeaders_(),
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  const code = response.getResponseCode();
  if (code < 200 || code >= 300) {
    return notify_('送出失敗：HTTP ' + code);
  }
  return notify_('已送出人工標註，請到 Dashboard 審核。');
}

function analyzeMessage_(message) {
  if (!message) {
    return null;
  }
  const text = [
    '寄件者: ' + message.getFrom(),
    '主旨: ' + message.getSubject(),
    '內容: ' + String(message.getPlainBody() || '').slice(0, 20000)
  ].join('\\n');

  try {
    const response = UrlFetchApp.fetch(apiBaseUrl_() + '/api/analyze-text', {
      method: 'post',
      headers: authHeaders_(),
      contentType: 'application/json',
      payload: JSON.stringify({text: text}),
      muteHttpExceptions: true
    });
    const code = response.getResponseCode();
    if (code < 200 || code >= 300) {
      return {error: 'HTTP ' + code};
    }
    return JSON.parse(response.getContentText());
  } catch (err) {
    return {error: String(err)};
  }
}

function analysisSummary_(message, analysis) {
  if (!message) {
    return '<b>無法讀取目前 Gmail 郵件。</b>';
  }
  if (!analysis) {
    return '<b>尚未取得分析結果。</b>';
  }
  if (analysis.error) {
    return '<b>分析失敗：</b>' + escapeHtml_(analysis.error);
  }
  const risk = escapeHtml_(analysis.risk_level || 'unknown');
  const score = escapeHtml_(analysis.risk_score || 0);
  const reason = escapeHtml_(analysis.label_reason || '');
  const summary = escapeHtml_(analysis.summary || '');
  const topReasons = (analysis.reasons || []).slice(0, 3).map(function(reasonText) {
    return '<li>' + escapeHtml_(reasonText) + '</li>';
  }).join('');
  return [
    '<b>風險：</b>' + risk + ' / ' + score + ' 分<br>',
    '<b>原因：</b>' + reason + '<br>',
    '<b>摘要：</b>' + summary,
    topReasons ? '<ul>' + topReasons + '</ul>' : ''
  ].join('');
}

function currentMessage_(e) {
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    return null;
  }
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

function authHeaders_() {
  const token = apiToken_();
  return token ? {'X-FINALX-API-TOKEN': token} : {};
}

function button_(text, functionName) {
  return CardService.newTextButton()
    .setText(text)
    .setOnClickAction(CardService.newAction().setFunctionName(functionName));
}

function notify_(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}

function apiBaseUrl_() {
  const value = PropertiesService.getScriptProperties().getProperty('FINALX_API_BASE_URL');
  return (value || DEFAULT_API_BASE_URL).replace(/\\/$/, '');
}

function apiToken_() {
  return PropertiesService.getScriptProperties().getProperty('FINALX_API_TOKEN') || '';
}

function escapeHtml_(value) {
  return String(value || '').replace(/[&<>"']/g, function(ch) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
  });
}
