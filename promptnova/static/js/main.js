document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('analysis-form');
  const promptInput = document.getElementById('prompt-input');
  const analyzeBtn = document.getElementById('analyze-btn');
  const clearBtn = document.getElementById('clear-btn');
  const promptCount = document.getElementById('prompt-count');
  const analysisSubtitle = document.getElementById('analysis-subtitle');

  const compareSection = document.getElementById('compare-section');
  const frameworkAnalysisDetails = document.getElementById('framework-analysis-details');

  const sanitizedPromptCard = document.getElementById('sanitized-prompt-card');
  const sanitizedPromptContent = document.getElementById('sanitized-prompt-content');
  const copySanitizedBtn = document.getElementById('copy-sanitized-btn');

  const copyReportBtn = document.getElementById('copy-report-btn');
  const downloadReportBtn = document.getElementById('download-report-btn');

  const feedbackBar = document.getElementById('feedback-bar');
  const feedbackBenignBtn = document.getElementById('feedback-benign-btn');
  const feedbackMaliciousBtn = document.getElementById('feedback-malicious-btn');

  const mlTelemetryCard = document.getElementById('ml-telemetry');
  const mlModelVersion = document.getElementById('ml-model-version');
  const mlConfidence = document.getElementById('ml-confidence');
  const mlTopPreds = document.getElementById('ml-top-preds');
  const mlStatus = document.getElementById('ml-status');
  const mlEval = document.getElementById('ml-eval');
  const evaluateBtn = document.getElementById('evaluate-ml-btn');
  const retrainBtn = document.getElementById('retrain-ml-btn');

  const intelSection = document.getElementById('intel-section');
  const riskDial = document.getElementById('risk-dial');
  const riskDialValue = document.getElementById('risk-dial-value');
  const riskSummary = document.getElementById('risk-summary');
  const layerHeatmap = document.getElementById('layer-heatmap');
  const mlSpectrum = document.getElementById('ml-spectrum');
  const metadataGrid = document.getElementById('ml-metadata-grid');
  const groqSection = document.getElementById('groq-section');
  const groqDirectResponse = document.getElementById('groq-direct-response');
  const groqFrameworkResponse = document.getElementById('groq-framework-response');
  const groqInjectionTag = document.getElementById('groq-injection-tag');
  const groqMlTag = document.getElementById('groq-ml-tag');

  const sampleButtons = document.querySelectorAll('.sample-btn');
  const toastContainer = document.getElementById('toast-container');
  const historyList = document.getElementById('history-list');

  const apiPill = document.getElementById('api-pill');
  const mlPill = document.getElementById('ml-pill');
  const themeToggle = document.getElementById('theme-toggle');

  let lastAnalysis = null;
  let mlMetadataCache = {};

  applySavedTheme();
  updatePromptCount();
  resetResultsUI();
  bootstrapStatus();
  bootstrapMLStatus();
  renderHistory();

  themeToggle?.addEventListener('click', () => {
    const current = document.body.getAttribute('data-theme') || 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    document.body.setAttribute('data-theme', next);
    try {
      localStorage.setItem('pg_theme', next);
    } catch (_) {}
  });

  sampleButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const sample = btn.getAttribute('data-sample') || '';
      promptInput.value = sample;
      updatePromptCount();
      runAnalysis();
    });
  });

  promptInput?.addEventListener('input', updatePromptCount);
  promptInput?.addEventListener('keydown', (e) => {
    const key = (e.key || '').toLowerCase();
    if (key === 'enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      runAnalysis();
      return;
    }
    if (key === 'escape') {
      e.preventDefault();
      clearAll();
    }
  });

  clearBtn?.addEventListener('click', () => clearAll());

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleAnalyze();
  });

  copyReportBtn?.addEventListener('click', async () => {
    if (!lastAnalysis) return;
    try {
      await safeCopyText(JSON.stringify(lastAnalysis, null, 2));
      showToast('Copied analysis JSON to clipboard.', 'success');
    } catch (err) {
      showToast(`Unable to copy: ${err.message}`, 'error');
    }
  });

  downloadReportBtn?.addEventListener('click', () => {
    if (!lastAnalysis) return;
    downloadJson('prompt_nova_report.json', lastAnalysis);
  });

  copySanitizedBtn?.addEventListener('click', async () => {
    const text = sanitizedPromptContent?.textContent || '';
    if (!text) return;
    try {
      await safeCopyText(text);
      showToast('Copied sanitized prompt.', 'success');
    } catch (err) {
      showToast(`Unable to copy: ${err.message}`, 'error');
    }
  });

  feedbackBenignBtn?.addEventListener('click', async () => {
    await submitFeedback('benign');
  });

  feedbackMaliciousBtn?.addEventListener('click', async () => {
    await submitFeedback('malicious');
  });

  retrainBtn?.addEventListener('click', async () => {
    if (!retrainBtn) return;
    retrainBtn.disabled = true;
    const originalText = retrainBtn.textContent;
    retrainBtn.textContent = 'Retraining...';
    try {
      const res = await fetch('/ml/retrain', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to retrain model');
      renderMetadata(data.metadata || {});
      updateMLStatusBlock('online', data.metadata || {});
      showToast('ML detector retrained successfully.', 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      retrainBtn.disabled = false;
      retrainBtn.textContent = originalText;
    }
  });

  evaluateBtn?.addEventListener('click', async () => {
    if (!mlEval || !evaluateBtn) return;
    evaluateBtn.disabled = true;
    const originalText = evaluateBtn.textContent;
    evaluateBtn.textContent = 'Evaluating...';
    mlEval.style.display = 'block';
    mlEval.innerHTML = '<div class="loading">Evaluating ML model...</div>';
    try {
      const res = await fetch('/ml/evaluate');
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to evaluate model');
      mlEval.innerHTML = renderEvalReport(data);
      showToast('Evaluation complete.', 'success');
    } catch (err) {
      mlEval.innerHTML = `<div class="error"><strong>Error:</strong> ${escapeHtml(err.message)}</div>`;
      showToast(err.message, 'error');
    } finally {
      evaluateBtn.disabled = false;
      evaluateBtn.textContent = originalText;
    }
  });

  async function handleAnalyze() {
    const prompt = (promptInput?.value || '').trim();
    if (!prompt) {
      showToast('Please enter a prompt to analyze.', 'info');
      return;
    }

    setAnalyzeLoading(true);
    compareSection && (compareSection.style.display = 'block');
    if (analysisSubtitle) analysisSubtitle.textContent = 'Analyzing...';
    if (frameworkAnalysisDetails) {
      frameworkAnalysisDetails.innerHTML = '<div class="loading">Running multi-layer analysis...</div>';
    }
    sanitizedPromptCard && (sanitizedPromptCard.style.display = 'none');
    feedbackBar && (feedbackBar.style.display = 'none');
    mlTelemetryCard && (mlTelemetryCard.style.display = 'none');
    intelSection && (intelSection.style.display = 'none');
    mlEval && (mlEval.style.display = 'none');
    if (groqSection) groqSection.style.display = 'block';
    if (groqDirectResponse) groqDirectResponse.textContent = 'Loading...';
    if (groqFrameworkResponse) groqFrameworkResponse.textContent = 'Loading...';
    if (groqInjectionTag) groqInjectionTag.textContent = 'Prompt injection: checking...';
    if (groqMlTag) groqMlTag.textContent = 'ML: checking...';

    const start = performance.now();
    try {
      const compareResponse = await fetch('/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      });

      const compareData = await compareResponse.json();
      if (!compareResponse.ok || !compareData.analysis) {
        throw new Error(compareData.error || 'Unable to run Groq comparison');
      }

      const elapsedMs = Math.round(performance.now() - start);
      displayAnalysisResults(compareData.analysis, elapsedMs);
      displayGroqComparison(compareData);
    } catch (error) {
      // Fallback to analysis-only endpoint if Groq comparison fails.
      try {
        const response = await fetch('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt }),
        });

        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || 'An error occurred during analysis');
        }

        const elapsedMs = Math.round(performance.now() - start);
        displayAnalysisResults(data, elapsedMs);
        hideGroqSection('Groq comparison unavailable.');
      } catch (fallbackError) {
        if (analysisSubtitle) analysisSubtitle.textContent = 'Analysis failed';
        if (frameworkAnalysisDetails) {
          frameworkAnalysisDetails.innerHTML = `<div class="error"><strong>Error:</strong> ${escapeHtml(fallbackError.message)}</div>`;
        }
        showToast(fallbackError.message, 'error');
      }
    } finally {
      setAnalyzeLoading(false);
    }
  }

  function displayAnalysisResults(analysis, elapsedMs) {
    lastAnalysis = analysis;

    const action = String(analysis.action || 'ALLOW').toUpperCase();
    const riskScore = clampInt(analysis.risk_score, 0, 100, 0);
    const riskLevel = String(analysis.risk_level || 'Low');
    const attacks = Array.isArray(analysis.detected_attacks) ? analysis.detected_attacks : [];
    const layers = analysis.layers || {};
    const ruleLayer = layers.rule || layers.rule_based || {};
    const semanticLayer = layers.semantic || {};
    const policyLayer = layers.policy || {};
    const riskLayer = layers.risk || {};
    const mlLayer = layers.ml || semanticLayer.ml || {};

    if (analysisSubtitle) {
      const now = new Date();
      const t = now.toLocaleTimeString();
      analysisSubtitle.textContent = `Completed in ${elapsedMs} ms at ${t}`;
    }

    const badgeClass = action === 'ALLOW'
      ? 'badge--allow'
      : action === 'BLOCK'
        ? 'badge--block'
        : 'badge--rewrite';

    const layerTags = [
      { label: 'Rule', score: ruleLayer?.score },
      { label: 'Semantic (ML)', score: semanticLayer?.score },
      { label: 'Policy', score: policyLayer?.score },
      { label: 'Risk', score: riskLayer?.score },
    ]
      .map((x) => {
        const pct = Math.round(clampNumber(x.score, 0, 1, 0) * 100);
        return `<span class="tag">${escapeHtml(x.label)}: ${pct}%</span>`;
      })
      .join('');

    const attackTags = attacks.length
      ? attacks.map((a) => `<span class="tag">${escapeHtml(String(a))}</span>`).join('')
      : '<span class="muted">None</span>';

    const explanation = String(analysis.explanation || '');
    const timelineHtml = renderDecisionTimeline(analysis.decision_timeline || []);

    frameworkAnalysisDetails.innerHTML = `
      <div class="result-item">
        <span class="result-label">Action</span>
        <div class="result-value">
          <span class="badge ${badgeClass}">${escapeHtml(action)}</span>
        </div>
      </div>
      <div class="result-item">
        <span class="result-label">Hybrid Risk</span>
        <div class="result-value">
          <strong>${riskScore}/100</strong> <span class="muted">(${escapeHtml(riskLevel)})</span>
          <div class="risk-bar"><div class="risk-fill" style="width:${riskScore}%;"></div></div>
        </div>
      </div>
      <div class="result-item">
        <span class="result-label">Framework Layers</span>
        <div class="tags">${layerTags}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Detected Signals</span>
        <div class="tags">${attackTags}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Explanation</span>
        <div class="result-value">${escapeHtml(explanation)}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Decision Timeline</span>
        <div class="timeline">${timelineHtml}</div>
      </div>
    `;

    if (feedbackBar) feedbackBar.style.display = 'flex';
    resetFeedbackButtons();

    if (['REWRITE', 'SANITIZE', 'ISOLATE'].includes(action) && analysis.sanitized_prompt && sanitizedPromptContent) {
      sanitizedPromptCard.style.display = 'block';
      sanitizedPromptContent.textContent = String(analysis.sanitized_prompt);
    } else if (sanitizedPromptCard) {
      sanitizedPromptCard.style.display = 'none';
    }

    hydrateMLTelemetry(mlLayer);
    renderRiskDial({ riskScore, riskLevel, action });
    renderLayerHeatmap(layers);
    renderMLSpectrum(mlLayer?.top_predictions || []);
    renderMetadata(mlLayer?.metadata || mlMetadataCache);

    addToHistory(analysis);
    renderHistory();

    if (intelSection) intelSection.style.display = 'block';
  }

  function displayGroqComparison(payload) {
    if (!groqSection) return;
    groqSection.style.display = 'block';

    const direct = payload?.direct_response ?? '';
    const framework = payload?.framework_response ?? '';
    if (groqDirectResponse) groqDirectResponse.textContent = String(direct || 'No direct response available.');
    if (groqFrameworkResponse) groqFrameworkResponse.textContent = String(framework || 'No framework response available.');

    const analysis = payload?.analysis || {};
    const detected = Array.isArray(analysis.detected_attacks) && analysis.detected_attacks.length > 0;
    if (groqInjectionTag) {
      groqInjectionTag.textContent = detected ? 'Prompt injection: detected' : 'Prompt injection: none';
    }

    const semantic = analysis.layers?.semantic || {};
    const intent = semantic.intent_category || 'unknown';
    const confidence = semantic.semantic_confidence;
    if (groqMlTag) {
      groqMlTag.textContent = Number.isFinite(Number(confidence))
        ? `ML: ${intent} (${confidence}%)`
        : `ML: ${intent}`;
    }
  }

  function hideGroqSection(message) {
    if (!groqSection) return;
    groqSection.style.display = 'block';
    const text = message || 'Groq comparison unavailable.';
    if (groqDirectResponse) groqDirectResponse.textContent = text;
    if (groqFrameworkResponse) groqFrameworkResponse.textContent = text;
  }

  function hydrateMLTelemetry(mlLayer) {
    if (!mlTelemetryCard) return;
    if (!mlLayer) {
      mlTelemetryCard.style.display = 'none';
      return;
    }

    mlTelemetryCard.style.display = 'block';

    const meta = mlLayer.metadata || {};
    mlMetadataCache = meta;
    if (mlModelVersion) mlModelVersion.textContent = meta.model_version || 'N/A';

    const risk = Math.round(clampNumber(mlLayer.score, 0, 1, 0) * 100);
    const label = String(mlLayer.label || 'unknown');
    const conf = Math.round(clampNumber(mlLayer.confidence, 0, 1, 0) * 100);
    if (mlConfidence) mlConfidence.textContent = `${risk}% risk - ${label} (${conf}% confidence)`;

    updateMLStatusBlock(mlLayer.status || 'offline', meta);

    if (mlTopPreds) {
      mlTopPreds.innerHTML = '';
      (mlLayer.top_predictions || []).forEach((pred) => {
        const chip = document.createElement('span');
        chip.className = 'prediction-chip';
        const p = Math.round(clampNumber(pred.probability, 0, 1, 0) * 1000) / 10;
        chip.textContent = `${pred.label}: ${p.toFixed(1)}%`;
        mlTopPreds.appendChild(chip);
      });
    }
  }

  function renderRiskDial({ riskScore, riskLevel, action }) {
    if (!riskDial || !riskDialValue || !riskSummary) return;

    const level = String(riskLevel || '').toLowerCase();
    const color = level === 'low'
      ? 'var(--success)'
      : level === 'medium'
        ? 'var(--warning)'
        : level === 'high'
          ? 'var(--danger)'
          : 'var(--primary)';

    riskDial.style.setProperty('--risk-value', String(riskScore));
    riskDial.style.setProperty('--risk-color', color);
    riskDialValue.textContent = String(riskScore);
    riskSummary.textContent = `${riskLevel} risk - Action ${action}`;
  }

  function renderLayerHeatmap(layers = {}) {
    if (!layerHeatmap) return;
    layerHeatmap.innerHTML = '';
    Object.entries(layers).forEach(([key, payload]) => {
      if (key === 'ml') return;
      if (!payload) return;
      const chip = document.createElement('div');
      chip.className = 'layer-chip';
      const scorePct = Math.round(clampNumber(payload.score, 0, 1, 0) * 100);
      chip.textContent = `${formatLayerName(key)} - ${scorePct}%`;
      layerHeatmap.appendChild(chip);
    });
  }

  function renderDecisionTimeline(steps = []) {
    if (!Array.isArray(steps) || !steps.length) {
      return '<div class="muted">No timeline available.</div>';
    }

    return steps
      .map((step) => {
        const meta = [];
        if (step.status) meta.push(`status ${step.status}`);
        if (Number.isFinite(Number(step.score))) {
          meta.push(`score ${Math.round(Number(step.score) * 100)}%`);
        }
        if (step.intent) meta.push(`intent ${step.intent}`);
        if (step.severity) meta.push(`severity ${step.severity}`);
        if (step.action) meta.push(`action ${step.action}`);
        if (Array.isArray(step.signals) && step.signals.length) {
          meta.push(`signals ${step.signals.join(', ')}`);
        }
        return `
          <div class="timeline-item">
            <div class="timeline-step">${escapeHtml(String(step.step || ''))}</div>
            <div class="timeline-meta">${escapeHtml(meta.join(' | '))}</div>
          </div>
        `;
      })
      .join('');
  }

  function renderMLSpectrum(predictions = []) {
    if (!mlSpectrum) return;
    mlSpectrum.innerHTML = '';
    if (!predictions.length) return;

    predictions.forEach((pred) => {
      const row = document.createElement('div');
      row.className = 'spectrum-row';

      const label = document.createElement('div');
      label.className = 'spectrum-label';
      label.textContent = pred.label;

      const bar = document.createElement('div');
      bar.className = 'spectrum-bar';
      const fill = document.createElement('div');
      fill.className = 'spectrum-fill';
      const width = Math.max(0, Math.min(100, clampNumber(pred.probability, 0, 1, 0) * 100));
      fill.style.width = `${width.toFixed(1)}%`;
      bar.appendChild(fill);

      const value = document.createElement('div');
      value.className = 'spectrum-value';
      value.textContent = `${width.toFixed(1)}%`;

      row.appendChild(label);
      row.appendChild(bar);
      row.appendChild(value);
      mlSpectrum.appendChild(row);
    });
  }

  function renderMetadata(metadata = {}) {
    if (!metadataGrid) return;
    mlMetadataCache = metadata || {};
    metadataGrid.innerHTML = '';

    const entries = Object.entries(mlMetadataCache);
    if (!entries.length) {
      const item = document.createElement('div');
      item.className = 'metadata-item';
      const k = document.createElement('span');
      k.textContent = 'metadata';
      const v = document.createElement('div');
      v.className = 'meta-value';
      v.textContent = 'No metadata available';
      item.appendChild(k);
      item.appendChild(v);
      metadataGrid.appendChild(item);
      return;
    }

    const preferredOrder = [
      'model_version',
      'trained_on',
      'sample_count',
      'augmented_sample_count',
      'validation_accuracy',
      'validation_f1',
      'binary_validation_auc',
      'attack_threshold',
      'attack_model',
      'class_distribution',
      'augmented_class_distribution',
    ];

    entries.sort(([a], [b]) => {
      const ia = preferredOrder.indexOf(a);
      const ib = preferredOrder.indexOf(b);
      if (ia !== -1 || ib !== -1) {
        return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
      }
      return a.localeCompare(b);
    });

    entries.forEach(([key, value]) => {
      const item = document.createElement('div');
      item.className = 'metadata-item';
      const k = document.createElement('span');
      k.textContent = key.replace(/_/g, ' ');
      item.appendChild(k);

      // Pretty / structured rendering for the fields that were hard to read.
      if ((key === 'trained_on' || key.endsWith('_on')) && typeof value === 'string') {
        const d = new Date(value);
        const ok = !isNaN(d.getTime());
        const primary = document.createElement('div');
        primary.className = 'meta-value';
        primary.textContent = ok ? d.toLocaleString() : value;
        item.appendChild(primary);
        if (ok) {
          const raw = document.createElement('div');
          raw.className = 'meta-sub';
          raw.textContent = value;
          item.appendChild(raw);
        }
        metadataGrid.appendChild(item);
        return;
      }

      if (
        (key === 'class_distribution' || key === 'augmented_class_distribution')
        && value
        && typeof value === 'object'
        && !Array.isArray(value)
      ) {
        const chips = document.createElement('div');
        chips.className = 'meta-chips';
        const pairs = Object.entries(value)
          .map(([label, count]) => [String(label), Number(count)])
          .filter(([, count]) => Number.isFinite(count))
          .sort((a, b) => b[1] - a[1]);

        const shown = pairs.slice(0, 8);
        shown.forEach(([label, count]) => {
          const chip = document.createElement('span');
          chip.className = 'meta-chip';
          const prettyLabel = label.replace(/_/g, ' ').replace(/;/g, ' + ');
          chip.textContent = `${prettyLabel}: ${count.toLocaleString()}`;
          chips.appendChild(chip);
        });

        if (pairs.length > shown.length) {
          const more = document.createElement('span');
          more.className = 'meta-chip meta-chip--muted';
          more.textContent = `+${pairs.length - shown.length} more`;
          chips.appendChild(more);
        }

        item.appendChild(chips);
        metadataGrid.appendChild(item);
        return;
      }

      if (key === 'attack_model' && value && typeof value === 'object' && !Array.isArray(value)) {
        const chips = document.createElement('div');
        chips.className = 'meta-chips';
        const status = value.status ? String(value.status) : 'unknown';
        const acc = Number(value.validation_accuracy);
        const f1 = Number(value.validation_f1);
        const labelCount = Number(value.label_count);

        const statusChip = document.createElement('span');
        statusChip.className = 'meta-chip';
        statusChip.textContent = `status: ${status}`;
        chips.appendChild(statusChip);

        if (Number.isFinite(acc)) {
          const c = document.createElement('span');
          c.className = 'meta-chip';
          c.textContent = `acc: ${(acc * 100).toFixed(1)}%`;
          chips.appendChild(c);
        }

        if (Number.isFinite(f1)) {
          const c = document.createElement('span');
          c.className = 'meta-chip';
          c.textContent = `f1: ${(f1 * 100).toFixed(1)}%`;
          chips.appendChild(c);
        }

        if (Number.isFinite(labelCount) && labelCount > 0) {
          const c = document.createElement('span');
          c.className = 'meta-chip';
          c.textContent = `labels: ${labelCount.toLocaleString()}`;
          chips.appendChild(c);
        }

        item.appendChild(chips);
        metadataGrid.appendChild(item);
        return;
      }

      if (value && typeof value === 'object') {
        const pre = document.createElement('pre');
        pre.className = 'meta-json';
        try {
          pre.textContent = JSON.stringify(value, null, 2);
        } catch (_) {
          pre.textContent = String(value);
        }
        item.appendChild(pre);
        metadataGrid.appendChild(item);
        return;
      }

      const v = document.createElement('div');
      v.className = 'meta-value';

      if (typeof value === 'number' && Number.isFinite(value)) {
        if (key === 'attack_threshold') {
          v.textContent = value.toFixed(2);
        } else if (key.includes('accuracy') || key.endsWith('_f1') || key === 'validation_f1') {
          v.textContent = `${(value * 100).toFixed(1)}%`;
        } else if (key.endsWith('_count') || key === 'sample_count' || key === 'augmented_sample_count') {
          v.textContent = value.toLocaleString();
        } else if (key.includes('auc')) {
          v.textContent = value.toFixed(3);
        } else {
          v.textContent = String(value);
        }
      } else {
        v.textContent = String(value);
      }

      item.appendChild(v);
      metadataGrid.appendChild(item);
    });
  }

  function updateMLStatusBlock(status, metadata = {}) {
    if (!mlStatus) return;
    mlStatus.textContent = JSON.stringify(
      {
        status,
        trained_on: metadata.trained_on,
        validation_accuracy: metadata.validation_accuracy,
        validation_f1: metadata.validation_f1,
      },
      null,
      2
    );
  }

  async function bootstrapMLStatus() {
    if (!mlStatus) return;
    try {
      const res = await fetch('/ml/status');
      const data = await res.json();
      if (res.ok) {
        renderMetadata(data.metadata || {});
        updateMLStatusBlock(data.status, data.metadata || {});
      } else {
        mlStatus.textContent = data.error || 'ML subsystem unavailable';
      }
    } catch (err) {
      mlStatus.textContent = `Unable to load ML status: ${err.message}`;
    }
  }

  async function bootstrapStatus() {
    try {
      const res = await fetch('/status');
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to load status');

      const semanticEnabled = Boolean(data.semantic_enabled);
      if (apiPill) {
        apiPill.textContent = semanticEnabled ? 'API: online' : 'API: online (semantic off)';
        apiPill.classList.remove('pill--off', 'pill--warn');
        apiPill.classList.add(semanticEnabled ? 'pill--ok' : 'pill--warn');
      }

      if (mlPill) {
        const status = data.ml?.status || 'offline';
        const version = data.ml?.metadata?.model_version || 'N/A';
        mlPill.textContent = `ML: ${status} (v${version})`;
        mlPill.classList.remove('pill--ok', 'pill--warn', 'pill--off');
        mlPill.classList.add(status === 'online' ? 'pill--ok' : 'pill--off');
      }
    } catch (_) {
      if (apiPill) {
        apiPill.textContent = 'API: offline';
        apiPill.classList.remove('pill--ok', 'pill--warn');
        apiPill.classList.add('pill--off');
      }
      if (mlPill) {
        mlPill.textContent = 'ML: offline';
        mlPill.classList.remove('pill--ok', 'pill--warn');
        mlPill.classList.add('pill--off');
      }
    }
  }

  function applySavedTheme() {
    try {
      const saved = localStorage.getItem('pg_theme');
      if (saved === 'light' || saved === 'dark') {
        document.body.setAttribute('data-theme', saved);
      } else {
        document.body.setAttribute('data-theme', 'dark');
      }
    } catch (_) {
      document.body.setAttribute('data-theme', 'dark');
    }
  }

  function updatePromptCount() {
    if (!promptCount) return;
    const n = (promptInput?.value || '').length;
    promptCount.textContent = `${n} chars`;
  }

  function setAnalyzeLoading(isLoading) {
    if (!analyzeBtn) return;
    analyzeBtn.disabled = Boolean(isLoading);
    analyzeBtn.classList.toggle('btn--loading', Boolean(isLoading));
  }

  function clearAll() {
    if (promptInput) promptInput.value = '';
    updatePromptCount();
    resetResultsUI();
    try {
      promptInput?.focus();
    } catch (_) {}
  }

  function resetResultsUI() {
    lastAnalysis = null;
    if (analysisSubtitle) analysisSubtitle.textContent = 'Awaiting analysis...';
    if (frameworkAnalysisDetails) {
      frameworkAnalysisDetails.innerHTML = `
        <div class="empty-state">
          <div class="empty-title">No analysis yet</div>
          <div class="empty-text">Run analysis to generate a security decision and ML telemetry.</div>
        </div>
      `;
    }
    sanitizedPromptCard && (sanitizedPromptCard.style.display = 'none');
    feedbackBar && (feedbackBar.style.display = 'none');
    mlTelemetryCard && (mlTelemetryCard.style.display = 'none');
    intelSection && (intelSection.style.display = 'none');
    mlEval && (mlEval.style.display = 'none');
    if (groqSection) groqSection.style.display = 'none';
    if (groqDirectResponse) groqDirectResponse.textContent = 'Awaiting response...';
    if (groqFrameworkResponse) groqFrameworkResponse.textContent = 'Awaiting response...';
    if (groqInjectionTag) groqInjectionTag.textContent = 'Prompt injection: --';
    if (groqMlTag) groqMlTag.textContent = 'ML: --';
  }

  function resetFeedbackButtons() {
    if (feedbackBenignBtn) {
      feedbackBenignBtn.disabled = false;
      feedbackBenignBtn.textContent = 'Mark Safe';
    }
    if (feedbackMaliciousBtn) {
      feedbackMaliciousBtn.disabled = false;
      feedbackMaliciousBtn.textContent = 'Mark Malicious';
    }
  }

  async function submitFeedback(userLabel) {
    if (!lastAnalysis) return;

    if (feedbackBenignBtn) feedbackBenignBtn.disabled = true;
    if (feedbackMaliciousBtn) feedbackMaliciousBtn.disabled = true;

    const mlLabel = lastAnalysis.layers?.ml?.label || lastAnalysis.layers?.semantic?.ml?.label || '';
    const attackType = (mlLabel && mlLabel !== 'benign' && mlLabel !== 'unknown') ? mlLabel : '';

    try {
      const res = await fetch('/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: lastAnalysis.prompt,
          user_label: userLabel,
          attack_type: attackType,
          analysis: lastAnalysis,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to record feedback');
      if (userLabel === 'benign' && feedbackBenignBtn) feedbackBenignBtn.textContent = 'Saved';
      if (userLabel === 'malicious' && feedbackMaliciousBtn) feedbackMaliciousBtn.textContent = 'Saved';
      showToast('Feedback recorded. Thanks!', 'success');
    } catch (err) {
      resetFeedbackButtons();
      showToast(err.message, 'error');
    }
  }

  function addToHistory(analysis) {
    try {
      const entry = {
        ts: new Date().toISOString(),
        prompt: analysis.prompt || '',
        action: analysis.action || '',
        risk_score: analysis.risk_score ?? null,
      };
      const key = 'pg_history_v1';
      const existing = JSON.parse(localStorage.getItem(key) || '[]');
      const next = [entry, ...existing].slice(0, 12);
      localStorage.setItem(key, JSON.stringify(next));
    } catch (_) {
      // ignore storage failures
    }
  }

  function renderHistory() {
    if (!historyList) return;
    historyList.innerHTML = '';
    let items = [];
    try {
      items = JSON.parse(localStorage.getItem('pg_history_v1') || '[]');
    } catch (_) {
      items = [];
    }

    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'metadata-item';
      const k = document.createElement('span');
      k.textContent = 'history';
      const v = document.createElement('div');
      v.textContent = 'No runs yet';
      empty.appendChild(k);
      empty.appendChild(v);
      historyList.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      const div = document.createElement('div');
      div.className = 'history-item';
      const date = new Date(item.ts);
      const time = isNaN(date.getTime()) ? '' : date.toLocaleTimeString();
      div.innerHTML = `
        <div class="history-meta">
          <span>${escapeHtml(time)}</span>
          <span>${escapeHtml(String(item.action || ''))} ${escapeHtml(String(item.risk_score ?? ''))}/100</span>
        </div>
        <div class="history-prompt">${escapeHtml(String(item.prompt || ''))}</div>
      `;
      div.addEventListener('click', () => {
        promptInput.value = item.prompt || '';
        updatePromptCount();
        runAnalysis();
      });
      historyList.appendChild(div);
    });
  }

  function showToast(message, type = 'info') {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);
    setTimeout(() => toast.remove(), 3200);
  }

  function runAnalysis() {
    if (!form) return;
    if (typeof form.requestSubmit === 'function') {
      form.requestSubmit();
      return;
    }
    form.dispatchEvent(new Event('submit'));
  }

  async function safeCopyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.top = '-1000px';
    textArea.style.left = '-1000px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textArea);
    if (!ok) throw new Error('copy command failed');
  }

  function downloadJson(filename, obj) {
    const payload = JSON.stringify(obj, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function formatLayerName(name) {
    return String(name || '')
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  }

  function clampNumber(value, min, max, fallback) {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    if (n < min) return min;
    if (n > max) return max;
    return n;
  }

  function clampInt(value, min, max, fallback) {
    const n = clampNumber(value, min, max, fallback);
    return Math.round(n);
  }

  function renderEvalReport(report) {
    const binary = report?.binary || {};
    const cm = binary?.confusion_matrix || {};
    const fp = Array.isArray(report?.false_positives_top10) ? report.false_positives_top10 : [];
    const attack = report?.attack || null;

    const tags = [
      `acc ${binary.accuracy ?? 'n/a'}`,
      `precision ${binary.precision ?? 'n/a'}`,
      `recall ${binary.recall ?? 'n/a'}`,
      `f1 ${binary.f1 ?? 'n/a'}`,
      `auc ${binary.auc ?? 'n/a'}`,
    ].map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('');

    const cmTags = [
      `tn ${cm.tn ?? 'n/a'}`,
      `fp ${cm.fp ?? 'n/a'}`,
      `fn ${cm.fn ?? 'n/a'}`,
      `tp ${cm.tp ?? 'n/a'}`,
    ].map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('');

    const fpText = fp.length
      ? fp.slice(0, 5).map((row) => `- (${row.malicious_probability}) ${row.prompt}`).join('\n')
      : 'None';

    const attackText = attack
      ? JSON.stringify(attack, null, 2)
      : 'Attack model: disabled';

    const detailJson = JSON.stringify(report, null, 2);

    return `
      <div class="result-item">
        <span class="result-label">Binary Metrics</span>
        <div class="tags">${tags}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Confusion Matrix</span>
        <div class="tags">${cmTags}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Top False Positives</span>
        <div class="response-box">${escapeHtml(fpText)}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Attack Model</span>
        <div class="response-box">${escapeHtml(attackText)}</div>
      </div>
      <div class="result-item">
        <span class="result-label">Full Report</span>
        <div class="response-box">${escapeHtml(detailJson)}</div>
      </div>
    `;
  }
});
