import React, { useEffect, useRef, useState } from 'react';
import { apiFetch } from '../apiFetch.js';
import Icon from './Icon.jsx';

const endpoint = '/api/ai/settings';

export default function AISettings() {
  const [config, setConfig] = useState(null);
  const [provider, setProvider] = useState('groq');
  const [model, setModel] = useState('openai/gpt-oss-20b');
  const [apiKey, setApiKey] = useState('');
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [providerOpen, setProviderOpen] = useState(false);
  const providerMenuRef = useRef(null);

  useEffect(() => {
    if (!providerOpen) return undefined;
    const closeOutside = (event) => {
      if (!providerMenuRef.current?.contains(event.target)) setProviderOpen(false);
    };
    document.addEventListener('pointerdown', closeOutside);
    return () => document.removeEventListener('pointerdown', closeOutside);
  }, [providerOpen]);

  useEffect(() => {
    fetch(endpoint)
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Could not load AI settings');
        setConfig(payload);
        const liveProvider =
          payload.current.mode === 'live' ? payload.current.provider : payload.providers[0]?.id;
        setProvider(liveProvider || 'groq');
        setModel(
          payload.current.mode === 'live'
            ? payload.current.model
            : payload.providers.find((item) => item.id === liveProvider)?.default_model || '',
        );
      })
      .catch((failure) =>
        setError(failure.message || 'Could not load AI settings. Restart the local API.'),
      );
  }, []);

  function changeProvider(next) {
    setProviderOpen(false);
    requestAnimationFrame(() =>
      providerMenuRef.current?.querySelector('.ai-provider-trigger')?.focus(),
    );
    setProvider(next);
    setModel(config.providers.find((item) => item.id === next)?.default_model || '');
    setApiKey('');
    setNotice('');
    setError('');
  }

  async function submit(action) {
    setBusy(action);
    setNotice('');
    setError('');
    try {
      const response = await apiFetch(action === 'test' ? `${endpoint}/test` : endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SOC-Desk-Settings': '1' },
        body: JSON.stringify({ provider, model, api_key: apiKey }),
      });
      const payload = await response.json();
      if (!response.ok)
        throw new Error(payload.message || payload.error || 'AI settings request failed');
      if (action === 'save') {
        setConfig(payload);
        setApiKey('');
        setNotice('Settings saved. You can now run AI check on a Case.');
      } else {
        setNotice(payload.message);
      }
    } catch (failure) {
      setError(failure.message || 'Could not reach the local API.');
    } finally {
      setBusy('');
    }
  }

  const selected = config?.providers.find((item) => item.id === provider);
  function handleProviderKeyDown(event) {
    if (event.key === 'Escape') {
      setProviderOpen(false);
      providerMenuRef.current?.querySelector('.ai-provider-trigger')?.focus();
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!providerOpen) {
        setProviderOpen(true);
        requestAnimationFrame(() =>
          providerMenuRef.current?.querySelector('[aria-selected="true"]')?.focus(),
        );
      } else {
        const options = [...providerMenuRef.current.querySelectorAll('.ai-provider-option')];
        const current = options.indexOf(document.activeElement);
        options[
          (current + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length
        ]?.focus();
      }
    }
  }
  return (
    <section className="ai-settings-page">
      <header>
        <h1>AI settings</h1>
      </header>
      <div className="ai-settings-card">
        <div className="ai-settings-status">
          <div>
            <strong>Current connection</strong>
            <p>
              {config
                ? config.current.mode === 'live'
                  ? `${config.current.provider.toUpperCase()} · ${config.current.model}`
                  : 'No live model connected'
                : 'Loading…'}
            </p>
          </div>
          <span className={config?.current.ready && config?.current.mode === 'live' ? 'ready' : ''}>
            {config?.current.ready && config?.current.mode === 'live'
              ? 'Configured'
              : 'Not configured'}
          </span>
        </div>
        <div className="ai-settings-form-grid">
          <div className="ai-provider-field">
            <span id="ai-provider-label">AI provider</span>
            <div
              className="ai-provider-picker"
              ref={providerMenuRef}
              onKeyDown={handleProviderKeyDown}
            >
              <button
                type="button"
                className="ai-provider-trigger"
                aria-labelledby="ai-provider-label ai-provider-value"
                aria-haspopup="listbox"
                aria-expanded={providerOpen}
                aria-controls="ai-provider-options"
                onClick={() => setProviderOpen((open) => !open)}
                disabled={!config || !!busy}
              >
                <span id="ai-provider-value">{selected?.label || 'Choose a provider'}</span>
                <span className="ai-provider-chevron" aria-hidden="true" />
              </button>
              {providerOpen && (
                <div
                  id="ai-provider-options"
                  className="ai-provider-menu"
                  role="listbox"
                  aria-labelledby="ai-provider-label"
                >
                  {config.providers.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className="ai-provider-option"
                      role="option"
                      aria-selected={item.id === provider}
                      onClick={() => changeProvider(item.id)}
                    >
                      <span>{item.label}</span>
                      {item.id === provider && (
                        <span className="ai-provider-check" aria-hidden="true">
                          ✓
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
          <label>
            Model
            <input
              value={model}
              onChange={(event) => setModel(event.target.value)}
              disabled={!config || !!busy || provider === 'mock'}
              autoComplete="off"
            />
          </label>
          {provider === 'codex' ? (
            <details className="ui-disclosure">
              <summary>Set up Codex CLI</summary>
              <p className="ai-settings-codex-help">
                On the computer running the SOC Desk API, install Codex CLI with{' '}
                <code>npm install -g @openai/codex</code>, then run <code>codex login</code>. Click{' '}
                <strong>Test connection</strong>, then <strong>Save settings</strong>. Testing and
                AI checks use your Codex allowance; completed case records remain saved locally.
              </p>
            </details>
          ) : (
            <label>
              API key
              <input
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                disabled={!config || !!busy}
                placeholder={
                  selected?.key_configured
                    ? 'Key saved · leave blank to keep it'
                    : 'Paste your API key'
                }
                autoComplete="new-password"
              />
              <small>
                {selected?.key_configured
                  ? 'A key is already configured. It is never shown again.'
                  : 'Stored locally on this computer.'}
              </small>
            </label>
          )}
        </div>
        <div className="ai-settings-actions">
          <button type="button" onClick={() => submit('test')} disabled={!config || !!busy}>
            <Icon name="connection" size={16} />
            <span>{busy === 'test' ? 'Testing…' : 'Test connection'}</span>
          </button>
          <button type="button" onClick={() => submit('save')} disabled={!config || !!busy}>
            <Icon name="saveSettings" size={16} />
            <span>{busy === 'save' ? 'Saving…' : 'Save settings'}</span>
          </button>
        </div>
        {notice && (
          <p className="ai-settings-message success" role="status">
            {notice}
          </p>
        )}
        {error && (
          <p className="ai-settings-message error" role="alert">
            {error}
          </p>
        )}
      </div>
    </section>
  );
}
