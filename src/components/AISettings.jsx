import React, { useEffect, useState } from 'react';
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

  useEffect(() => {
    fetch(endpoint).then(async (response) => {
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Could not load AI settings');
      setConfig(payload);
      const liveProvider = payload.current.mode === 'live' ? payload.current.provider : payload.providers[0]?.id;
      setProvider(liveProvider || 'groq');
      setModel(payload.current.mode === 'live' ? payload.current.model : payload.providers.find((item) => item.id === liveProvider)?.default_model || '');
    }).catch((failure) => setError(failure.message || 'Could not load AI settings. Restart the local API.'));
  }, []);

  function changeProvider(next) {
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
      if (!response.ok) throw new Error(payload.message || payload.error || 'AI settings request failed');
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
  return <section className="ai-settings-page">
    <header><h1>AI settings</h1><p>Connect a model for evidence-based Case assessments.</p></header>
    <div className="ai-settings-card">
      <div className="ai-settings-status"><div><strong>Current connection</strong><p>{config ? config.current.mode === 'live' ? `${config.current.provider.toUpperCase()} · ${config.current.model}` : 'No live model connected' : 'Loading…'}</p></div><span className={config?.current.ready && config?.current.mode === 'live' ? 'ready' : ''}>{config?.current.ready && config?.current.mode === 'live' ? 'Configured' : 'Not configured'}</span></div>
      <label>AI provider<span className="ai-settings-select"><select value={provider} onChange={(event) => changeProvider(event.target.value)} disabled={!config || !!busy}>{config?.providers.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select><span className="ai-settings-chevron" aria-hidden="true" /></span></label>
      <label>Model ID<input value={model} onChange={(event) => setModel(event.target.value)} disabled={!config || !!busy || provider === 'mock'} autoComplete="off" /></label>
      <label>API key<input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} disabled={!config || !!busy} placeholder={selected?.key_configured ? 'Key saved · leave blank to keep it' : 'Paste your API key'} autoComplete="new-password" /><small>{selected?.key_configured ? 'A key is already configured. It is never shown again.' : 'The key is sent only to your local SOC Desk API and saved in the Git-ignored data folder.'}</small></label>
      <div className="ai-settings-actions"><button type="button" onClick={() => submit('test')} disabled={!config || !!busy}><Icon name="refresh" size={16} /><span>{busy === 'test' ? 'Testing…' : 'Test connection'}</span></button><button type="button" onClick={() => submit('save')} disabled={!config || !!busy}><Icon name="save" size={16} /><span>{busy === 'save' ? 'Saving…' : 'Save settings'}</span></button></div>
      {notice && <p className="ai-settings-message success" role="status">{notice}</p>}
      {error && <p className="ai-settings-message error" role="alert">{error}</p>}
    </div>
  </section>;
}
