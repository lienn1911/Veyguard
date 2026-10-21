import React, { useState } from 'react';
import Icon from './Icon.jsx';

export default function Login({ onLogin, notice }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  async function submit(event) {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SOC-Desk-Auth': '1' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error === 'Unknown endpoint' ? 'An old SOC Desk API is running. Restart start.cmd.' : payload.error || 'Local API unavailable. Restart start.cmd.');
      setPassword('');
      onLogin(payload.username, payload.csrf_token);
    } catch (failure) {
      setError(failure.message || 'Could not reach the local API. Restart start.cmd.');
    } finally {
      setSubmitting(false);
    }
  }

  return <main className="login-page">
    <div className="login-shell">
      <section className="login-brand-side" aria-label="SOC Desk">
        <div className="login-brand-scene" aria-hidden="true">
          <svg className="login-draw-logo" viewBox="0 0 100 100" fill="none">
            <g className="login-logo-ring login-logo-outer" stroke="#fff" strokeWidth="7" strokeLinecap="round">
              <path pathLength="100" d="M12 37A40 40 0 0 1 57 10" />
              <path pathLength="100" d="M83 24A40 40 0 0 1 88 65" />
              <path pathLength="100" d="M67 86A40 40 0 0 1 11 64" />
            </g>
            <g className="login-logo-ring login-logo-inner" strokeWidth="7" strokeLinecap="round">
              <path pathLength="100" stroke="#fff" d="M43 30A23 23 0 0 0 39 71" />
              <path pathLength="100" stroke="#fff" d="M67 69A23 23 0 0 1 54 75" />
              <path pathLength="100" stroke="#C8B8EF" d="M52 27A23 23 0 0 1 75 50" />
            </g>
            <g className="login-logo-points" fill="#fff">
              <circle cx="71" cy="12" r="5" />
              <circle cx="11" cy="51" r="5" />
              <circle cx="78" cy="79" r="5" />
            </g>
            <circle className="login-logo-core" cx="52" cy="53" r="8" fill="#C8B8EF" />
          </svg>
        </div>
        <div className="login-brand-name" aria-hidden="true">
          <span className="login-brand-word login-brand-word-soc">{'SOC'.split('').map((letter, index) => <span className="login-brand-letter" style={{ '--letter-delay': `${1.15 + index * 0.075}s` }} key={index}>{letter}</span>)}</span>
          <span className="login-brand-word login-brand-word-desk">{'Desk'.split('').map((letter, index) => <span className="login-brand-letter" style={{ '--letter-delay': `${1.38 + index * 0.075}s` }} key={index}>{letter}</span>)}</span>
        </div>
      </section>
      <div className="login-form-side">
        <h1 className="login-heading">Sign in to your account</h1>
        {notice && <p className="login-notice" role="status">{notice}</p>}
        <form onSubmit={submit}>
          <label htmlFor="login-user">Username</label>
          <div className="login-input"><input id="login-user" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required placeholder="Enter your username" /></div>
          <label htmlFor="login-password">Password</label>
          <div className="login-input"><input id="login-password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required placeholder="Enter your password" /><button className="login-password-toggle" type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword}><Icon name={showPassword ? 'hide' : 'show'} size={20} /></button></div>
          {error && <p className="login-error" role="alert">{error}</p>}
          <button className={`login-submit${submitting ? ' is-submitting' : ''}`} type="submit" disabled={submitting} aria-busy={submitting}><span className="login-submit-icon"><Icon name="arrow" size={21} /></span><span className="login-submit-label">Sign in</span></button>
        </form>
      </div>
    </div>
  </main>;
}
