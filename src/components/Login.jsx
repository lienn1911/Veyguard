import React, { useState } from 'react';
import Icon from './Icon.jsx';
import VeyGuardAnimatedLogo from './VeyGuardAnimatedLogo.jsx';

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
      if (!response.ok) throw new Error(payload.error === 'Unknown endpoint' ? 'An old VeyGuard API is running. Restart start.cmd.' : payload.error || 'Local API unavailable. Restart start.cmd.');
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
   <section className="login-brand-side" aria-label="VeyGuard">
  <div className="login-brand-scene">
    <VeyGuardAnimatedLogo />
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
