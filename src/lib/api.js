/**
 * Thin client for the Python API.
 *
 * The browser only ever talks to our own backend (via the Vite proxy in dev).
 * LLM credentials stay server-side; nothing here knows about a provider key.
 */

const BASE = import.meta.env.VITE_API_BASE ?? '';
const DEFAULT_TIMEOUT = 90000;

export class ApiError extends Error {
  constructor(code, message, status, payload) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.payload = payload;
  }
}

async function request(path, { method = 'GET', body, timeout = DEFAULT_TIMEOUT } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(`${BASE}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const error = payload?.error || {
        code: 'HTTP_ERROR',
        message: `Request failed with status ${response.status}`,
      };
      throw new ApiError(error.code, error.message, response.status, payload);
    }
    return payload;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === 'AbortError') {
      throw new ApiError('CLIENT_TIMEOUT', 'The backend did not respond in time.', 0, null);
    }
    throw new ApiError('NETWORK_ERROR', 'Cannot reach the SOC-Triage API.', 0, null);
  } finally {
    clearTimeout(timer);
  }
}

export const getHealth = () => request('/api/health');
export const getDataset = () => request('/api/dataset');
export const getIncidents = () => request('/api/incidents');
export const getIncident = (id) => request(`/api/incidents/${encodeURIComponent(id)}`);
export const getAudit = (limit = 100) => request(`/api/audit?limit=${limit}`);

export async function runTriage(incidentId) {
  try {
    return await request(`/api/incidents/${encodeURIComponent(incidentId)}/triage`, { method: 'POST' });
  } catch (error) {
    // A failed investigation still returns a recorded run (status "error").
    // That is a result to display, not a transport failure to swallow.
    if (error.payload?.triage) return error.payload;
    throw error;
  }
}

export const submitDecision = (incidentId, decision) =>
  request(`/api/incidents/${encodeURIComponent(incidentId)}/decision`, {
    method: 'POST',
    body: decision,
  });

export const approveRecommendation = (incidentId, recommendationId) =>
  request(
    `/api/incidents/${encodeURIComponent(incidentId)}/recommendations/${encodeURIComponent(recommendationId)}/approve`,
    { method: 'POST' },
  );
