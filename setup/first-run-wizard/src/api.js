const JSON_HEADERS = Object.freeze({
  Accept: 'application/json',
  'Content-Type': 'application/json',
});

const request = async (path, options = {}) => {
  const response = await fetch(path, {
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    ...options,
    headers: {
      ...JSON_HEADERS,
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    let message = `Setup request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body?.error === 'string' && body.error) {
        message = body.error;
      }
    } catch (_error) {
      // Do not reflect response bodies from failed setup requests into the UI.
    }
    throw new Error(message);
  }

  return response.status === 204 ? null : response.json();
};

export const getSetupStatus = () => request('/setup/api/status', { method: 'GET' });

export const validatePassword = (password, context = []) =>
  request('/setup/api/password-quality', {
    method: 'POST',
    body: JSON.stringify({ password, context }),
  });

export const submitFirstRun = ({ planDigest, configuration, secrets, confirmations }) =>
  request('/setup/api/apply', {
    method: 'POST',
    body: JSON.stringify({
      schemaVersion: 1,
      planDigest,
      configuration,
      secrets,
      confirmations,
    }),
  });

// Deliberately no browser-side Authentik provisioning, generated Nix
// configuration, console logging of credential-bearing objects, or secret
// persistence. The authenticated first-run service owns mutations and passes
// secrets to nas-setup through private one-shot files/stdin.
