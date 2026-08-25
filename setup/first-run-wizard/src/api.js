const request = async (path, options = {}) => {
  const response = await fetch(path, {
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  });
  const value = await response.json();
  if (!response.ok || (value && value.error)) {
    throw new Error((value && value.error) || `Setup API request failed with HTTP ${response.status}`);
  }
  return value;
};

export const firstStartStatus = () => request('api/first-start');

export const passwordQuality = (password, userInputs = []) =>
  request('api/password-quality', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password, userInputs }),
  });

export const submitFirstStart = (payload) =>
  request('api/first-run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

export const firstStartJob = (jobId) => request(`api/first-start/job/${encodeURIComponent(jobId)}`);

export const rebootAfterSetup = () => request('api/reboot', { method: 'POST' });
