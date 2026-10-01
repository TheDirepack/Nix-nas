export const fetchJson = async (input, init) => {
  const response = await fetch(input, init);
  let value;
  try {
    value = await response.json();
  } catch (_error) {
    const reason = new Error(`Setup service returned an invalid response (${response.status}).`);
    reason.status = response.status;
    throw reason;
  }
  if (!response.ok || value?.error) {
    const reason = new Error(value?.error || `Setup request failed (${response.status}).`);
    reason.status = response.status;
    throw reason;
  }
  return value;
};
