export const fetchJson = async (input, init) => {
  const response = await fetch(input, init);
  let value;
  try {
    value = await response.json();
  } catch (_error) {
    throw new Error(`Setup service returned an invalid response (${response.status}).`);
  }
  if (!response.ok || value?.error) {
    throw new Error(value?.error || `Setup request failed (${response.status}).`);
  }
  return value;
};
