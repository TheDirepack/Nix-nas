export function message(error) {
  if (error instanceof Error) return error.message;
  return String(error || "Unknown error");
}

export function pretty(value) {
  return JSON.stringify(value, null, 2);
}
