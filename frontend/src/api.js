export async function request(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`/api${path}`, {
      ...options,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...options.headers },
    });
    const body = await response.json().catch(() => null);
    if (!response.ok)
      throw new Error(
        typeof body?.detail === "string"
          ? body.detail
          : `API request failed (${response.status}). Check backend logs and ScanOut schemas.`,
      );
    if (body === null)
      throw new Error(
        "The API returned an invalid response. Check the gateway connection.",
      );
    return body;
  } catch (e) {
    if (e.name === "AbortError")
      throw new Error(
        "API request timed out. Check that the backend is running.",
      );
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
export const api = {
  domains: () => request("/domains/"),
  register: (name) =>
    request("/domains/", { method: "POST", body: JSON.stringify({ name }) }),
  verify: (id) => request(`/verify/${id}`, { method: "POST" }),
  scans: (id) => request(`/scans/domain/${id}`),
  scan: (id) => request(`/scans/${id}`),
  start: (id) => request(`/scans/${id}`, { method: "POST" }),
};
