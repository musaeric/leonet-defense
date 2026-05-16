// In-memory store shared within a Vercel instance.
// For production with multiple instances: replace with Vercel KV or Upstash Redis.
if (!globalThis.__sentinelStore) {
  globalThis.__sentinelStore = {
    agents:   {},   // agentId → { ...report, updatedAt }
    commands: {},   // agentId → [{ action, ... }]
  };
}
module.exports = globalThis.__sentinelStore;
