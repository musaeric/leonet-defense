// POST /api/sentinel/report — Sentinel agents push threat data here
const store = require('./_store.js');

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const { agentId, agentName, platform, hostname, timestamp, system, threats, threatCount, criticalCount, highCount } = req.body;
  if (!agentId) return res.status(400).json({ error: 'agentId required' });

  store.agents[agentId] = {
    agentId, agentName, platform, hostname,
    system, threats: threats || [],
    threatCount:   threatCount   || 0,
    criticalCount: criticalCount || 0,
    highCount:     highCount     || 0,
    lastSeen: timestamp || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    online: true,
  };

  return res.status(200).json({ ok: true, received: (threats || []).length });
}
