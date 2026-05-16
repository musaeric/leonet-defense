// POST /api/sentinel/mitigation — Sentinel reports back what it executed
const store = require('./_store.js');

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const { agentId, ...result } = req.body;
  if (!agentId) return res.status(400).json({ error: 'agentId required' });

  if (store.agents[agentId]) {
    if (!store.agents[agentId].mitigations) store.agents[agentId].mitigations = [];
    store.agents[agentId].mitigations = [result, ...store.agents[agentId].mitigations].slice(0, 30);
  }

  return res.status(200).json({ ok: true });
}
