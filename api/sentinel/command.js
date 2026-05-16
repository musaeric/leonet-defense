// GET  /api/sentinel/command?agentId=x  — Sentinel polls for commands
// POST /api/sentinel/command             — Dashboard sends commands to agent
const store = require('./_store.js');

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    const { agentId } = req.query;
    if (!agentId) return res.status(400).json({ error: 'agentId required' });
    const commands = store.commands[agentId] || [];
    store.commands[agentId] = []; // clear after delivery (one-time dispatch)
    return res.status(200).json({ commands });
  }

  if (req.method === 'POST') {
    const { agentId, action, pid, ip, label } = req.body;
    if (!agentId || !action) return res.status(400).json({ error: 'agentId and action required' });
    if (!store.commands[agentId]) store.commands[agentId] = [];
    store.commands[agentId].push({ action, pid, ip, label, queuedAt: new Date().toISOString() });
    return res.status(200).json({ ok: true, queued: action });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
