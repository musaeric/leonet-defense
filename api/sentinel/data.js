// GET /api/sentinel/data — LeoNet Defense dashboard reads all connected agents
const store = require('./_store.js');

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // Mark agents offline if not seen in last 45 seconds
  const now = Date.now();
  Object.values(store.agents).forEach(a => {
    a.online = (now - new Date(a.updatedAt).getTime()) < 45000;
  });

  return res.status(200).json({
    agents: Object.values(store.agents),
    total:  Object.keys(store.agents).length,
    online: Object.values(store.agents).filter(a => a.online).length,
  });
}
