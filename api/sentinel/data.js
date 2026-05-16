// GET /api/sentinel/data — LeoNet Defense dashboard reads all connected agents
// Sensitive fields (hostname, IPs, PIDs, process names) are nullified in the response
// so they cannot be read from the browser's network inspection panel.
const store = require('./_store.js');

function sanitizeThreats(threats = []) {
  return threats.map(t => ({
    id:       t.id,
    type:     t.type,
    severity: t.severity,
    name:     null,      // process name / IP — nullified in transit
    details:  null,      // PID / port details — nullified in transit
    source:   t.source,
    timestamp: t.timestamp,
    mitigated: t.mitigated,
    action:   t.action ? { action: t.action.action, label: null, pid: null, ip: null } : null,
  }));
}

function sanitizeAgent(a) {
  return {
    agentId:       null,   // agent identifier — nullified
    agentName:     null,   // device name — nullified
    platform:      a.platform,
    hostname:      null,   // device hostname — nullified
    online:        a.online,
    threatCount:   a.threatCount   || 0,
    criticalCount: a.criticalCount || 0,
    highCount:     a.highCount     || 0,
    lastSeen:      a.lastSeen,
    updatedAt:     a.updatedAt,
    system: a.system ? {
      platform:   a.system.platform,
      arch:       a.system.arch,
      cpuCount:   a.system.cpuCount,
      cpuModel:   null,    // hardware identity — nullified
      cpuPct:     a.system.cpuPct,
      memTotalGB: a.system.memTotalGB,
      memFreeGB:  a.system.memFreeGB,
      memPct:     a.system.memPct,
      uptime:     a.system.uptime,
      loadAvg:    a.system.loadAvg,
      hostname:   null,    // nullified
      interfaces: null,    // IP addresses — nullified
    } : null,
    threats:     sanitizeThreats(a.threats),
    mitigations: (a.mitigations || []).map(m => ({
      action:     m.action,
      success:    m.success,
      output:     null,    // may contain IPs/PIDs — nullified
      executedAt: m.executedAt,
    })),
  };
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const now = Date.now();
  Object.values(store.agents).forEach(a => {
    a.online = (now - new Date(a.updatedAt).getTime()) < 45000;
  });

  const sanitized = Object.values(store.agents).map(sanitizeAgent);

  return res.status(200).json({
    agents: sanitized,
    total:  sanitized.length,
    online: sanitized.filter(a => a.online).length,
  });
}
