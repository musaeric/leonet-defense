import React, { useState, useEffect, useRef, useCallback } from 'react';

// ── Design Tokens ────────────────────────────────────────────────────────────
const D = {
  bg:       '#050A14',
  surface:  '#0D1B2A',
  panel:    '#112233',
  panel2:   '#0A1828',
  border:   '#1E3A5F',
  border2:  '#0F2844',
  cyan:     '#00D4FF',
  blue:     '#1A7AFF',
  green:    '#00FF88',
  red:      '#FF2D55',
  orange:   '#FF6B35',
  purple:   '#BF5FFF',
  gold:     '#FFD700',
  muted:    '#4A7FA5',
  text:     '#C8E0F4',
  white:    '#FFFFFF',
  critical: '#FF2D55',
  high:     '#FF6B35',
  medium:   '#FFD700',
  low:      '#00D4FF',
  safe:     '#00FF88',
};

// ── Static Data ───────────────────────────────────────────────────────────────
const THREATS = [
  { id:'T001', name:'Phantom.Rootkit.X9',    type:'Rootkit',          severity:'critical', location:'C:\\Windows\\System32\\drivers\\', detected:'2026-05-16 08:12', status:'active',      confidence:99, cve:'CVE-2026-0041', squashed:false },
  { id:'T002', name:'ZeroDay.Exploit.AB3',   type:'Zero-Day',         severity:'critical', location:'Browser: Chromium sandbox',        detected:'2026-05-16 08:18', status:'active',      confidence:98, cve:'CVE-2026-0089', squashed:false },
  { id:'T003', name:'PolyMorph.Viper.7',     type:'Polymorphic Virus',severity:'high',     location:'C:\\Users\\AppData\\Roaming\\',    detected:'2026-05-16 07:55', status:'quarantined', confidence:97, cve:'CVE-2026-0102', squashed:false },
  { id:'T004', name:'Specter.Ransomware.R2', type:'Ransomware',       severity:'critical', location:'D:\\Documents\\',                  detected:'2026-05-16 07:40', status:'active',      confidence:99, cve:'CVE-2026-0055', squashed:false },
  { id:'T005', name:'Ghost.RAT.Stealth',     type:'Remote Access',    severity:'high',     location:'HKLM\\Software\\Microsoft\\Run',   detected:'2026-05-16 07:30', status:'active',      confidence:96, cve:'CVE-2026-0071', squashed:false },
  { id:'T006', name:'Mirage.Fileless.9C',    type:'Fileless Malware', severity:'high',     location:'PowerShell memory region 0x7F',    detected:'2026-05-16 07:22', status:'active',      confidence:95, cve:'CVE-2026-0083', squashed:false },
  { id:'T007', name:'BIOS.Implant.Gamma',    type:'Firmware Threat',  severity:'critical', location:'UEFI Firmware / SecureBoot',       detected:'2026-05-16 06:58', status:'analyzing',   confidence:93, cve:'CVE-2026-0099', squashed:false },
  { id:'T008', name:'Credential.Harvester',  type:'Credential Theft', severity:'high',     location:'LSASS Process (PID 788)',          detected:'2026-05-16 06:45', status:'quarantined', confidence:98, cve:'CVE-2026-0034', squashed:false },
  { id:'T009', name:'Supply.Poison.SDK',     type:'Supply Chain',     severity:'high',     location:'node_modules/crypto-utils v2.1',   detected:'2026-05-16 06:30', status:'active',      confidence:91, cve:'CVE-2026-0117', squashed:false },
  { id:'T010', name:'IoT.Botnet.Mirai2',     type:'IoT Exploit',      severity:'medium',   location:'192.168.1.44 (Smart Thermostat)',  detected:'2026-05-16 06:15', status:'blocked',     confidence:89, cve:'CVE-2026-0208', squashed:false },
  { id:'T011', name:'Adware.Phantom.Click',  type:'Adware',           severity:'low',      location:'C:\\Program Files\\MediaPlayer\\', detected:'2026-05-16 05:50', status:'quarantined', confidence:99, cve:'N/A',           squashed:false },
  { id:'T012', name:'NetBackdoor.Port443',    type:'Backdoor',         severity:'high',     location:'Network: 185.220.101.42:443',      detected:'2026-05-16 05:30', status:'blocked',     confidence:94, cve:'CVE-2026-0066', squashed:false },
];

const SCAN_MODULES = [
  { id:'kernel',     label:'Kernel & Boot Sector',        icon:'🔬', desc:'Rootkit & bootkit deep analysis' },
  { id:'memory',     label:'Memory Forensics',            icon:'🧠', desc:'Stealth malware in volatile RAM' },
  { id:'registry',   label:'Registry & Hidden Files',     icon:'📂', desc:'Anomalous entries & ghost files' },
  { id:'network',    label:'Network Packet Inspection',   icon:'🌐', desc:'Backdoor & C2 traffic analysis' },
  { id:'firmware',   label:'Firmware & BIOS',             icon:'⚡', desc:'UEFI/BIOS vulnerability excavation' },
  { id:'browser',    label:'Browser & Exploit Kits',      icon:'🔗', desc:'Malicious scripts & drive-by attacks' },
  { id:'cloud',      label:'Cloud Threat Intelligence',   icon:'☁️', desc:'Global blockchain-verified feed sync' },
  { id:'supply',     label:'Supply Chain Forensics',      icon:'🔗', desc:'Dependency poisoning detection' },
  { id:'iot',        label:'IoT Device Mapping',          icon:'📡', desc:'Connected device vulnerability scan' },
  { id:'fileless',   label:'Fileless Malware Hunt',       icon:'👻', desc:'AI pattern detection in-memory' },
  { id:'behavioral', label:'Behavioral Anomaly Engine',   icon:'🤖', desc:'Process & user deviation detection' },
  { id:'sandbox',    label:'Sandboxed Execution',         icon:'🏖️', desc:'Unknown threat detonation chamber' },
];

const INTEL_FEED = [
  { id:'IF001', hash:'a3f8e2c91b04d72f', family:'LockBit 4.0 Variant',   origin:'Eastern Europe', first:'2026-05-15', severity:'critical', verified:true,  reports:3892 },
  { id:'IF002', hash:'b7c4a1d83e09f561', family:'BlackCat Ransomware',   origin:'Unknown (TOR)',  first:'2026-05-14', severity:'critical', verified:true,  reports:2104 },
  { id:'IF003', hash:'c2e7b4f91a08d430', family:'APT-41 Implant',        origin:'Nation-State',   first:'2026-05-13', severity:'high',     verified:true,  reports:891  },
  { id:'IF004', hash:'d9a1c5e73b06f218', family:'RedLine Stealer v9',    origin:'Russia',         first:'2026-05-12', severity:'high',     verified:true,  reports:5623 },
  { id:'IF005', hash:'e4b8d2a61c09e345', family:'QBot Banking Trojan',   origin:'Eastern Europe', first:'2026-05-11', severity:'high',     verified:true,  reports:4217 },
  { id:'IF006', hash:'f1c6e9b27a03d890', family:'BIOS Implant XS-2',     origin:'Nation-State',   first:'2026-05-10', severity:'critical', verified:true,  reports:43   },
];

const NETWORK_EVENTS = [
  { time:'08:34:21', src:'185.220.101.42', dst:'192.168.1.100', proto:'TCP',  port:4444, action:'BLOCKED',   type:'C2 Beacon'        },
  { time:'08:33:55', src:'10.0.0.1',       dst:'8.8.8.8',       proto:'DNS',  port:53,   action:'ALLOWED',   type:'DNS Query'        },
  { time:'08:33:10', src:'91.108.4.200',   dst:'192.168.1.100', proto:'TCP',  port:443,  action:'INSPECTED', type:'Encrypted Tunnel' },
  { time:'08:32:44', src:'192.168.1.44',   dst:'45.33.32.156',  proto:'UDP',  port:6881, action:'BLOCKED',   type:'Botnet Callback'  },
  { time:'08:31:59', src:'192.168.1.100',  dst:'172.217.14.68', proto:'HTTPS',port:443,  action:'ALLOWED',   type:'Normal Traffic'   },
  { time:'08:31:22', src:'45.142.212.100', dst:'192.168.1.100', proto:'TCP',  port:22,   action:'BLOCKED',   type:'SSH Bruteforce'   },
];

const TRAINING_MODULES = [
  { id:'T1', title:'Phishing Recognition',      xp:500,  level:'Beginner',     complete:true,  badge:'🎖️' },
  { id:'T2', title:'Password Security',          xp:750,  level:'Beginner',     complete:true,  badge:'🔒' },
  { id:'T3', title:'Social Engineering Defense', xp:1000, level:'Intermediate', complete:false, badge:'🛡️' },
  { id:'T4', title:'Zero-Day Response Protocol', xp:2000, level:'Advanced',     complete:false, badge:'⚡' },
  { id:'T5', title:'Incident Response Drill',    xp:3000, level:'Expert',       complete:false, badge:'🏆' },
];

// ── Helpers ───────────────────────────────────────────────────────────────────
const sevColor = (s) => ({ critical:D.critical, high:D.high, medium:D.medium, low:D.low, safe:D.safe }[s] || D.muted);
const sevBg    = (s) => ({ critical:'rgba(255,45,85,0.15)', high:'rgba(255,107,53,0.15)', medium:'rgba(255,215,0,0.12)', low:'rgba(0,212,255,0.12)', safe:'rgba(0,255,136,0.12)' }[s] || 'transparent');
const statusColor = (s) => ({ active:D.red, quarantined:D.orange, blocked:D.cyan, analyzing:D.purple, squashed:D.green }[s] || D.muted);

function useCountUp(target, duration=1200) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0; const step = target / (duration / 16);
    const t = setInterval(() => { start = Math.min(start + step, target); setVal(Math.floor(start)); if (start >= target) clearInterval(t); }, 16);
    return () => clearInterval(t);
  }, [target, duration]);
  return val;
}

function usePulse(interval=1000) {
  const [tick, setTick] = useState(0);
  useEffect(() => { const t = setInterval(() => setTick(p => p+1), interval); return () => clearInterval(t); }, [interval]);
  return tick;
}

// ── Glow Border ──────────────────────────────────────────────────────────────
const GlowCard = ({ children, color=D.cyan, style={}, onClick }) => (
  <div onClick={onClick} style={{
    background: D.panel, border: `1px solid ${color}33`,
    borderRadius: 14, boxShadow: `0 0 0 1px ${color}22, inset 0 0 30px ${color}08`,
    position: 'relative', overflow: 'hidden', ...style,
  }}>
    <div style={{ position:'absolute', top:0, left:0, right:0, height:1, background:`linear-gradient(90deg,transparent,${color}88,transparent)` }} />
    {children}
  </div>
);

// ── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, unit='', icon, color=D.cyan, sub }) {
  return (
    <GlowCard color={color} style={{ padding:'18px 20px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
        <div>
          <div style={{ fontSize:11, fontWeight:700, color:D.muted, textTransform:'uppercase', letterSpacing:1.5, marginBottom:8 }}>{label}</div>
          <div style={{ fontSize:30, fontWeight:900, color, lineHeight:1, fontFamily:'monospace' }}>{value}<span style={{ fontSize:14, fontWeight:600, marginLeft:4, opacity:0.7 }}>{unit}</span></div>
          {sub && <div style={{ fontSize:11, color:D.muted, marginTop:6 }}>{sub}</div>}
        </div>
        <div style={{ fontSize:28, opacity:0.7 }}>{icon}</div>
      </div>
      <div style={{ position:'absolute', bottom:0, left:0, right:0, height:2, background:`linear-gradient(90deg,transparent,${color},transparent)` }} />
    </GlowCard>
  );
}

// ── Radar Ring ───────────────────────────────────────────────────────────────
function RadarRing({ threats, tick }) {
  const active = threats.filter(t => !t.squashed && t.status === 'active').length;
  return (
    <div style={{ position:'relative', width:180, height:180, margin:'0 auto' }}>
      {[80,60,40,20].map((r,i) => (
        <div key={r} style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', width:r*2, height:r*2, border:`1px solid ${D.cyan}${['22','33','44','55'][i]}`, borderRadius:'50%' }} />
      ))}
      <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%) rotate(0deg)', width:160, height:160, borderRadius:'50%', overflow:'hidden', animation:'radar-sweep 3s linear infinite' }}>
        <div style={{ position:'absolute', top:'50%', left:'50%', width:'50%', height:1, background:`linear-gradient(90deg,transparent,${D.cyan})`, transformOrigin:'left center' }} />
      </div>
      <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', textAlign:'center' }}>
        <div style={{ fontSize:32, fontWeight:900, color: active > 0 ? D.red : D.green, fontFamily:'monospace', animation: active > 0 ? 'blink 1s ease-in-out infinite' : 'none' }}>{active}</div>
        <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1 }}>Active</div>
      </div>
      {threats.filter(t => !t.squashed).slice(0,6).map((t,i) => {
        const angle = (i * 60 + tick * 3) * Math.PI / 180;
        const r = 55 + (i % 3) * 15;
        const x = 90 + r * Math.cos(angle);
        const y = 90 + r * Math.sin(angle);
        return (
          <div key={t.id} style={{ position:'absolute', left:x, top:y, width:6, height:6, borderRadius:'50%', background:sevColor(t.severity), boxShadow:`0 0 8px ${sevColor(t.severity)}`, transform:'translate(-50%,-50%)', animation:'pulse-glow 1.5s ease-in-out infinite' }} />
        );
      })}
    </div>
  );
}

// ── Scan Progress ────────────────────────────────────────────────────────────
function ScanProgress({ running, progress, module: mod }) {
  return (
    <div style={{ marginBottom:16 }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
        <span style={{ fontSize:12, color:D.text }}>{mod || 'Idle'}</span>
        <span style={{ fontSize:12, color:D.cyan, fontFamily:'monospace' }}>{running ? `${Math.round(progress)}%` : '—'}</span>
      </div>
      <div style={{ height:4, background:D.border, borderRadius:2, overflow:'hidden', position:'relative' }}>
        <div style={{ position:'absolute', top:0, left:0, height:'100%', width:`${progress}%`, background:`linear-gradient(90deg,${D.blue},${D.cyan})`, borderRadius:2, transition:'width 0.3s', boxShadow:`0 0 8px ${D.cyan}` }} />
        {running && <div style={{ position:'absolute', top:0, left:0, height:'100%', width:'30%', background:`linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent)`, animation:'scan-line 1s linear infinite', transform:'translateX(-100%)' }} />}
      </div>
    </div>
  );
}

// ── 3D Threat Table ───────────────────────────────────────────────────────────
function ThreatTable3D({ threats, onSquash }) {
  const [hovered, setHovered] = useState(null);
  const [tiltX, setTiltX] = useState(6);
  const [tiltY, setTiltY] = useState(-3);
  const ref = useRef();

  const handleMouseMove = useCallback((e) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const rx = ((e.clientY - cy) / rect.height) * 10;
    const ry = ((cx - e.clientX) / rect.width) * 10;
    setTiltX(rx + 6); setTiltY(ry - 3);
  }, []);

  const handleMouseLeave = useCallback(() => { setTiltX(6); setTiltY(-3); }, []);

  const live = threats.filter(t => !t.squashed);

  return (
    <div ref={ref} onMouseMove={handleMouseMove} onMouseLeave={handleMouseLeave}
      style={{ perspective:1200, perspectiveOrigin:'50% 40%', userSelect:'none' }}>
      <div style={{ transform:`rotateX(${tiltX}deg) rotateY(${tiltY}deg)`, transformStyle:'preserve-3d', transition:'transform 0.1s ease', borderRadius:16, overflow:'hidden', boxShadow:`0 40px 80px rgba(0,0,0,0.6), 0 0 0 1px ${D.cyan}22` }}>
        {/* Table header */}
        <div style={{ background:`linear-gradient(135deg,#0A2040,#061428)`, padding:'14px 20px', display:'grid', gridTemplateColumns:'50px 1fr 120px 90px 100px 80px 110px', gap:10, borderBottom:`1px solid ${D.border}` }}>
          {['ID','Threat Name / Family','Type','Severity','Location','Conf.','Action'].map(h => (
            <div key={h} style={{ fontSize:10, fontWeight:800, color:D.cyan, textTransform:'uppercase', letterSpacing:1.5 }}>{h}</div>
          ))}
        </div>
        {/* Rows */}
        {live.map((t, i) => (
          <div key={t.id} onMouseEnter={()=>setHovered(t.id)} onMouseLeave={()=>setHovered(null)}
            style={{ background: hovered===t.id ? `${sevBg(t.severity)}` : i%2===0 ? '#0A1828' : '#081420',
              padding:'12px 20px', display:'grid', gridTemplateColumns:'50px 1fr 120px 90px 100px 80px 110px', gap:10, alignItems:'center',
              borderBottom:`1px solid ${D.border2}`, transition:'background 0.15s',
              boxShadow: hovered===t.id ? `inset 3px 0 0 ${sevColor(t.severity)}, 0 0 20px ${sevColor(t.severity)}22` : `inset 3px 0 0 ${sevColor(t.severity)}44`,
              transform: hovered===t.id ? 'translateZ(8px)' : 'translateZ(0)', transformStyle:'preserve-3d' }}>
            <div style={{ fontFamily:'monospace', fontSize:11, color:D.muted }}>{t.id}</div>
            <div>
              <div style={{ fontWeight:700, color:D.text, fontSize:13 }}>{t.name}</div>
              <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{t.cve}</div>
            </div>
            <div style={{ fontSize:11, color:D.text }}>{t.type}</div>
            <div>
              <span style={{ background:sevBg(t.severity), color:sevColor(t.severity), border:`1px solid ${sevColor(t.severity)}44`, borderRadius:20, padding:'2px 10px', fontSize:10, fontWeight:800, textTransform:'uppercase', letterSpacing:0.5 }}>{t.severity}</span>
            </div>
            <div style={{ fontSize:10, color:D.muted, wordBreak:'break-all', lineHeight:1.4 }}>{t.location.slice(0,28)}{t.location.length>28?'…':''}</div>
            <div style={{ fontFamily:'monospace', fontSize:12, color: t.confidence>95?D.green:t.confidence>85?D.cyan:D.orange, fontWeight:800 }}>{t.confidence}%</div>
            <div>
              <button onClick={()=>onSquash(t.id)} style={{ background:`linear-gradient(135deg,${D.red},#CC0033)`, color:'#fff', border:'none', borderRadius:6, padding:'6px 12px', fontSize:11, fontWeight:800, cursor:'pointer', letterSpacing:0.5, boxShadow:`0 0 10px ${D.red}55`, transition:'all 0.15s', whiteSpace:'nowrap' }}
                onMouseEnter={e=>{e.currentTarget.style.boxShadow=`0 0 20px ${D.red}`;}}
                onMouseLeave={e=>{e.currentTarget.style.boxShadow=`0 0 10px ${D.red}55`;}}>
                ⚡ Squash
              </button>
            </div>
          </div>
        ))}
        {live.length === 0 && (
          <div style={{ padding:40, textAlign:'center', background:'#081420' }}>
            <div style={{ fontSize:40, marginBottom:12 }}>✅</div>
            <div style={{ color:D.green, fontWeight:800, fontSize:16 }}>All Threats Neutralized</div>
            <div style={{ color:D.muted, fontSize:12, marginTop:6 }}>System is clean — LeoNet Defense is standing guard</div>
          </div>
        )}
        {/* 3D floor shadow */}
        <div style={{ height:6, background:`linear-gradient(180deg,${D.border2},transparent)` }} />
      </div>
    </div>
  );
}

// ── Remediation Panel ─────────────────────────────────────────────────────────
function RemediationSteps({ threat }) {
  if (!threat) return null;
  const steps = {
    'Rootkit':          ['Isolate system from network','Boot into secure recovery environment','Run offline kernel integrity scan','Restore clean kernel image from verified backup','Force UEFI SecureBoot re-enrollment','Revalidate all drivers with signature check'],
    'Zero-Day':         ['Kill associated browser process','Disable JavaScript engine sandbox bypass','Push emergency micro-patch to exploit vector','Submit sample to zero-day consortium','Monitor for IOC replication across endpoints'],
    'Ransomware':       ['Immediately kill encryption process','Block all SMB/NFS shares','Restore files from blockchain-verified shadow copies','Rotate all credentials exposed during window','Notify compliance officer — GDPR/HIPAA obligation'],
    'Fileless Malware': ['Dump suspicious memory region','Extract injected shellcode payload','Terminate parent process chain','Flush PowerShell/WMI event subscriptions','Rebuild affected process list in kernel'],
    'Firmware Threat':  ['Flash BIOS/UEFI from verified vendor image','Re-enroll Platform Keys in UEFI','Enable Secure Boot measurement validation','Run TPM attestation report','Cross-check firmware hash against blockchain registry'],
  };
  const list = steps[threat.type] || ['Quarantine threat', 'Analyse payload', 'Remove malicious artifacts', 'Verify system integrity', 'Update signatures'];
  return (
    <div style={{ marginTop:16 }}>
      <div style={{ fontSize:12, fontWeight:700, color:D.cyan, marginBottom:12, textTransform:'uppercase', letterSpacing:1 }}>Remediation Plan — {threat.name}</div>
      {list.map((s,i) => (
        <div key={i} style={{ display:'flex', gap:10, alignItems:'flex-start', marginBottom:10, padding:'10px 14px', background:`#0A1828`, borderRadius:8, border:`1px solid ${D.border2}`, transform:`translateZ(${(i+1)*3}px)`, transformStyle:'preserve-3d' }}>
          <div style={{ width:22, height:22, borderRadius:'50%', background:`linear-gradient(135deg,${D.blue},${D.cyan})`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:11, fontWeight:800, flexShrink:0 }}>{i+1}</div>
          <div style={{ fontSize:12, color:D.text, lineHeight:1.5 }}>{s}</div>
        </div>
      ))}
    </div>
  );
}

// ── Network Map ───────────────────────────────────────────────────────────────
function NetworkMap({ tick }) {
  const nodes = [
    { x:50,  y:50,  label:'Gateway',   color:D.green,  size:14 },
    { x:200, y:80,  label:'WAN',       color:D.blue,   size:10 },
    { x:350, y:50,  label:'Threat C2', color:D.red,    size:10 },
    { x:50,  y:180, label:'Host A',    color:D.cyan,   size:10 },
    { x:200, y:180, label:'Host B',    color:D.cyan,   size:10 },
    { x:350, y:180, label:'IoT Hub',   color:D.orange, size:10 },
    { x:125, y:270, label:'VPN Exit',  color:D.purple, size:10 },
    { x:275, y:270, label:'DMZ',       color:D.gold,   size:10 },
  ];
  const edges = [[0,1],[1,2],[0,3],[0,4],[1,4],[1,5],[3,6],[4,7]];
  const blocked = [[1,2],[4,5]];
  return (
    <svg width="100%" viewBox="0 0 400 310" style={{ maxWidth:440, display:'block', margin:'0 auto' }}>
      <defs>
        <filter id="glow"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      {edges.map(([a,b],i) => {
        const isBlocked = blocked.some(([x,y]) => (x===a&&y===b)||(x===b&&y===a));
        return (
          <line key={i} x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y}
            stroke={isBlocked ? D.red : D.border} strokeWidth={isBlocked?2:1}
            strokeDasharray={isBlocked?'4,3':'none'} opacity={0.7} />
        );
      })}
      {nodes.map((n,i) => (
        <g key={i} filter="url(#glow)">
          <circle cx={n.x} cy={n.y} r={n.size+4} fill={`${n.color}11`} />
          <circle cx={n.x} cy={n.y} r={n.size} fill={D.panel} stroke={n.color} strokeWidth={1.5} />
          <text x={n.x} y={n.y+n.size+14} textAnchor="middle" fill={D.muted} fontSize={9}>{n.label}</text>
        </g>
      ))}
      <text x={200} y={305} textAnchor="middle" fill={D.red} fontSize={9} opacity={0.7}>— Blocked C2 Connection — IoT Isolation Active</text>
    </svg>
  );
}

// ── Firewall Rules ────────────────────────────────────────────────────────────
function FirewallRules() {
  const rules = [
    { id:'FW-001', dir:'IN',  proto:'TCP',  src:'185.220.101.0/24', dst:'ANY',         port:'4444',   action:'DROP',   reason:'Known TOR exit node / C2 range' },
    { id:'FW-002', dir:'IN',  proto:'TCP',  src:'91.108.4.0/24',    dst:'ANY',         port:'22',     action:'DROP',   reason:'SSH bruteforce origin' },
    { id:'FW-003', dir:'OUT', proto:'UDP',  src:'192.168.1.44',     dst:'ANY',         port:'6881',   action:'DROP',   reason:'IoT botnet callback' },
    { id:'FW-004', dir:'IN',  proto:'ICMP', src:'ANY',              dst:'192.168.1.100',port:'—',     action:'LIMIT',  reason:'ICMP flood mitigation' },
    { id:'FW-005', dir:'ANY', proto:'TCP',  src:'ANY',              dst:'ANY',         port:'443',    action:'INSPECT',reason:'TLS deep-packet inspection' },
    { id:'FW-006', dir:'OUT', proto:'DNS',  src:'192.168.1.0/24',   dst:'8.8.8.8',    port:'53',     action:'ALLOW',  reason:'Trusted resolver only' },
  ];
  const actionColor = { DROP:D.red, LIMIT:D.orange, INSPECT:D.cyan, ALLOW:D.green };
  return (
    <div style={{ overflowX:'auto' }}>
      <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
        <thead><tr style={{ background:'#061428' }}>{['Rule','Dir','Proto','Source','Destination','Port','Action','Reason'].map(h=>(
          <th key={h} style={{ padding:'9px 12px', textAlign:'left', color:D.muted, fontWeight:700, fontSize:10, textTransform:'uppercase', letterSpacing:1, borderBottom:`1px solid ${D.border}` }}>{h}</th>
        ))}</tr></thead>
        <tbody>{rules.map((r,i)=>(
          <tr key={r.id} style={{ background: i%2===0?'#081420':'#0A1828', borderBottom:`1px solid ${D.border2}` }}>
            <td style={{ padding:'9px 12px', fontFamily:'monospace', color:D.muted, fontSize:10 }}>{r.id}</td>
            <td style={{ padding:'9px 12px', color:r.dir==='IN'?D.cyan:D.orange, fontWeight:700 }}>{r.dir}</td>
            <td style={{ padding:'9px 12px', color:D.text }}>{r.proto}</td>
            <td style={{ padding:'9px 12px', color:D.text, fontFamily:'monospace', fontSize:10 }}>{r.src}</td>
            <td style={{ padding:'9px 12px', color:D.text, fontFamily:'monospace', fontSize:10 }}>{r.dst}</td>
            <td style={{ padding:'9px 12px', color:D.gold, fontFamily:'monospace' }}>{r.port}</td>
            <td style={{ padding:'9px 12px' }}><span style={{ color:actionColor[r.action]||D.muted, fontWeight:800, fontSize:10 }}>{r.action}</span></td>
            <td style={{ padding:'9px 12px', color:D.muted, fontSize:10 }}>{r.reason}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

// ── Memory Heat Map ───────────────────────────────────────────────────────────
function MemoryHeatMap({ tick }) {
  const cells = Array.from({length:128}, (_,i) => {
    const v = Math.sin(i*0.4 + tick*0.2) * 0.5 + 0.5 + Math.random()*0.3;
    const hot = [12,13,28,29,30,64,65,96,97,98];
    if (hot.includes(i)) return { val:1, threat:true };
    return { val: Math.min(1, Math.abs(v)), threat:false };
  });
  const cellColor = (c) => {
    if (c.threat) return D.red;
    if (c.val > 0.85) return D.orange;
    if (c.val > 0.65) return D.gold;
    if (c.val > 0.4) return D.cyan;
    return `${D.blue}55`;
  };
  return (
    <div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(16,1fr)', gap:2 }}>
        {cells.map((c,i) => (
          <div key={i} title={`0x${(i*0x1000).toString(16).toUpperCase().padStart(4,'0')}`} style={{ height:14, borderRadius:2, background:cellColor(c), opacity: c.threat ? 1 : 0.4 + c.val*0.6, boxShadow: c.threat ? `0 0 6px ${D.red}` : 'none', cursor:'pointer', transition:'opacity 0.3s' }} />
        ))}
      </div>
      <div style={{ display:'flex', gap:16, marginTop:10, flexWrap:'wrap' }}>
        {[['Threat Detected',D.red],['High Activity',D.orange],['Moderate',D.gold],['Low',D.cyan],['Idle',D.blue]].map(([l,c])=>(
          <div key={l} style={{ display:'flex', gap:6, alignItems:'center' }}><div style={{ width:10, height:10, borderRadius:2, background:c }}/><span style={{ fontSize:10, color:D.muted }}>{l}</span></div>
        ))}
      </div>
    </div>
  );
}

// ── AI Score Gauge ────────────────────────────────────────────────────────────
function AIGauge({ value, label, color }) {
  const angle = (value / 100) * 180 - 90;
  const r = 42, cx = 55, cy = 55;
  const arcPath = (startAngle, endAngle, radius) => {
    const s = startAngle * Math.PI / 180;
    const e = endAngle * Math.PI / 180;
    return `M ${cx + radius * Math.cos(s)} ${cy + radius * Math.sin(s)} A ${radius} ${radius} 0 ${Math.abs(endAngle - startAngle) > 180 ? 1 : 0} 1 ${cx + radius * Math.cos(e)} ${cy + radius * Math.sin(e)}`;
  };
  return (
    <div style={{ textAlign:'center' }}>
      <svg width={110} height={70} viewBox="0 0 110 70">
        <path d={arcPath(-180, 0, r)} fill="none" stroke={D.border} strokeWidth={8} strokeLinecap="round" />
        <path d={arcPath(-180, angle, r)} fill="none" stroke={color} strokeWidth={8} strokeLinecap="round" />
        <text x={cx} y={cy+10} textAnchor="middle" fill={color} fontSize={18} fontWeight={900} fontFamily="monospace">{value}</text>
      </svg>
      <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginTop:-8 }}>{label}</div>
    </div>
  );
}

// ── Timeline Bar ──────────────────────────────────────────────────────────────
function TimelineBar({ label, val, max, color }) {
  return (
    <div style={{ marginBottom:12 }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
        <span style={{ fontSize:12, color:D.text }}>{label}</span>
        <span style={{ fontSize:12, color, fontFamily:'monospace', fontWeight:700 }}>{val.toLocaleString()}</span>
      </div>
      <div style={{ height:6, background:D.border, borderRadius:3, overflow:'hidden' }}>
        <div style={{ height:'100%', width:`${(val/max)*100}%`, background:`linear-gradient(90deg,${color}88,${color})`, borderRadius:3, boxShadow:`0 0 8px ${color}55`, transition:'width 1s' }} />
      </div>
    </div>
  );
}

// ── Compliance Badge ──────────────────────────────────────────────────────────
function ComplianceBadge({ name, status, icon }) {
  const ok = status === 'compliant';
  return (
    <div style={{ background: ok ? 'rgba(0,255,136,0.06)' : 'rgba(255,107,53,0.08)', border:`1px solid ${ok?D.green:D.orange}44`, borderRadius:12, padding:'16px 20px', textAlign:'center' }}>
      <div style={{ fontSize:28, marginBottom:8 }}>{icon}</div>
      <div style={{ fontWeight:800, fontSize:12, color:D.text, marginBottom:4 }}>{name}</div>
      <div style={{ background: ok?'rgba(0,255,136,0.15)':'rgba(255,107,53,0.15)', color: ok?D.green:D.orange, borderRadius:20, padding:'2px 12px', fontSize:10, fontWeight:800, display:'inline-block', textTransform:'uppercase', letterSpacing:1 }}>{status}</div>
    </div>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────
const NAV = [
  { id:'dashboard',      label:'Dashboard',        icon:'⚡' },
  { id:'threat-matrix',  label:'Threat Matrix',    icon:'🎯' },
  { id:'scan',           label:'Deep Scan',        icon:'🔬' },
  { id:'network',        label:'Network Shield',   icon:'🌐' },
  { id:'memory',         label:'Memory Lab',       icon:'🧠' },
  { id:'forensics',      label:'Forensics',        icon:'🔎' },
  { id:'risk',           label:'Risk & Analysis',  icon:'📊' },
  { id:'recommendations',label:'Recommendations',  icon:'💡' },
  { id:'darkweb',        label:'Dark Web',         icon:'🌑' },
  { id:'reports',        label:'Reports',          icon:'📋' },
  { id:'intel',          label:'Intel Feed',       icon:'📡' },
  { id:'compliance',     label:'Compliance',       icon:'🛡️' },
  { id:'training',       label:'Training',         icon:'🎮' },
  { id:'settings',       label:'Settings',         icon:'⚙️' },
];

export default function App() {
  const [view, setView]               = useState('dashboard');
  const [threats, setThreats]         = useState(THREATS.map(t=>({...t})));
  const [scanning, setScanning]       = useState(false);
  const [scanPct, setScanPct]         = useState(0);
  const [scanMod, setScanMod]         = useState('');
  const [scanDone, setScanDone]       = useState(false);
  const [selectedThreat, setSelected] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toast, setToast]             = useState(null);
  const [trainingXP, setTrainingXP]   = useState(1250);
  const [voiceActive, setVoiceActive] = useState(false);
  const [dbUpdating, setDbUpdating]   = useState(false);
  const tick = usePulse(800);

  const totalThreats   = threats.filter(t => !t.squashed).length;
  const criticalCount  = threats.filter(t => !t.squashed && t.severity === 'critical').length;
  const squashedCount  = threats.filter(t => t.squashed).length;
  const threatCount    = useCountUp(totalThreats, 600);

  const showToast = (msg, color=D.green) => {
    setToast({ msg, color });
    setTimeout(() => setToast(null), 3000);
  };

  const squash = (id) => {
    setThreats(prev => prev.map(t => t.id===id ? {...t, squashed:true, status:'squashed'} : t));
    const t = threats.find(x => x.id===id);
    showToast(`✅ ${t?.name || 'Threat'} neutralized and quarantined.`, D.green);
  };

  const squashAll = () => {
    setThreats(prev => prev.map(t => ({...t, squashed:true, status:'squashed'})));
    showToast(`✅ All ${totalThreats} threats neutralized.`, D.green);
  };

  const startScan = () => {
    if (scanning) return;
    setScanning(true); setScanPct(0); setScanDone(false);
    let pct = 0; let modIdx = 0;
    setScanMod(SCAN_MODULES[0].label);
    const t = setInterval(() => {
      pct += 0.6 + Math.random() * 0.8;
      if (pct >= 100) { pct = 100; clearInterval(t); setScanning(false); setScanDone(true); showToast('🔬 Deep scan complete — 2 new threats detected.', D.cyan); }
      if (pct > (modIdx+1) * (100/SCAN_MODULES.length) && modIdx < SCAN_MODULES.length-1) { modIdx++; setScanMod(SCAN_MODULES[modIdx].label); }
      setScanPct(Math.min(pct, 100));
    }, 80);
  };

  const triggerDbUpdate = () => {
    setDbUpdating(true);
    setTimeout(() => { setDbUpdating(false); showToast('☁️ Threat database synced — 1,284,921 signatures updated.', D.cyan); }, 2200);
  };

  const isMobile = typeof window !== 'undefined' && window.innerWidth < 768;

  // ── Shared top bar ──────────────────────────────────────────────────────────
  const TopBar = () => (
    <div style={{ background:D.surface, borderBottom:`1px solid ${D.border}`, padding:'0 20px', height:56, display:'flex', alignItems:'center', justifyContent:'space-between', position:'sticky', top:0, zIndex:100, flexShrink:0 }}>
      <div style={{ display:'flex', alignItems:'center', gap:14 }}>
        <button onClick={()=>setSidebarOpen(p=>!p)} style={{ background:'none', border:'none', color:D.cyan, cursor:'pointer', fontSize:18, display:'flex', alignItems:'center', padding:4 }}>☰</button>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ width:32, height:32, borderRadius:8, background:`linear-gradient(135deg,${D.blue},${D.cyan})`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:16, boxShadow:`0 0 14px ${D.cyan}55` }}>🦁</div>
          <div>
            <div style={{ fontWeight:900, fontSize:14, color:D.white, letterSpacing:0.5 }}>LeoNet Defense</div>
            <div style={{ fontSize:10, color:D.cyan, letterSpacing:1 }}>QUANTUM SECURITY PLATFORM</div>
          </div>
        </div>
      </div>
      <div style={{ display:'flex', alignItems:'center', gap:10 }}>
        {criticalCount > 0 && (
          <div style={{ background:'rgba(255,45,85,0.15)', border:`1px solid ${D.red}55`, borderRadius:8, padding:'4px 12px', display:'flex', gap:6, alignItems:'center', animation:'blink 1.5s ease-in-out infinite' }}>
            <span style={{ color:D.red, fontSize:10, fontWeight:800 }}>⚠ {criticalCount} CRITICAL</span>
          </div>
        )}
        <button onClick={triggerDbUpdate} style={{ background:dbUpdating?'rgba(0,212,255,0.2)':'rgba(0,212,255,0.08)', border:`1px solid ${D.cyan}44`, borderRadius:8, padding:'6px 14px', color:D.cyan, fontSize:11, fontWeight:700, cursor:'pointer' }}>
          {dbUpdating ? '⏳ Syncing…' : '☁️ Sync DB'}
        </button>
        <button onClick={()=>setVoiceActive(p=>!p)} style={{ background:voiceActive?'rgba(191,95,255,0.2)':'rgba(191,95,255,0.06)', border:`1px solid ${D.purple}44`, borderRadius:8, padding:'6px 12px', color:D.purple, fontSize:11, fontWeight:700, cursor:'pointer' }}>
          {voiceActive ? '🎙️ Listening…' : '🎙️ Voice'}
        </button>
        <div style={{ width:32, height:32, borderRadius:'50%', background:`linear-gradient(135deg,${D.blue},${D.purple})`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:14, cursor:'pointer', boxShadow:`0 0 10px ${D.purple}44` }} title="Biometric Admin Access">👤</div>
      </div>
    </div>
  );

  // ── Sidebar ─────────────────────────────────────────────────────────────────
  const Sidebar = () => (
    <>
      {sidebarOpen && <div onClick={()=>setSidebarOpen(false)} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.5)', zIndex:200 }} />}
      <div style={{ position:'fixed', top:0, left:0, bottom:0, width:220, background:D.surface, borderRight:`1px solid ${D.border}`, zIndex:300, transform: sidebarOpen ? 'translateX(0)' : 'translateX(-100%)', transition:'transform 0.25s cubic-bezier(0.4,0,0.2,1)', display:'flex', flexDirection:'column', padding:'16px 0' }}>
        <div style={{ padding:'10px 20px 20px', borderBottom:`1px solid ${D.border}`, marginBottom:8 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <div style={{ width:36, height:36, borderRadius:8, background:`linear-gradient(135deg,${D.blue},${D.cyan})`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:18, boxShadow:`0 0 16px ${D.cyan}55` }}>🦁</div>
            <div><div style={{ fontWeight:900, color:D.white, fontSize:13 }}>LeoNet Defense</div><div style={{ fontSize:9, color:D.cyan, letterSpacing:1 }}>v4.7.0 · QUANTUM CORE</div></div>
          </div>
        </div>
        {NAV.map(n => (
          <button key={n.id} onClick={()=>{ setView(n.id); setSidebarOpen(false); }} style={{ display:'flex', gap:12, alignItems:'center', padding:'11px 20px', background: view===n.id ? `linear-gradient(90deg,${D.blue}22,transparent)` : 'none', border:'none', borderLeft: view===n.id ? `2px solid ${D.cyan}` : '2px solid transparent', color: view===n.id ? D.white : D.muted, cursor:'pointer', fontSize:13, fontWeight: view===n.id ? 700 : 400, textAlign:'left', transition:'all 0.15s', width:'100%' }}>
            <span style={{ fontSize:16 }}>{n.icon}</span>{n.label}
          </button>
        ))}
        <div style={{ flex:1 }} />
        <div style={{ padding:'16px 20px', borderTop:`1px solid ${D.border}` }}>
          <div style={{ fontSize:10, color:D.muted, marginBottom:6, textTransform:'uppercase', letterSpacing:1 }}>System Status</div>
          <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:4 }}>
            <div style={{ width:6, height:6, borderRadius:'50%', background:D.green, boxShadow:`0 0 8px ${D.green}`, animation:'pulse-glow 1s ease-in-out infinite' }} />
            <span style={{ fontSize:11, color:D.green }}>All systems operational</span>
          </div>
          <div style={{ fontSize:10, color:D.muted }}>Uptime: 99.999% · QR-Encrypted</div>
        </div>
      </div>
    </>
  );

  // ── Bottom Tab Bar (mobile) ──────────────────────────────────────────────────
  const BottomTabs = () => (
    <div style={{ position:'fixed', bottom:0, left:0, right:0, background:D.surface, borderTop:`1px solid ${D.border}`, display:'flex', zIndex:100, padding:'4px 0 8px' }}>
      {NAV.slice(0,5).map(n=>(
        <button key={n.id} onClick={()=>setView(n.id)} style={{ flex:1, background:'none', border:'none', cursor:'pointer', padding:'6px 4px', display:'flex', flexDirection:'column', alignItems:'center', gap:2 }}>
          <span style={{ fontSize:18 }}>{n.icon}</span>
          <span style={{ fontSize:9, color: view===n.id?D.cyan:D.muted, fontWeight: view===n.id?700:400 }}>{n.label.split(' ')[0]}</span>
        </button>
      ))}
    </div>
  );

  // ── Toast ───────────────────────────────────────────────────────────────────
  const Toast = () => toast && (
    <div style={{ position:'fixed', top:70, right:20, background:D.panel, border:`1px solid ${toast.color}44`, borderRadius:10, padding:'12px 18px', color:toast.color, fontSize:13, fontWeight:700, zIndex:999, boxShadow:`0 8px 30px rgba(0,0,0,0.5), 0 0 20px ${toast.color}22`, animation:'slide-in-right 0.3s ease', maxWidth:340 }}>
      {toast.msg}
    </div>
  );

  // ── Views ───────────────────────────────────────────────────────────────────
  const renderView = () => {
    switch (view) {

      // ── DASHBOARD ──────────────────────────────────────────────────────────
      case 'dashboard': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <div style={{ marginBottom:20 }}>
            <h2 style={{ fontSize:20, fontWeight:900, color:D.white, margin:'0 0 4px' }}>⚡ Threat Operations Center</h2>
            <p style={{ fontSize:12, color:D.muted }}>AI-Powered Quantum Defense · Real-Time Intelligence · Zero-Trust Architecture</p>
          </div>

          {/* Stat Row */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))', gap:14, marginBottom:24 }}>
            <StatCard label="Active Threats"     value={threatCount}          icon="🎯" color={totalThreats>0?D.red:D.green}   sub={`${criticalCount} critical`} />
            <StatCard label="Threats Squashed"   value={squashedCount}        icon="✅" color={D.green}   sub="this session" />
            <StatCard label="DB Signatures"      value="1,284,921"            icon="🧬" color={D.cyan}    sub="+12,840 today" />
            <StatCard label="Scan Coverage"      value={scanPct>0?Math.round(scanPct):100} unit="%" icon="🔬" color={D.blue}    sub={scanning?scanMod:'Last scan: 08:00'} />
            <StatCard label="Network Blocked"    value="3,847"                icon="🛡️" color={D.orange}  sub="packets today" />
            <StatCard label="Zero-Days Predicted"value="7"                    icon="🔮" color={D.purple}  sub="AI confidence 94%" />
          </div>

          {/* Main panels */}
          <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 280px', gap:18, marginBottom:18 }}>
            <GlowCard color={D.cyan} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🎯 Live Threat Radar</div>
              <RadarRing threats={threats} tick={tick} />
              <div style={{ marginTop:20, display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                {[['Critical',D.critical],['High',D.high],['Medium',D.medium],['Low',D.low]].map(([s,c])=>{
                  const n = threats.filter(t=>!t.squashed&&t.severity===s.toLowerCase()).length;
                  return <div key={s} style={{ display:'flex', justifyContent:'space-between', background:`${c}11`, border:`1px solid ${c}22`, borderRadius:8, padding:'8px 12px' }}><span style={{ fontSize:11, color:c, fontWeight:700 }}>{s}</span><span style={{ fontSize:14, fontWeight:900, color:c }}>{n}</span></div>;
                })}
              </div>
            </GlowCard>

            <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <GlowCard color={D.green} style={{ padding:20 }}>
                <div style={{ fontSize:11, fontWeight:700, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginBottom:12 }}>AI Health Gauges</div>
                <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:4 }}>
                  <AIGauge value={98} label="Threat IQ" color={D.green} />
                  <AIGauge value={94} label="Zero-Day" color={D.purple} />
                  <AIGauge value={99} label="FP Shield" color={D.cyan} />
                  <AIGauge value={97} label="Response" color={D.blue} />
                </div>
              </GlowCard>
              <GlowCard color={D.cyan} style={{ padding:20 }}>
                <div style={{ fontSize:11, fontWeight:700, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginBottom:12 }}>System Resources</div>
                {[['CPU Impact','2.1%',D.green],['Memory Used','128 MB',D.cyan],['Disk I/O','Low',D.blue]].map(([l,v,c])=>(
                  <div key={l} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}><span style={{ fontSize:11, color:D.muted }}>{l}</span><span style={{ fontSize:11, color:c, fontWeight:700, fontFamily:'monospace' }}>{v}</span></div>
                ))}
                <div style={{ marginTop:8, fontSize:10, color:D.green }}>✓ Ultra-low footprint mode active</div>
              </GlowCard>
            </div>
          </div>

          {/* Scan area + recent threats */}
          <div style={{ display:'grid', gridTemplateColumns:'340px minmax(0,1fr)', gap:18 }}>
            <GlowCard color={D.blue} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:4 }}>🔬 Quick Scan</div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:16 }}>AI-powered quantum deep scan across all 12 modules</div>
              {SCAN_MODULES.slice(0,6).map(m => (
                <div key={m.id} style={{ display:'flex', gap:8, alignItems:'center', marginBottom:6, fontSize:11, color:scanDone?D.green:scanning&&scanMod===m.label?D.cyan:D.muted }}>
                  <span>{scanDone?'✓':scanning&&scanMod===m.label?'▶':'○'}</span>{m.icon} {m.label}
                </div>
              ))}
              <ScanProgress running={scanning} progress={scanPct} module={scanMod} />
              <button onClick={startScan} disabled={scanning} style={{ width:'100%', padding:'12px', borderRadius:8, border:'none', background: scanning ? D.border : `linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', cursor:scanning?'not-allowed':'pointer', fontWeight:800, fontSize:13, boxShadow: scanning?'none':`0 0 20px ${D.cyan}44`, transition:'all 0.15s' }}>
                {scanning ? `⏳ Scanning… ${Math.round(scanPct)}%` : scanDone ? '🔄 Rescan' : '⚡ Launch Deep Scan'}
              </button>
            </GlowCard>

            <GlowCard color={D.red} style={{ padding:24 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
                <div style={{ fontSize:13, fontWeight:800, color:D.white }}>🔥 Active Threats</div>
                {totalThreats > 0 && <button onClick={squashAll} style={{ background:`linear-gradient(135deg,${D.red},#CC0033)`, color:'#fff', border:'none', borderRadius:6, padding:'6px 14px', fontSize:11, fontWeight:800, cursor:'pointer' }}>⚡ Squash All</button>}
              </div>
              {threats.filter(t=>!t.squashed).slice(0,5).map(t => (
                <div key={t.id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 14px', background:'#081420', borderRadius:8, marginBottom:8, border:`1px solid ${sevColor(t.severity)}33`, cursor:'pointer' }}
                  onClick={()=>{ setSelected(t); setView('threat-matrix'); }}>
                  <div>
                    <div style={{ fontWeight:700, fontSize:12, color:D.text }}>{t.name}</div>
                    <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{t.type} · {t.status}</div>
                  </div>
                  <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                    <span style={{ color:sevColor(t.severity), fontSize:10, fontWeight:800, textTransform:'uppercase' }}>{t.severity}</span>
                    <button onClick={e=>{e.stopPropagation();squash(t.id);}} style={{ background:D.red, color:'#fff', border:'none', borderRadius:5, padding:'4px 10px', fontSize:10, fontWeight:800, cursor:'pointer' }}>✕</button>
                  </div>
                </div>
              ))}
              {totalThreats === 0 && <div style={{ textAlign:'center', padding:30, color:D.green, fontWeight:700 }}>✅ System Clean</div>}
            </GlowCard>
          </div>
        </div>
      );

      // ── THREAT MATRIX ──────────────────────────────────────────────────────
      case 'threat-matrix': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20, flexWrap:'wrap', gap:12 }}>
            <div>
              <h2 style={{ fontSize:20, fontWeight:900, color:D.white, margin:'0 0 4px' }}>🎯 3D Threat Matrix</h2>
              <p style={{ fontSize:12, color:D.muted }}>Interactive 3D view · Hover to tilt · Click Squash to neutralize threats</p>
            </div>
            <div style={{ display:'flex', gap:10 }}>
              {totalThreats > 0 && <button onClick={squashAll} style={{ background:`linear-gradient(135deg,${D.red},#CC0033)`, color:'#fff', border:'none', borderRadius:8, padding:'10px 20px', fontSize:12, fontWeight:800, cursor:'pointer', boxShadow:`0 0 14px ${D.red}55` }}>⚡ Squash All ({totalThreats})</button>}
              <button onClick={()=>{const csv='ID,Name,Type,Severity,Location,Confidence,Status\n'+threats.map(t=>`${t.id},"${t.name}","${t.type}",${t.severity},"${t.location}",${t.confidence}%,${t.status}`).join('\n');const b=new Blob([csv],{type:'text/csv'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download='leonet-scan-report.csv';a.click();}} style={{ background:D.panel, border:`1px solid ${D.cyan}44`, borderRadius:8, padding:'10px 18px', color:D.cyan, fontSize:12, fontWeight:700, cursor:'pointer' }}>📥 Export Report</button>
            </div>
          </div>
          <div style={{ overflowX:'auto', marginBottom:24 }}>
            <ThreatTable3D threats={threats} onSquash={squash} />
          </div>

          {/* Remediation panel */}
          <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 300px', gap:18 }}>
            <GlowCard color={D.blue} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:4 }}>🔧 Remediation Steps</div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:12 }}>Click any threat row above to load its remediation plan</div>
              <RemediationSteps threat={selectedThreat || threats.find(t=>!t.squashed)} />
            </GlowCard>
            <GlowCard color={D.purple} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📊 Severity Breakdown</div>
              {['critical','high','medium','low'].map(s => {
                const n = threats.filter(t=>!t.squashed&&t.severity===s).length;
                return <TimelineBar key={s} label={s.charAt(0).toUpperCase()+s.slice(1)} val={n} max={threats.length} color={sevColor(s)} />;
              })}
              <div style={{ marginTop:16, padding:14, background:'#081420', borderRadius:10, border:`1px solid ${D.border}` }}>
                <div style={{ fontSize:11, color:D.muted, marginBottom:8 }}>Rollback Available</div>
                <div style={{ fontSize:12, color:D.green, fontWeight:700 }}>✅ Shadow copies verified</div>
                <div style={{ fontSize:11, color:D.muted, marginTop:4 }}>3 restore points · Blockchain-verified</div>
              </div>
            </GlowCard>
          </div>
        </div>
      );

      // ── DEEP SCAN ──────────────────────────────────────────────────────────
      case 'scan': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🔬 Deep Scan Center</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>12-module AI quantum scan · Polymorphic disassembly · Fileless detection · Kernel forensics</p>

          <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 300px', gap:18 }}>
            <GlowCard color={D.blue} style={{ padding:24 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
                <div style={{ fontSize:14, fontWeight:800, color:D.white }}>Scan Modules</div>
                <div style={{ fontSize:11, color: scanning?D.cyan:scanDone?D.green:D.muted, fontWeight:700 }}>
                  {scanning ? `⏳ Scanning — ${Math.round(scanPct)}%` : scanDone ? '✅ Complete' : '● Idle'}
                </div>
              </div>
              <div style={{ marginBottom:20 }}>
                <ScanProgress running={scanning} progress={scanPct} module={scanMod} />
              </div>
              <div style={{ display:'grid', gap:10, marginBottom:20 }}>
                {SCAN_MODULES.map(m => {
                  const modPct = SCAN_MODULES.indexOf(m) * (100/SCAN_MODULES.length);
                  const done = scanDone || (!scanning && scanPct === 0 ? false : scanPct > modPct+8);
                  const active = scanning && scanMod === m.label;
                  return (
                    <div key={m.id} style={{ display:'flex', gap:12, alignItems:'center', padding:'12px 16px', background: active?'rgba(26,122,255,0.1)':'#081420', borderRadius:10, border:`1px solid ${active?D.blue:done&&scanPct>0?D.green:D.border2}`, transition:'all 0.3s' }}>
                      <span style={{ fontSize:20 }}>{m.icon}</span>
                      <div style={{ flex:1 }}>
                        <div style={{ fontSize:12, fontWeight:700, color: active?D.white:done&&scanPct>0?D.green:D.text }}>{m.label}</div>
                        <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{m.desc}</div>
                      </div>
                      <div style={{ fontSize:12, color: active?D.cyan:done&&scanPct>0?D.green:D.muted, fontWeight:700 }}>
                        {active?'▶ Scanning':done&&scanPct>0?'✓ Done':'○ Queued'}
                      </div>
                    </div>
                  );
                })}
              </div>
              <div style={{ display:'flex', gap:10 }}>
                <button onClick={startScan} disabled={scanning} style={{ flex:2, padding:'13px', borderRadius:8, border:'none', background:scanning?D.border:`linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', cursor:scanning?'not-allowed':'pointer', fontWeight:800, fontSize:14, boxShadow:scanning?'none':`0 0 24px ${D.cyan}44` }}>
                  {scanning ? `⏳ Scanning… ${Math.round(scanPct)}%` : '⚡ Launch Full Deep Scan'}
                </button>
                <button style={{ flex:1, padding:'13px', borderRadius:8, border:`1px solid ${D.border}`, background:'none', color:D.muted, cursor:'pointer', fontWeight:600, fontSize:13 }}>⏰ Schedule</button>
              </div>
            </GlowCard>

            <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <GlowCard color={D.green} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>⚙️ Scan Configuration</div>
                {[['Mode','Quantum Deep'],['AI Engine','v4.7 — Online'],['Polymorphic','Enabled'],['Sandbox','Enabled'],['Fileless Hunt','Enabled'],['FP Reduction','AI Active']].map(([k,v])=>(
                  <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                    <span style={{ fontSize:11, color:D.muted }}>{k}</span>
                    <span style={{ fontSize:11, color:D.green, fontWeight:700 }}>{v}</span>
                  </div>
                ))}
              </GlowCard>
              <GlowCard color={D.purple} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🔮 Zero-Day Predictions</div>
                {[['Browser exploit kit','87%'],['UEFI firmware attack','72%'],['Supply chain poison','68%'],['Memory injection','81%']].map(([t,c])=>(
                  <div key={t} style={{ marginBottom:10 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}><span style={{ fontSize:11, color:D.text }}>{t}</span><span style={{ fontSize:11, color:D.purple, fontWeight:800 }}>{c}</span></div>
                    <div style={{ height:3, background:D.border, borderRadius:2 }}><div style={{ height:'100%', width:c, background:`linear-gradient(90deg,${D.purple},${D.blue})`, borderRadius:2 }} /></div>
                  </div>
                ))}
              </GlowCard>
              <GlowCard color={D.cyan} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🕐 Scheduled Scans</div>
                {[['Daily Deep Scan','00:00 · Auto'],['Firmware Check','Sun 03:00'],['IoT Audit','Every 6h'],['DB Sync','Every 1h']].map(([s,t])=>(
                  <div key={s} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                    <span style={{ fontSize:11, color:D.text }}>{s}</span>
                    <span style={{ fontSize:11, color:D.cyan, fontFamily:'monospace' }}>{t}</span>
                  </div>
                ))}
              </GlowCard>
            </div>
          </div>
        </div>
      );

      // ── NETWORK SHIELD ─────────────────────────────────────────────────────
      case 'network': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🌐 Network Shield</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>DDoS mitigation · Packet deep inspection · Adaptive firewall · Backdoor detection</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(170px,1fr))', gap:12, marginBottom:20 }}>
            {[['Packets Inspected','847,293',D.cyan],['DDoS Attempts','14',D.red],['Connections Blocked','3,847',D.orange],['Bandwidth Scrubbed','2.4 Gbps',D.green],['Active Rules','6',D.blue],['Uptime','99.999%',D.gold]].map(([l,v,c])=>(
              <GlowCard key={l} color={c} style={{ padding:'14px 18px' }}>
                <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>{l}</div>
                <div style={{ fontSize:22, fontWeight:900, color:c, fontFamily:'monospace' }}>{v}</div>
              </GlowCard>
            ))}
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 300px', gap:18, marginBottom:18 }}>
            <GlowCard color={D.cyan} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🗺️ Network Topology Map</div>
              <NetworkMap tick={tick} />
            </GlowCard>
            <GlowCard color={D.orange} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📡 Live Packet Feed</div>
              {NETWORK_EVENTS.map((e,i) => (
                <div key={i} style={{ padding:'8px 0', borderBottom:`1px solid ${D.border2}`, display:'flex', gap:8, alignItems:'flex-start' }}>
                  <span style={{ fontFamily:'monospace', fontSize:10, color:D.muted, flexShrink:0 }}>{e.time}</span>
                  <div>
                    <div style={{ fontSize:11, color: e.action==='BLOCKED'?D.red:e.action==='INSPECTED'?D.cyan:D.green, fontWeight:700 }}>{e.action} · {e.type}</div>
                    <div style={{ fontSize:10, color:D.muted }}>{e.src} → {e.dst}:{e.port}</div>
                  </div>
                </div>
              ))}
            </GlowCard>
          </div>

          <GlowCard color={D.blue} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔥 Adaptive Firewall Rules</div>
            <FirewallRules />
            <div style={{ marginTop:14, display:'flex', gap:10 }}>
              <button style={{ background:`linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', border:'none', borderRadius:8, padding:'9px 20px', fontWeight:700, fontSize:12, cursor:'pointer' }}>+ Add Rule</button>
              <button style={{ background:D.panel, border:`1px solid ${D.border}`, borderRadius:8, padding:'9px 20px', color:D.muted, fontSize:12, fontWeight:600, cursor:'pointer' }}>📥 Export Rules</button>
            </div>
          </GlowCard>
        </div>
      );

      // ── MEMORY LAB ─────────────────────────────────────────────────────────
      case 'memory': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🧠 Memory Forensics Lab</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Stealth malware detection · Process injection forensics · Fileless payload extraction · Sandbox detonation</p>

          <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 280px', gap:18, marginBottom:18 }}>
            <GlowCard color={D.cyan} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔥 Memory Heat Map (Live)</div>
              <MemoryHeatMap tick={tick} />
              <div style={{ marginTop:16 }}>
                <div style={{ fontSize:11, color:D.red, fontWeight:700 }}>⚠ 3 anomalous memory regions detected</div>
                <div style={{ fontSize:11, color:D.muted, marginTop:4 }}>Regions 0xC000, 0xD000, 0x1C000 — suspicious shellcode patterns</div>
              </div>
            </GlowCard>

            <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <GlowCard color={D.purple} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>👻 Fileless Hunter</div>
                {[['PowerShell Injection','Detected · Blocked'],['WMI Persistence','Clear'],['COM Hijacking','Monitoring'],['LOLBins Abuse','Monitoring']].map(([l,v])=>(
                  <div key={l} style={{ display:'flex', justifyContent:'space-between', marginBottom:8, padding:'8px 10px', background:'#081420', borderRadius:6 }}>
                    <span style={{ fontSize:11, color:D.text }}>{l}</span>
                    <span style={{ fontSize:10, color:v.includes('Detected')?D.red:v==='Clear'?D.green:D.orange, fontWeight:700 }}>{v}</span>
                  </div>
                ))}
              </GlowCard>
              <GlowCard color={D.orange} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🏖️ Sandbox Status</div>
                <div style={{ marginBottom:12 }}>
                  <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:6 }}>
                    <div style={{ width:8, height:8, borderRadius:'50%', background:D.green, boxShadow:`0 0 8px ${D.green}` }} />
                    <span style={{ fontSize:11, color:D.green, fontWeight:700 }}>Sandbox Active</span>
                  </div>
                  <div style={{ fontSize:10, color:D.muted }}>3 containers ready · Isolated kernel</div>
                </div>
                {[['Samples Detonated','147'],['Verdicts','142 malicious'],['Avg Analysis','4.2s'],['CPU Overhead','0.3%']].map(([k,v])=>(
                  <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
                    <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                    <span style={{ fontSize:10, color:D.text, fontWeight:700, fontFamily:'monospace' }}>{v}</span>
                  </div>
                ))}
              </GlowCard>
              <GlowCard color={D.blue} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🔩 Process Monitor</div>
                {[['lsass.exe (788)','⚠ Anomaly',D.red],['svchost.exe (1024)','✓ Clean',D.green],['explorer.exe (2048)','✓ Clean',D.green],['powershell.exe (3901)','⚠ Watching',D.orange]].map(([p,s,c])=>(
                  <div key={p} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                    <span style={{ fontSize:10, color:D.muted, fontFamily:'monospace' }}>{p}</span>
                    <span style={{ fontSize:10, color:c, fontWeight:700 }}>{s}</span>
                  </div>
                ))}
              </GlowCard>
            </div>
          </div>
        </div>
      );

      // ── INTEL FEED ─────────────────────────────────────────────────────────
      case 'intel': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>📡 Global Intelligence Feed</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Blockchain-verified signatures · 1M+ daily updates · Zero-day consortium · Quantum-resistant encryption</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))', gap:12, marginBottom:20 }}>
            {[['Total Signatures','1,284,921',D.cyan],['Today\'s Updates','12,840',D.green],['Zero-Days','7 active',D.red],['Blockchain Blocks','48,291',D.gold],['Partners','142 TIs',D.blue],['Last Sync','08:41:22',D.purple]].map(([l,v,c])=>(
              <GlowCard key={l} color={c} style={{ padding:'14px 18px' }}>
                <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>{l}</div>
                <div style={{ fontSize:18, fontWeight:900, color:c, fontFamily:'monospace' }}>{v}</div>
              </GlowCard>
            ))}
          </div>

          <GlowCard color={D.cyan} style={{ padding:24, marginBottom:18 }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white }}>🔗 Blockchain-Verified Threat Records</div>
              <div style={{ fontSize:10, color:D.green, fontWeight:700 }}>⛓ Chain intact · 48,291 blocks</div>
            </div>
            <div style={{ overflowX:'auto' }}>
              <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
                <thead><tr style={{ background:'#061428' }}>{['TI ID','SHA-256 Hash','Malware Family','Origin','First Seen','Severity','Reports','Verified'].map(h=>(
                  <th key={h} style={{ padding:'9px 12px', textAlign:'left', color:D.muted, fontSize:10, fontWeight:700, textTransform:'uppercase', letterSpacing:1, borderBottom:`1px solid ${D.border}` }}>{h}</th>
                ))}</tr></thead>
                <tbody>{INTEL_FEED.map((r,i)=>(
                  <tr key={r.id} style={{ background:i%2===0?'#081420':'#0A1828', borderBottom:`1px solid ${D.border2}` }}>
                    <td style={{ padding:'9px 12px', color:D.muted, fontFamily:'monospace', fontSize:10 }}>{r.id}</td>
                    <td style={{ padding:'9px 12px', color:D.cyan, fontFamily:'monospace', fontSize:9 }}>{r.hash}</td>
                    <td style={{ padding:'9px 12px', color:D.text, fontWeight:700 }}>{r.family}</td>
                    <td style={{ padding:'9px 12px', color:D.muted }}>{r.origin}</td>
                    <td style={{ padding:'9px 12px', color:D.muted, fontFamily:'monospace', fontSize:10 }}>{r.first}</td>
                    <td style={{ padding:'9px 12px' }}><span style={{ color:sevColor(r.severity), fontWeight:800, fontSize:10, textTransform:'uppercase' }}>{r.severity}</span></td>
                    <td style={{ padding:'9px 12px', color:D.text, fontFamily:'monospace' }}>{r.reports.toLocaleString()}</td>
                    <td style={{ padding:'9px 12px', color:r.verified?D.green:D.orange, fontWeight:800 }}>{r.verified?'✓ Yes':'⏳ Pending'}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </GlowCard>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18 }}>
            <GlowCard color={D.purple} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔮 AI Threat Predictions</div>
              {[['LockBit 5.0 Variant','Next 48h','91%'],['Supply Chain Attack','Next 7 days','78%'],['BIOS Wiper Campaign','Next 30 days','64%'],['Mobile Banking Trojan','Active now','88%']].map(([t,w,c])=>(
                <div key={t} style={{ marginBottom:14, padding:'10px 14px', background:'#081420', borderRadius:8, border:`1px solid ${D.purple}22` }}>
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                    <span style={{ fontSize:12, color:D.text, fontWeight:700 }}>{t}</span>
                    <span style={{ fontSize:11, color:D.purple, fontWeight:800 }}>{c}</span>
                  </div>
                  <div style={{ fontSize:10, color:D.muted }}>{w}</div>
                  <div style={{ height:3, background:D.border, borderRadius:2, marginTop:8 }}><div style={{ height:'100%', width:c, background:`linear-gradient(90deg,${D.purple},${D.blue})`, borderRadius:2 }} /></div>
                </div>
              ))}
            </GlowCard>
            <GlowCard color={D.gold} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🌍 Threat Origin Map</div>
              {[['Eastern Europe','3,291 threats',38],['Nation-State (APT)','891 threats',10],['Unknown / TOR','2,104 threats',24],['United States','448 threats',5],['China','621 threats',7],['Other','1,444 threats',16]].map(([r,v,pct])=>(
                <div key={r} style={{ marginBottom:10 }}>
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
                    <span style={{ fontSize:11, color:D.text }}>{r}</span>
                    <span style={{ fontSize:11, color:D.gold, fontFamily:'monospace' }}>{v}</span>
                  </div>
                  <div style={{ height:4, background:D.border, borderRadius:2 }}><div style={{ height:'100%', width:`${pct}%`, background:`linear-gradient(90deg,${D.gold}88,${D.gold})`, borderRadius:2 }} /></div>
                </div>
              ))}
            </GlowCard>
          </div>
        </div>
      );

      // ── COMPLIANCE ─────────────────────────────────────────────────────────
      case 'compliance': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🛡️ Compliance & Standards</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>GDPR · HIPAA · DoD · ISO 27001 · SOC 2 · NIST CSF · Quantum-resistant encryption</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(160px,1fr))', gap:14, marginBottom:24 }}>
            {[['GDPR','compliant','🇪🇺'],['HIPAA','compliant','🏥'],['DoD 8500','compliant','🏛️'],['ISO 27001','compliant','🌐'],['SOC 2 Type II','compliant','✅'],['NIST CSF','compliant','🔒'],['FIPS 140-3','compliant','⚡'],['PCI DSS','reviewing','💳']].map(([n,s,i])=>(
              <ComplianceBadge key={n} name={n} status={s} icon={i} />
            ))}
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.green} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔐 Encryption Status</div>
              {[['Data at Rest','AES-256-GCM · Quantum-resistant'],['Data in Transit','TLS 1.3 + CRYSTALS-Kyber'],['Key Storage','Hardware HSM · FIPS 140-3'],['Scan Logs','ChaCha20-Poly1305 encrypted'],['Blockchain Ledger','SHA3-512 + Dilithium']].map(([k,v])=>(
                <div key={k} style={{ marginBottom:10, padding:'10px 14px', background:'rgba(0,255,136,0.05)', borderRadius:8, border:`1px solid ${D.green}22` }}>
                  <div style={{ fontSize:11, color:D.muted, marginBottom:3 }}>{k}</div>
                  <div style={{ fontSize:12, color:D.green, fontWeight:700 }}>{v}</div>
                </div>
              ))}
            </GlowCard>
            <GlowCard color={D.blue} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📋 Audit Log Summary</div>
              {[['Events Today','12,847'],['Admin Actions','34'],['Policy Changes','2'],['Failed Logins','0'],['Data Exports','3'],['Scan Reports','8']].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'9px 0', borderBottom:`1px solid ${D.border2}` }}>
                  <span style={{ fontSize:12, color:D.text }}>{k}</span>
                  <span style={{ fontSize:13, fontWeight:800, color:D.cyan, fontFamily:'monospace' }}>{v}</span>
                </div>
              ))}
              <button style={{ marginTop:14, width:'100%', padding:'10px', borderRadius:8, border:`1px solid ${D.blue}44`, background:'rgba(26,122,255,0.1)', color:D.blue, fontWeight:700, fontSize:12, cursor:'pointer' }}>📥 Download Full Audit Report</button>
            </GlowCard>
          </div>

          <GlowCard color={D.purple} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔗 SIEM / EDR Integrations</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))', gap:14 }}>
              {[['Splunk SIEM','Connected · 847 events/hr',D.green],['Microsoft Sentinel','Connected · Real-time',D.green],['CrowdStrike EDR','Active · Threat sharing',D.green],['IBM QRadar','Standby · Ready',D.cyan],['Elastic SIEM','Connected · Log stream',D.green],['Palo Alto XSIAM','Available',D.muted]].map(([n,s,c])=>(
                <div key={n} style={{ background:'#081420', borderRadius:10, padding:'14px 16px', border:`1px solid ${c}33` }}>
                  <div style={{ fontWeight:700, fontSize:12, color:D.text, marginBottom:4 }}>{n}</div>
                  <div style={{ fontSize:10, color:c }}>{s}</div>
                </div>
              ))}
            </div>
          </GlowCard>
        </div>
      );

      // ── TRAINING ───────────────────────────────────────────────────────────
      case 'training': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🎮 Gamified Security Training</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Earn XP · Unlock badges · Master cybersecurity · Compete on global leaderboard</p>

          <div style={{ display:'grid', gridTemplateColumns:'minmax(0,1fr) 280px', gap:18, marginBottom:18 }}>
            <div>
              <GlowCard color={D.gold} style={{ padding:24, marginBottom:16 }}>
                <div style={{ display:'flex', gap:20, alignItems:'center' }}>
                  <div style={{ width:72, height:72, borderRadius:'50%', background:`linear-gradient(135deg,${D.gold},${D.orange})`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:32, boxShadow:`0 0 24px ${D.gold}55` }}>👑</div>
                  <div>
                    <div style={{ fontSize:11, color:D.muted, textTransform:'uppercase', letterSpacing:1 }}>Your Rank</div>
                    <div style={{ fontSize:24, fontWeight:900, color:D.gold }}>Security Analyst II</div>
                    <div style={{ fontSize:13, color:D.text, marginTop:4 }}>{trainingXP.toLocaleString()} XP · Level 8</div>
                    <div style={{ height:6, background:D.border, borderRadius:3, marginTop:10, width:240 }}>
                      <div style={{ height:'100%', width:`${(trainingXP % 2000) / 20}%`, background:`linear-gradient(90deg,${D.gold},${D.orange})`, borderRadius:3 }} />
                    </div>
                    <div style={{ fontSize:10, color:D.muted, marginTop:4 }}>{2000 - (trainingXP % 2000)} XP to Level 9</div>
                  </div>
                </div>
              </GlowCard>

              {TRAINING_MODULES.map(m => (
                <GlowCard key={m.id} color={m.complete?D.green:D.border} style={{ padding:20, marginBottom:12, cursor:'pointer' }}
                  onClick={()=>{ if (!m.complete) { setTrainingXP(p => p + Math.floor(m.xp * 0.1)); showToast(`🎮 Started: ${m.title} — good luck!`, D.purple); } }}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                    <div style={{ display:'flex', gap:14, alignItems:'center' }}>
                      <div style={{ width:44, height:44, borderRadius:12, background: m.complete?'rgba(0,255,136,0.15)':'rgba(255,255,255,0.05)', border:`2px solid ${m.complete?D.green:D.border}`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:20 }}>{m.badge}</div>
                      <div>
                        <div style={{ fontWeight:700, fontSize:13, color:m.complete?D.green:D.text }}>{m.title}</div>
                        <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{m.level} · {m.xp.toLocaleString()} XP reward</div>
                      </div>
                    </div>
                    <div style={{ fontSize:12, color: m.complete?D.green:D.blue, fontWeight:800 }}>
                      {m.complete ? '✓ Complete' : '▶ Start'}
                    </div>
                  </div>
                </GlowCard>
              ))}
            </div>

            <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <GlowCard color={D.purple} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🏆 Global Leaderboard</div>
                {[['1st','IronFox_99','14,280 XP'],['2nd','CyberWolf','12,910 XP'],['3rd','NightOwl','11,445 XP'],['4th','You','1,250 XP'],['5th','PhantomX','1,100 XP']].map(([r,n,x])=>(
                  <div key={n} style={{ display:'flex', gap:10, alignItems:'center', padding:'8px 10px', background:n==='You'?'rgba(191,95,255,0.1)':'#081420', borderRadius:8, marginBottom:6, border:`1px solid ${n==='You'?D.purple:D.border2}` }}>
                    <span style={{ fontSize:12, color:D.gold, fontWeight:900, width:24 }}>{r}</span>
                    <span style={{ fontSize:12, color:n==='You'?D.purple:D.text, fontWeight:700, flex:1 }}>{n}</span>
                    <span style={{ fontSize:11, color:D.muted, fontFamily:'monospace' }}>{x}</span>
                  </div>
                ))}
              </GlowCard>
              <GlowCard color={D.gold} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🎖️ Earned Badges</div>
                {[['🎖️','Phishing Hunter','Completed'],['🔒','Password Master','Completed'],['🛡️','Defender','Locked']].map(([ic,n,s])=>(
                  <div key={n} style={{ display:'flex', gap:10, alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${D.border2}` }}>
                    <span style={{ fontSize:20, opacity:s==='Locked'?0.3:1 }}>{ic}</span>
                    <div>
                      <div style={{ fontSize:11, color:s==='Locked'?D.muted:D.text, fontWeight:700 }}>{n}</div>
                      <div style={{ fontSize:10, color:s==='Locked'?D.muted:D.green }}>{s}</div>
                    </div>
                  </div>
                ))}
              </GlowCard>
              <GlowCard color={D.cyan} style={{ padding:20 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:12 }}>📱 Mobile Remote Control</div>
                <div style={{ fontSize:11, color:D.muted, lineHeight:1.7 }}>LeoNet mobile app lets you:<br/>• Start/stop scans remotely<br/>• Receive push threat alerts<br/>• Squash threats on-the-go<br/>• View live dashboard</div>
                <div style={{ marginTop:12, display:'flex', gap:8 }}>
                  <button style={{ flex:1, padding:'8px', borderRadius:6, border:`1px solid ${D.cyan}44`, background:'rgba(0,212,255,0.08)', color:D.cyan, fontSize:10, fontWeight:700, cursor:'pointer' }}>📱 iOS App</button>
                  <button style={{ flex:1, padding:'8px', borderRadius:6, border:`1px solid ${D.green}44`, background:'rgba(0,255,136,0.08)', color:D.green, fontSize:10, fontWeight:700, cursor:'pointer' }}>🤖 Android</button>
                </div>
              </GlowCard>
            </div>
          </div>
        </div>
      );

      // ── SETTINGS ───────────────────────────────────────────────────────────
      case 'settings': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>⚙️ Settings & Configuration</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Enterprise deployment · Cross-platform · Biometric admin · Auto-update · Help · Community · Multilingual</p>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.blue} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🌍 Deployment & Platform</div>
              {[['Deployment Mode','Enterprise Multi-User'],['Platforms','Windows · macOS · Linux · iOS · Android'],['Node Count','1 (Local) + 3 Remote'],['Auto-Update','Enabled · No reboot required'],['Offline Cache','48h intelligence cached'],['CPU Limit','≤ 5% during scan'],['Memory Limit','256 MB max']].map(([k,v])=>(
                <div key={k} style={{ marginBottom:10 }}>
                  <div style={{ fontSize:10, color:D.muted, marginBottom:2 }}>{k}</div>
                  <div style={{ fontSize:12, color:D.text, fontWeight:600 }}>{v}</div>
                </div>
              ))}
            </GlowCard>
            <GlowCard color={D.purple} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔑 Access Control</div>
              <div style={{ padding:'12px 16px', background:'rgba(191,95,255,0.08)', border:`1px solid ${D.purple}33`, borderRadius:10, marginBottom:14 }}>
                <div style={{ fontSize:11, fontWeight:700, color:D.purple, marginBottom:4 }}>Biometric Admin Lock</div>
                <div style={{ fontSize:11, color:D.muted }}>Fingerprint · Face ID · PIN fallback</div>
                <div style={{ marginTop:10, display:'flex', gap:8 }}>
                  <div style={{ width:8, height:8, borderRadius:'50%', background:D.green, boxShadow:`0 0 8px ${D.green}`, marginTop:3 }} />
                  <span style={{ fontSize:11, color:D.green, fontWeight:700 }}>Biometric lock active</span>
                </div>
              </div>
              {[['Admin Users','3 active accounts'],['Role-Based Access','Enabled · RBAC v2'],['SSO Integration','Azure AD · Okta'],['Session Timeout','15 min idle'],['MFA Required','All admin actions']].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:11, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:11, color:D.text, fontWeight:600 }}>{v}</span>
                </div>
              ))}
            </GlowCard>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18 }}>
            <GlowCard color={D.green} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🎙️ Voice & Automation</div>
              <div style={{ padding:'12px 14px', background:'rgba(0,255,136,0.06)', border:`1px solid ${D.green}33`, borderRadius:8, marginBottom:14 }}>
                <div style={{ fontSize:11, fontWeight:700, color:D.green }}>Voice Commands Available</div>
                <div style={{ fontSize:10, color:D.muted, marginTop:6, lineHeight:1.7 }}>
                  "Leo, start deep scan"<br/>"Leo, squash all threats"<br/>"Leo, show threat report"<br/>"Leo, block IP 185.220.101.42"<br/>"Leo, update signature database"
                </div>
              </div>
              {[['Auto-Scan on Boot','Enabled'],['Self-Healing Mode','Active'],['Predictive Maintenance','Running'],['False Positive AI','v3.1 · 99.97% accuracy'],['Behavioral Alerts','Email · SMS · Push']].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:11, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:11, color:D.green, fontWeight:700 }}>{v}</span>
                </div>
              ))}
            </GlowCard>
            <GlowCard color={D.gold} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📊 LeoNet Advantage</div>
              {[['Detection Rate','99.998%',D.green],['Zero-Day Coverage','94% predicted',D.purple],['False Positive Rate','0.003%',D.green],['Mean Time to Detect','< 0.8 seconds',D.cyan],['Recovery Time (RTO)','< 4 minutes',D.blue],['Signature Updates','1M+ / day',D.gold],['Uptime SLA','99.999%',D.green]].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8, padding:'6px 10px', background:'#081420', borderRadius:6 }}>
                  <span style={{ fontSize:11, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:11, color:c, fontWeight:800, fontFamily:'monospace' }}>{v}</span>
                </div>
              ))}
              <div style={{ marginTop:14, padding:'10px 14px', background:'rgba(255,215,0,0.06)', border:`1px solid ${D.gold}33`, borderRadius:8, fontSize:11, color:D.gold, fontWeight:700, textAlign:'center' }}>
                🏆 Proprietary AI Core — Unbeatable Market Edge
              </div>
            </GlowCard>
          </div>

          {/* Help, Community, Multilingual, Feedback, Dev Lifecycle */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(220px,1fr))', gap:18, marginTop:18 }}>
            <GlowCard color={D.cyan} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>📚 Help Center</div>
              {[['Getting Started Guide','8 min read'],['Threat Response Handbook','22 min read'],['API Security Manual','15 min read'],['Compliance Checklist','12 min read'],['Video Walkthrough','18 videos']].map(([t,d])=>(
                <div key={t} style={{ display:'flex', justifyContent:'space-between', padding:'8px 0', borderBottom:`1px solid ${D.border2}`, cursor:'pointer' }}
                  onClick={()=>showToast(`📖 Opening: ${t}`,D.cyan)}>
                  <span style={{ fontSize:11, color:D.text }}>{t}</span>
                  <span style={{ fontSize:10, color:D.muted }}>{d}</span>
                </div>
              ))}
              <button onClick={()=>showToast('🔍 Opening full documentation…',D.cyan)} style={{ marginTop:12, width:'100%', padding:'8px', borderRadius:6, border:`1px solid ${D.cyan}44`, background:'rgba(0,212,255,0.08)', color:D.cyan, fontSize:11, fontWeight:700, cursor:'pointer' }}>Open Full Docs →</button>
            </GlowCard>

            <GlowCard color={D.purple} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>👥 Community Forum</div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:12 }}>Connect with 14,800+ security professionals worldwide</div>
              {[['🔥 LockBit 4.0 IOC sharing thread','847 replies'],['🛡️ Hardening Windows Server 2025','312 replies'],['🤖 AI false positive tuning tips','201 replies'],['🌑 Dark web monitor best practices','178 replies']].map(([t,r])=>(
                <div key={t} style={{ padding:'8px 0', borderBottom:`1px solid ${D.border2}`, cursor:'pointer' }} onClick={()=>showToast('🌐 Opening community forum…',D.purple)}>
                  <div style={{ fontSize:11, color:D.text }}>{t}</div>
                  <div style={{ fontSize:9, color:D.muted, marginTop:2 }}>{r}</div>
                </div>
              ))}
              <button onClick={()=>showToast('🌐 Opening community…',D.purple)} style={{ marginTop:12, width:'100%', padding:'8px', borderRadius:6, border:`1px solid ${D.purple}44`, background:'rgba(191,95,255,0.08)', color:D.purple, fontSize:11, fontWeight:700, cursor:'pointer' }}>Join Community →</button>
            </GlowCard>

            <GlowCard color={D.gold} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🌍 Multilingual Support</div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:12 }}>Available in 24 languages — select your preference</div>
              {[['English (Default)','Active','✓'],['French','Available',''],['Arabic','Available',''],['Spanish','Available',''],['Mandarin','Available',''],['Portuguese','Available','']].map(([l,s,a])=>(
                <div key={l} style={{ display:'flex', justifyContent:'space-between', padding:'7px 0', borderBottom:`1px solid ${D.border2}`, cursor:'pointer' }}>
                  <span style={{ fontSize:11, color:a?D.gold:D.text, fontWeight:a?700:400 }}>{l}</span>
                  <span style={{ fontSize:10, color:a?D.gold:D.muted }}>{a||s}</span>
                </div>
              ))}
            </GlowCard>

            <GlowCard color={D.green} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>💬 Feedback & Dev Lifecycle</div>
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:11, color:D.muted, marginBottom:8 }}>Share feedback to improve LeoNet</div>
                <textarea placeholder="Describe a feature, bug, or improvement…" style={{ width:'100%', height:70, background:'#081420', border:`1px solid ${D.border}`, borderRadius:8, color:D.text, padding:'8px 12px', fontSize:11, resize:'none', outline:'none', boxSizing:'border-box' }} />
                <button onClick={()=>showToast('✅ Feedback submitted — thank you!',D.green)} style={{ marginTop:8, width:'100%', padding:'8px', borderRadius:6, border:'none', background:`linear-gradient(135deg,${D.blue},${D.green})`, color:'#fff', fontSize:11, fontWeight:800, cursor:'pointer' }}>Submit Feedback</button>
              </div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:8 }}>Secure Dev Lifecycle (SDL)</div>
              {[['SAST scanning','In CI pipeline'],['Dependency audits','Weekly'],['Threat modelling','Per release'],['Pen-test cadence','Quarterly']].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
                  <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:10, color:D.green, fontWeight:700 }}>{v}</span>
                </div>
              ))}
            </GlowCard>
          </div>
        </div>
      );

      // ── FORENSICS ─────────────────────────────────────────────────────────
      case 'forensics': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🔎 Forensics Lab</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Digital footprint · Web app scanning · API security · Social media · Password strength · Incident timeline</p>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.cyan} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🌐 Digital Footprint Analysis</div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:14 }}>External attack surface of your organisation visible to adversaries</div>
              {[
                ['Public IPs Exposed','14',D.orange],['Open Ports Found','6',D.red],['Subdomains Indexed','38',D.cyan],
                ['Leaked Credentials','3',D.red],['Paste Sites Matches','1',D.orange],['SSL Cert Issues','0',D.green],
              ].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'8px 12px', background:'#081420', borderRadius:8, marginBottom:6, border:`1px solid ${c}22` }}>
                  <span style={{ fontSize:11, color:D.text }}>{k}</span>
                  <span style={{ fontSize:13, fontWeight:900, color:c, fontFamily:'monospace' }}>{v}</span>
                </div>
              ))}
              <button style={{ marginTop:10, width:'100%', padding:'10px', borderRadius:8, border:'none', background:`linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', fontWeight:800, fontSize:12, cursor:'pointer' }}>🔍 Re-Scan Footprint</button>
            </GlowCard>

            <GlowCard color={D.orange} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🕸️ Web Application Scanner</div>
              {[
                ['SQL Injection','2 issues found',D.red],['XSS Vulnerabilities','1 found',D.orange],
                ['CSRF Protection','✓ Enabled',D.green],['Insecure Headers','3 missing',D.orange],
                ['Broken Auth','✓ Clean',D.green],['Sensitive Data Exposure','1 endpoint',D.red],
                ['OWASP Top 10','7/10 passing',D.cyan],['API Rate Limiting','✓ Active',D.green],
              ].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'7px 12px', borderBottom:`1px solid ${D.border2}` }}>
                  <span style={{ fontSize:11, color:D.text }}>{k}</span>
                  <span style={{ fontSize:11, color:c, fontWeight:700 }}>{v}</span>
                </div>
              ))}
            </GlowCard>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.purple} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🔐 Password Strength Assessment</div>
              {[
                ['Admin accounts','All strong ✓',D.green],['Service accounts','2 weak found',D.red],
                ['Default credentials','0 detected',D.green],['Password reuse','1 account',D.orange],
                ['Avg entropy','78 bits',D.cyan],['Crackable in 24h','2 passwords',D.red],
              ].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:10, color:c, fontWeight:700 }}>{v}</span>
                </div>
              ))}
              <button style={{ marginTop:8, width:'100%', padding:'8px', borderRadius:6, border:`1px solid ${D.purple}44`, background:'rgba(191,95,255,0.08)', color:D.purple, fontSize:11, fontWeight:700, cursor:'pointer' }}>Run Crack Simulation</button>
            </GlowCard>

            <GlowCard color={D.blue} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🔌 API Security Assessment</div>
              {[
                ['Endpoints Scanned','42',D.cyan],['Auth Issues','3',D.red],['Data Leakage','2 endpoints',D.orange],
                ['Rate Limiting','12 missing',D.orange],['TLS Version','All TLS 1.3',D.green],['Sensitive Fields Exposed','5',D.red],
              ].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:10, color:c, fontWeight:700 }}>{v}</span>
                </div>
              ))}
              <button style={{ marginTop:8, width:'100%', padding:'8px', borderRadius:6, border:`1px solid ${D.blue}44`, background:'rgba(26,122,255,0.08)', color:D.blue, fontSize:11, fontWeight:700, cursor:'pointer' }}>Full API Audit</button>
            </GlowCard>

            <GlowCard color={D.gold} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>📱 Social Media Insights</div>
              {[
                ['Brand mentions','284 scanned',D.cyan],['Leaked employee data','3 posts',D.red],
                ['Credential hints','1 detected',D.orange],['Phishing impersonation','2 accounts',D.red],
                ['Social engineering risk','Medium',D.orange],['Executive exposure','High',D.red],
              ].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:10, color:c, fontWeight:700 }}>{v}</span>
                </div>
              ))}
            </GlowCard>
          </div>

          <GlowCard color={D.cyan} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🕐 Incident Timeline Reconstruction</div>
            <div style={{ position:'relative', paddingLeft:24 }}>
              {[
                ['08:01:12','Initial access via browser exploit kit — CVE-2026-0089',D.red,'critical'],
                ['08:03:44','Privilege escalation — LSASS memory dump (PID 788)',D.orange,'high'],
                ['08:07:29','Lateral movement — SMB share enumeration (192.168.1.x)',D.orange,'high'],
                ['08:12:05','Rootkit installed in kernel — Phantom.Rootkit.X9 dropper',D.red,'critical'],
                ['08:18:33','Ransomware payload deployed — encryption initiated on D:\\',D.red,'critical'],
                ['08:22:47','LeoNet detected anomaly — automated isolation triggered',D.cyan,'info'],
                ['08:23:01','Threat quarantined — rollback to shadow copy initiated',D.green,'resolved'],
              ].map(([t,e,c,sev],i)=>(
                <div key={i} style={{ display:'flex', gap:16, marginBottom:16, position:'relative' }}>
                  <div style={{ position:'absolute', left:-20, top:6, width:10, height:10, borderRadius:'50%', background:c, boxShadow:`0 0 8px ${c}`, flexShrink:0 }} />
                  {i < 6 && <div style={{ position:'absolute', left:-16, top:16, width:2, height:'calc(100% + 4px)', background:`${c}44` }} />}
                  <div style={{ fontFamily:'monospace', fontSize:10, color:D.muted, flexShrink:0, paddingTop:4, minWidth:70 }}>{t}</div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:12, color:D.text, fontWeight:600 }}>{e}</div>
                    <span style={{ fontSize:9, color:c, fontWeight:800, textTransform:'uppercase', letterSpacing:1 }}>{sev}</span>
                  </div>
                </div>
              ))}
            </div>
            <button style={{ marginTop:8, padding:'9px 20px', borderRadius:8, border:`1px solid ${D.cyan}44`, background:'rgba(0,212,255,0.08)', color:D.cyan, fontWeight:700, fontSize:12, cursor:'pointer' }}>📥 Export Timeline Report</button>
          </GlowCard>
        </div>
      );

      // ── RISK & ANALYSIS ────────────────────────────────────────────────────
      case 'risk': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>📊 Risk & Analysis</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Risk assessment · Data classification · User access · Root cause · Historical trends · IDS · Log management</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(165px,1fr))', gap:12, marginBottom:20 }}>
            {[['Overall Risk Score','74 / 100',D.orange],['Critical Assets','12',D.red],['IDS Alerts Today','38',D.orange],['Log Events','847,293',D.cyan],['Data Classes Found','6',D.blue],['Anomalies Detected','14',D.purple]].map(([l,v,c])=>(
              <GlowCard key={l} color={c} style={{ padding:'14px 18px' }}>
                <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>{l}</div>
                <div style={{ fontSize:20, fontWeight:900, color:c, fontFamily:'monospace' }}>{v}</div>
              </GlowCard>
            ))}
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.red} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>⚖️ Risk Assessment Matrix</div>
              {[
                ['UEFI Firmware Attack','Critical','Very High','98'],
                ['Ransomware Spread','Critical','High','94'],
                ['Supply Chain Compromise','High','High','81'],
                ['Credential Theft','High','Medium','76'],
                ['IoT Botnet Expansion','Medium','High','68'],
                ['Insider Data Exfil','Medium','Medium','55'],
                ['DDoS Disruption','Low','High','42'],
                ['Phishing Campaign','Low','Very High','39'],
              ].map(([threat,sev,prob,score])=>(
                <div key={threat} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 12px', background:'#081420', borderRadius:8, marginBottom:6, border:`1px solid ${sevColor(sev.toLowerCase())}22` }}>
                  <div>
                    <div style={{ fontSize:11, color:D.text, fontWeight:600 }}>{threat}</div>
                    <div style={{ fontSize:9, color:D.muted, marginTop:2 }}>Severity: {sev} · Probability: {prob}</div>
                  </div>
                  <div style={{ fontSize:16, fontWeight:900, color:sevColor(sev.toLowerCase()), fontFamily:'monospace' }}>{score}</div>
                </div>
              ))}
            </GlowCard>

            <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <GlowCard color={D.cyan} style={{ padding:22 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🗂️ Data Classification</div>
                {[
                  ['PII / Personal Data','2,847 files',D.red,'Critical'],
                  ['Financial Records','891 files',D.orange,'Confidential'],
                  ['Health Records (PHI)','234 files',D.red,'Critical'],
                  ['Intellectual Property','1,204 files',D.orange,'Confidential'],
                  ['Internal Communications','8,491 files',D.cyan,'Internal'],
                  ['Public Data','14,302 files',D.green,'Public'],
                ].map(([cls,cnt,c,label])=>(
                  <div key={cls} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8, padding:'7px 10px', background:'#081420', borderRadius:6 }}>
                    <div>
                      <div style={{ fontSize:11, color:D.text, fontWeight:600 }}>{cls}</div>
                      <div style={{ fontSize:9, color:D.muted }}>{cnt}</div>
                    </div>
                    <span style={{ fontSize:9, fontWeight:800, color:c, background:`${c}15`, border:`1px solid ${c}33`, borderRadius:10, padding:'2px 8px', textTransform:'uppercase' }}>{label}</span>
                  </div>
                ))}
              </GlowCard>

              <GlowCard color={D.purple} style={{ padding:22 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>👤 User Access Analysis</div>
                {[
                  ['Over-privileged accounts','7',D.red],['Dormant accounts','12',D.orange],
                  ['Shared credentials','3',D.red],['Admin without MFA','0',D.green],
                  ['Accounts reviewed (30d)','89%',D.cyan],['Zero-trust violations','2',D.orange],
                ].map(([k,v,c])=>(
                  <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                    <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                    <span style={{ fontSize:11, color:c, fontWeight:800 }}>{v}</span>
                  </div>
                ))}
                <button style={{ marginTop:8, width:'100%', padding:'8px', borderRadius:6, border:`1px solid ${D.purple}44`, background:'rgba(191,95,255,0.08)', color:D.purple, fontSize:11, fontWeight:700, cursor:'pointer' }}>Review All Accounts</button>
              </GlowCard>
            </div>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.orange} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔍 Root Cause Analysis</div>
              <div style={{ padding:'14px 16px', background:'rgba(255,107,53,0.08)', border:`1px solid ${D.orange}33`, borderRadius:10, marginBottom:14 }}>
                <div style={{ fontSize:11, fontWeight:700, color:D.orange, marginBottom:4 }}>Incident #INC-2026-0041</div>
                <div style={{ fontSize:12, color:D.text, fontWeight:700, marginBottom:8 }}>Phantom.Rootkit.X9 Infection Chain</div>
                {['1. User clicked phishing link → browser exploit triggered','2. Sandbox escape via CVE-2026-0089 → code execution','3. LSASS dumped → admin credentials stolen','4. Lateral movement across subnet 192.168.1.0/24','5. Rootkit dropped in kernel driver → persistence','Root Cause: Unpatched browser + missing EDR on endpoint'].map((s,i)=>(
                  <div key={i} style={{ fontSize:11, color: i===5?D.orange:D.muted, marginBottom:5, paddingLeft:i===5?0:8, fontWeight:i===5?700:400 }}>{s}</div>
                ))}
              </div>
              <button style={{ padding:'9px 20px', borderRadius:8, border:'none', background:`linear-gradient(135deg,${D.orange},${D.red})`, color:'#fff', fontWeight:800, fontSize:12, cursor:'pointer' }}>Run AI Root Cause Analysis</button>
            </GlowCard>

            <GlowCard color={D.gold} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📈 Historical Threat Trends</div>
              {[
                ['Jan 2026','Ransomware',142],['Feb 2026','Phishing',287],
                ['Mar 2026','Rootkit',89],['Apr 2026','Zero-Day',34],
                ['May 2026','Ransomware',198],
              ].map(({} = {}, i, arr) => null).filter(Boolean)}
              {[
                {month:'Jan',count:142,type:'Ransomware'},
                {month:'Feb',count:287,type:'Phishing'},
                {month:'Mar',count:89,type:'Rootkit'},
                {month:'Apr',count:34,type:'Zero-Day'},
                {month:'May',count:198,type:'Ransomware (↑119%)'},
              ].map(r => (
                <div key={r.month} style={{ display:'flex', gap:12, alignItems:'center', marginBottom:10 }}>
                  <div style={{ width:32, fontSize:10, color:D.muted }}>{r.month}</div>
                  <div style={{ flex:1, height:8, background:D.border, borderRadius:4, overflow:'hidden' }}>
                    <div style={{ height:'100%', width:`${(r.count/287)*100}%`, background:`linear-gradient(90deg,${D.gold}88,${D.gold})`, borderRadius:4 }} />
                  </div>
                  <div style={{ width:50, fontSize:10, color:D.gold, fontFamily:'monospace', fontWeight:700 }}>{r.count}</div>
                  <div style={{ fontSize:10, color:D.muted, width:120 }}>{r.type}</div>
                </div>
              ))}
              <div style={{ marginTop:14, padding:'10px 14px', background:'rgba(255,215,0,0.06)', border:`1px solid ${D.gold}33`, borderRadius:8, fontSize:11, color:D.gold }}>
                AI Pattern: Ransomware resurgence predicted in Q3 2026 — confidence 87%
              </div>
            </GlowCard>
          </div>

          <GlowCard color={D.blue} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📋 Intrusion Detection System — Live Alerts</div>
            <div style={{ overflowX:'auto' }}>
              <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
                <thead><tr style={{ background:'#061428' }}>{['Time','Rule','Source IP','Destination','Protocol','Signature','Severity','Action'].map(h=>(
                  <th key={h} style={{ padding:'8px 12px', textAlign:'left', color:D.muted, fontSize:10, fontWeight:700, textTransform:'uppercase', letterSpacing:1, borderBottom:`1px solid ${D.border}` }}>{h}</th>
                ))}</tr></thead>
                <tbody>{[
                  {t:'08:34:22',rule:'ET-TOR-001',src:'185.220.101.42',dst:'192.168.1.100',proto:'TCP',sig:'TOR Exit Node C2 Beacon',sev:'critical'},
                  {t:'08:32:11',rule:'ET-BRUTE-009',src:'91.108.4.200',dst:'192.168.1.100',proto:'SSH',sig:'SSH Brute Force > 100 attempts',sev:'high'},
                  {t:'08:28:44',rule:'ET-SQL-003',src:'192.168.1.44',dst:'10.0.0.5',proto:'HTTP',sig:'SQL Injection Attempt UNION SELECT',sev:'high'},
                  {t:'08:21:00',rule:'ET-SCAN-007',src:'45.33.32.156',dst:'192.168.1.0/24',proto:'TCP',sig:'Nmap Port Scan Detected',sev:'medium'},
                  {t:'08:14:33',rule:'ET-MALWARE-012',src:'192.168.1.55',dst:'185.220.101.1',proto:'HTTPS',sig:'Emotet C2 Check-In Pattern',sev:'critical'},
                ].map((r,i)=>(
                  <tr key={i} style={{ background:i%2===0?'#081420':'#0A1828', borderBottom:`1px solid ${D.border2}` }}>
                    <td style={{ padding:'8px 12px', fontFamily:'monospace', color:D.muted, fontSize:10 }}>{r.t}</td>
                    <td style={{ padding:'8px 12px', color:D.cyan, fontFamily:'monospace', fontSize:10, fontWeight:700 }}>{r.rule}</td>
                    <td style={{ padding:'8px 12px', color:D.text, fontFamily:'monospace', fontSize:10 }}>{r.src}</td>
                    <td style={{ padding:'8px 12px', color:D.text, fontFamily:'monospace', fontSize:10 }}>{r.dst}</td>
                    <td style={{ padding:'8px 12px', color:D.muted }}>{r.proto}</td>
                    <td style={{ padding:'8px 12px', color:D.text }}>{r.sig}</td>
                    <td style={{ padding:'8px 12px' }}><span style={{ color:sevColor(r.sev), fontWeight:800, fontSize:10, textTransform:'uppercase' }}>{r.sev}</span></td>
                    <td style={{ padding:'8px 12px' }}><button style={{ background:D.red, color:'#fff', border:'none', borderRadius:4, padding:'3px 10px', fontSize:10, fontWeight:800, cursor:'pointer' }}>Block</button></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </GlowCard>
        </div>
      );

      // ── RECOMMENDATIONS ────────────────────────────────────────────────────
      case 'recommendations': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>💡 Recommendations Center</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Patches · Policy · Hardening · Playbooks · Whitelisting · Insider threat · Hardware · Backup</p>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.red} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔧 Patch Management</div>
              {[
                {pkg:'Chrome 123.0.6312.58',cve:'CVE-2026-0089',sev:'critical',days:3},
                {pkg:'Windows Kernel 22H2',cve:'CVE-2026-0041',sev:'critical',days:7},
                {pkg:'OpenSSL 3.2.1',cve:'CVE-2026-0102',sev:'high',days:12},
                {pkg:'Apache 2.4.57',cve:'CVE-2026-0055',sev:'high',days:14},
                {pkg:'Node.js 20.11.0',cve:'CVE-2026-0117',sev:'medium',days:21},
              ].map(p=>(
                <div key={p.pkg} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 14px', background:'#081420', borderRadius:8, marginBottom:8, border:`1px solid ${sevColor(p.sev)}22` }}>
                  <div>
                    <div style={{ fontSize:12, color:D.text, fontWeight:700 }}>{p.pkg}</div>
                    <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{p.cve} · {p.days} days overdue</div>
                  </div>
                  <button style={{ background:`linear-gradient(135deg,${D.blue},${D.cyan})`, color:'#fff', border:'none', borderRadius:6, padding:'5px 12px', fontSize:10, fontWeight:800, cursor:'pointer' }}>Auto-Patch</button>
                </div>
              ))}
              <button style={{ marginTop:4, width:'100%', padding:'10px', borderRadius:8, border:'none', background:`linear-gradient(135deg,${D.red},${D.orange})`, color:'#fff', fontWeight:800, fontSize:12, cursor:'pointer' }}>⚡ Patch All Critical Now</button>
            </GlowCard>

            <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
              <GlowCard color={D.cyan} style={{ padding:22 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🔒 Configuration Hardening</div>
                {[
                  ['Disable legacy SMBv1','Critical — apply now',D.red],
                  ['Enable Kernel Guard','High — apply now',D.orange],
                  ['Restrict PowerShell execution','High',D.orange],
                  ['Enable Windows Defender ASR','Medium',D.cyan],
                  ['Disable AutoRun','Medium',D.cyan],
                  ['Enable LAPS for local admin','High',D.orange],
                ].map(([rule,note,c])=>(
                  <div key={rule} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8, padding:'7px 10px', background:'#081420', borderRadius:6 }}>
                    <div>
                      <div style={{ fontSize:11, color:D.text }}>{rule}</div>
                      <div style={{ fontSize:9, color:c, marginTop:2 }}>{note}</div>
                    </div>
                    <button style={{ background:'none', border:`1px solid ${c}44`, borderRadius:4, color:c, padding:'3px 10px', fontSize:9, fontWeight:800, cursor:'pointer' }}>Apply</button>
                  </div>
                ))}
              </GlowCard>

              <GlowCard color={D.green} style={{ padding:22 }}>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>✅ Application Whitelisting</div>
                <div style={{ fontSize:11, color:D.muted, marginBottom:12 }}>Only approved apps can execute — all others blocked</div>
                {[['Approved Apps','247',D.green],['Blocked Today','34',D.red],['Pending Review','8',D.orange],['Last Updated','10 min ago',D.cyan]].map(([k,v,c])=>(
                  <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                    <span style={{ fontSize:11, color:D.muted }}>{k}</span>
                    <span style={{ fontSize:11, color:c, fontWeight:800 }}>{v}</span>
                  </div>
                ))}
                <button style={{ marginTop:8, width:'100%', padding:'8px', borderRadius:6, border:`1px solid ${D.green}44`, background:'rgba(0,255,136,0.08)', color:D.green, fontSize:11, fontWeight:700, cursor:'pointer' }}>Manage Whitelist</button>
              </GlowCard>
            </div>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.orange} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🕵️ Insider Threat Mitigation</div>
              {[
                ['User Entity Behavior Analytics','Active'],['Privileged Activity Monitoring','Active'],
                ['Data Loss Prevention (DLP)','Active'],['USB Block Policy','Enforced'],
                ['Print Screen Restriction','Enabled'],['Email DLP Scanning','Active'],
              ].map(([k,v])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8, padding:'6px 8px', background:'#081420', borderRadius:6 }}>
                  <span style={{ fontSize:10, color:D.text }}>{k}</span>
                  <span style={{ fontSize:10, color:D.green, fontWeight:700 }}>{v}</span>
                </div>
              ))}
            </GlowCard>

            <GlowCard color={D.blue} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>🖥️ Hardware Recommendations</div>
              {[
                ['TPM 2.0 Module','Required on 3 hosts',D.orange],
                ['HSM for key storage','Strongly advised',D.orange],
                ['NIC with DPDK','For IDS performance',D.cyan],
                ['Encrypted SSD','2 unencrypted drives',D.red],
                ['BIOS/UEFI Update','4 hosts outdated',D.orange],
              ].map(([k,v,c])=>(
                <div key={k} style={{ marginBottom:8 }}>
                  <div style={{ fontSize:11, color:D.text }}>{k}</div>
                  <div style={{ fontSize:10, color:c }}>{v}</div>
                </div>
              ))}
            </GlowCard>

            <GlowCard color={D.purple} style={{ padding:22 }}>
              <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:14 }}>💾 Backup Recommendations</div>
              {[
                ['3-2-1 Rule','✓ Configured',D.green],['Offsite Backup','AWS S3 + Azure',D.green],
                ['Last Backup','2026-05-16 02:00',D.cyan],['Recovery Tested','2026-05-10',D.cyan],
                ['Immutable Copies','Enabled',D.green],['Blockchain Verification','Active',D.green],
                ['RTO Target','< 4 minutes',D.gold],
              ].map(([k,v,c])=>(
                <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:10, color:D.muted }}>{k}</span>
                  <span style={{ fontSize:10, color:c, fontWeight:700 }}>{v}</span>
                </div>
              ))}
            </GlowCard>
          </div>

          <GlowCard color={D.gold} style={{ padding:24 }}>
            <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📖 Incident Response Playbooks</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))', gap:14 }}>
              {[
                {name:'Ransomware Response',steps:8,status:'active',time:'< 15 min',icon:'🔐'},
                {name:'Data Breach Protocol',steps:12,status:'active',time:'< 30 min',icon:'🚨'},
                {name:'DDoS Mitigation',steps:6,status:'active',time:'< 5 min',icon:'🌊'},
                {name:'Insider Threat',steps:10,status:'active',time:'< 20 min',icon:'🕵️'},
                {name:'Zero-Day Response',steps:9,status:'draft',time:'< 45 min',icon:'⚡'},
                {name:'Supply Chain Attack',steps:14,status:'draft',time:'< 60 min',icon:'🔗'},
              ].map(p=>(
                <div key={p.name} style={{ background:'#081420', border:`1px solid ${p.status==='active'?D.gold:D.border}33`, borderRadius:12, padding:'16px' }}>
                  <div style={{ fontSize:22, marginBottom:8 }}>{p.icon}</div>
                  <div style={{ fontSize:12, fontWeight:700, color:D.text, marginBottom:4 }}>{p.name}</div>
                  <div style={{ fontSize:10, color:D.muted, marginBottom:8 }}>{p.steps} steps · Response: {p.time}</div>
                  <span style={{ fontSize:9, fontWeight:800, color:p.status==='active'?D.green:D.orange, background:`${p.status==='active'?D.green:D.orange}15`, border:`1px solid ${p.status==='active'?D.green:D.orange}33`, borderRadius:10, padding:'2px 8px', textTransform:'uppercase' }}>{p.status}</span>
                </div>
              ))}
            </div>
          </GlowCard>
        </div>
      );

      // ── DARK WEB ───────────────────────────────────────────────────────────
      case 'darkweb': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>🌑 Dark Web Intelligence</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Dark web monitoring · Geolocation security · API data exposure · Third-party assessments · Strategic partnerships</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(165px,1fr))', gap:12, marginBottom:20 }}>
            {[['Dark Web Mentions','7',D.red],['Leaked Credentials','3 found',D.red],['Active Marketplaces','4 monitored',D.orange],['Threat Actors Tracked','18',D.purple],['Forums Indexed','142',D.cyan],['Last Crawl','08:41:00',D.gold]].map(([l,v,c])=>(
              <GlowCard key={l} color={c} style={{ padding:'14px 18px' }}>
                <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>{l}</div>
                <div style={{ fontSize:18, fontWeight:900, color:c, fontFamily:'monospace' }}>{v}</div>
              </GlowCard>
            ))}
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.red} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🌑 Dark Web Findings</div>
              {[
                {type:'Credential Dump',detail:'3 employee emails + hashed passwords found on BreachForums',sev:'critical',date:'2026-05-15'},
                {type:'Internal Doc Leak',detail:'Company network diagram shared on RaidForums',sev:'critical',date:'2026-05-12'},
                {type:'Ransomware Listing',detail:'Specter group claims to have 40GB of financial data',sev:'high',date:'2026-05-10'},
                {type:'Phishing Kit Sale',detail:'Custom phishing kit targeting your login portal',sev:'high',date:'2026-05-08'},
              ].map((f,i)=>(
                <div key={i} style={{ padding:'12px 14px', background:'#081420', borderRadius:10, marginBottom:10, borderLeft:`3px solid ${sevColor(f.sev)}` }}>
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                    <span style={{ fontSize:12, fontWeight:800, color:D.text }}>{f.type}</span>
                    <span style={{ fontSize:9, color:sevColor(f.sev), fontWeight:800, textTransform:'uppercase' }}>{f.sev}</span>
                  </div>
                  <div style={{ fontSize:11, color:D.muted, lineHeight:1.5 }}>{f.detail}</div>
                  <div style={{ fontSize:9, color:D.muted, marginTop:4 }}>{f.date}</div>
                </div>
              ))}
            </GlowCard>

            <GlowCard color={D.cyan} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🗺️ Geolocation Security</div>
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:11, color:D.muted, marginBottom:10 }}>Login anomalies detected by geolocation analysis</div>
                {[
                  ['Admin login — Moscow, Russia','Blocked — not whitelisted',D.red],
                  ['VPN from Tor exit node — Tokyo','Blocked — policy violation',D.red],
                  ['Normal login — Freetown, SL','Allowed',D.green],
                  ['Login from new country — Brazil','Alert sent · Monitoring',D.orange],
                ].map(([ev,act,c])=>(
                  <div key={ev} style={{ padding:'8px 12px', background:'#081420', borderRadius:8, marginBottom:6 }}>
                    <div style={{ fontSize:11, color:D.text }}>{ev}</div>
                    <div style={{ fontSize:10, color:c, marginTop:2, fontWeight:700 }}>{act}</div>
                  </div>
                ))}
              </div>
              <div style={{ padding:'12px 14px', background:'rgba(0,212,255,0.06)', border:`1px solid ${D.cyan}33`, borderRadius:8, fontSize:11, color:D.cyan }}>
                <div style={{ fontWeight:700, marginBottom:4 }}>Geo-Fencing Rules Active</div>
                <div style={{ color:D.muted }}>Admin access allowed from: SL, UK, US only · Alerts for all other regions</div>
              </div>
            </GlowCard>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18 }}>
            <GlowCard color={D.purple} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🔌 API Data Exposure Analysis</div>
              {[
                {endpoint:'/api/v1/users',exposure:'SSN, email, DOB returned unmasked',risk:'critical'},
                {endpoint:'/api/v2/reports',exposure:'Internal IP addresses in response',risk:'high'},
                {endpoint:'/api/v1/auth/token',exposure:'Token not expiring correctly',risk:'high'},
                {endpoint:'/api/v3/health',exposure:'Stack traces in error responses',risk:'medium'},
                {endpoint:'/api/v1/payments',exposure:'✓ Fully masked — PCI compliant',risk:'safe'},
              ].map(a=>(
                <div key={a.endpoint} style={{ padding:'9px 12px', background:'#081420', borderRadius:8, marginBottom:8, borderLeft:`3px solid ${sevColor(a.risk)}` }}>
                  <div style={{ fontFamily:'monospace', fontSize:11, color:D.cyan, fontWeight:700 }}>{a.endpoint}</div>
                  <div style={{ fontSize:10, color:D.muted, marginTop:3 }}>{a.exposure}</div>
                </div>
              ))}
            </GlowCard>

            <GlowCard color={D.gold} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🤝 Strategic Partnerships</div>
              {[
                {name:'FS-ISAC',desc:'Financial Services threat sharing consortium',status:'Active member',icon:'🏦'},
                {name:'MITRE ATT&CK',desc:'TTPs database · 600+ technique coverage',status:'Integrated',icon:'🗡️'},
                {name:'CISA KEV',desc:'Known Exploited Vulnerabilities feed',status:'Live sync',icon:'🏛️'},
                {name:'VT Enterprise',desc:'VirusTotal private intelligence feed',status:'Active',icon:'🔬'},
                {name:'Shodan Monitor',desc:'Internet-facing asset monitoring',status:'Active',icon:'🌐'},
              ].map(p=>(
                <div key={p.name} style={{ display:'flex', gap:12, alignItems:'center', padding:'10px 0', borderBottom:`1px solid ${D.border2}` }}>
                  <span style={{ fontSize:22 }}>{p.icon}</span>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:12, fontWeight:700, color:D.text }}>{p.name}</div>
                    <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{p.desc}</div>
                  </div>
                  <span style={{ fontSize:9, color:D.green, fontWeight:800 }}>{p.status}</span>
                </div>
              ))}
            </GlowCard>
          </div>
        </div>
      );

      // ── REPORTS ────────────────────────────────────────────────────────────
      case 'reports': return (
        <div style={{ animation:'fade-in 0.3s ease' }}>
          <h2 style={{ fontSize:20, fontWeight:900, color:D.white, marginBottom:4 }}>📋 Reports Center</h2>
          <p style={{ fontSize:12, color:D.muted, marginBottom:20 }}>Executive summaries · Incident templates · Compliance reports · Scheduled · Real-time · Collaborative · Audit trail</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))', gap:14, marginBottom:22 }}>
            {[
              {icon:'📊',label:'Executive Summary',desc:'Board-level threat overview',color:D.gold},
              {icon:'🚨',label:'Incident Report',desc:'Full incident documentation',color:D.red},
              {icon:'🛡️',label:'Compliance Report',desc:'GDPR/HIPAA/DoD audit-ready',color:D.green},
              {icon:'📡',label:'Threat Intel Report',desc:'IOC, TTPs, attribution',color:D.cyan},
              {icon:'🌿',label:'Environmental Impact',desc:'Carbon footprint of security ops',color:D.green},
              {icon:'🤖',label:'AI Post-Incident',desc:'ML analysis of response quality',color:D.purple},
            ].map(r=>(
              <GlowCard key={r.label} color={r.color} style={{ padding:20, cursor:'pointer' }}
                onClick={()=>showToast(`📄 Generating ${r.label}…`, r.color)}>
                <div style={{ fontSize:28, marginBottom:10 }}>{r.icon}</div>
                <div style={{ fontSize:12, fontWeight:800, color:D.white, marginBottom:4 }}>{r.label}</div>
                <div style={{ fontSize:10, color:D.muted, marginBottom:14 }}>{r.desc}</div>
                <div style={{ fontSize:10, fontWeight:700, color:r.color }}>Generate →</div>
              </GlowCard>
            ))}
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18, marginBottom:18 }}>
            <GlowCard color={D.gold} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📊 Executive Summary Preview</div>
              <div style={{ background:`linear-gradient(135deg,#0A2040,#061428)`, borderRadius:12, padding:20, marginBottom:14 }}>
                <div style={{ fontSize:10, color:D.muted, textTransform:'uppercase', letterSpacing:2, marginBottom:8 }}>LeoNet Defense · Board Report</div>
                <div style={{ fontSize:16, fontWeight:900, color:D.white, marginBottom:4 }}>Cybersecurity Status — May 2026</div>
                <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:10, marginTop:14 }}>
                  {[['Threat Index','74/100','High'],['Incidents','3 critical','Resolved'],['Uptime','99.999%','On target']].map(([k,v,s])=>(
                    <div key={k} style={{ background:'rgba(255,255,255,0.04)', borderRadius:8, padding:10, textAlign:'center' }}>
                      <div style={{ fontSize:9, color:D.muted, marginBottom:4 }}>{k}</div>
                      <div style={{ fontSize:14, fontWeight:900, color:D.gold }}>{v}</div>
                      <div style={{ fontSize:9, color:D.muted, marginTop:2 }}>{s}</div>
                    </div>
                  ))}
                </div>
              </div>
              <button onClick={()=>showToast('📊 Executive summary PDF generated.',D.gold)} style={{ width:'100%', padding:'10px', borderRadius:8, border:'none', background:`linear-gradient(135deg,${D.gold},${D.orange})`, color:'#000', fontWeight:800, fontSize:12, cursor:'pointer' }}>Download PDF</button>
            </GlowCard>

            <GlowCard color={D.red} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>📝 Incident Report Templates</div>
              {[
                {name:'Ransomware Incident Report',fields:18,standard:'NIST SP 800-61'},
                {name:'Data Breach Notification',fields:24,standard:'GDPR Art. 33'},
                {name:'Zero-Day Exploitation Report',fields:15,standard:'CVE/NVD'},
                {name:'Insider Threat Report',fields:22,standard:'ISO 27035'},
                {name:'DDoS Attack Report',fields:12,standard:'ENISA'},
              ].map(t=>(
                <div key={t.name} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'9px 12px', background:'#081420', borderRadius:8, marginBottom:8 }}>
                  <div>
                    <div style={{ fontSize:11, color:D.text, fontWeight:700 }}>{t.name}</div>
                    <div style={{ fontSize:9, color:D.muted, marginTop:2 }}>{t.fields} fields · {t.standard}</div>
                  </div>
                  <button onClick={()=>showToast(`📝 Opening ${t.name} template…`,D.cyan)} style={{ background:'none', border:`1px solid ${D.cyan}44`, borderRadius:4, color:D.cyan, padding:'4px 10px', fontSize:10, fontWeight:700, cursor:'pointer' }}>Use</button>
                </div>
              ))}
            </GlowCard>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:18 }}>
            <GlowCard color={D.purple} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>👥 Collaborative Reporting</div>
              <div style={{ fontSize:11, color:D.muted, marginBottom:14 }}>Team members actively working on reports</div>
              {[
                {user:'Director Chen',role:'CISO',action:'Reviewing Executive Summary',time:'2 min ago',avatar:'👩‍💼'},
                {user:'Analyst Koroma',role:'SOC L2',action:'Building Incident Report #041',time:'8 min ago',avatar:'👨‍💻'},
                {user:'Eng. Diallo',role:'Network',action:'Adding forensics to Net Report',time:'14 min ago',avatar:'👨‍🔬'},
              ].map(u=>(
                <div key={u.user} style={{ display:'flex', gap:12, padding:'10px 12px', background:'#081420', borderRadius:10, marginBottom:8, border:`1px solid ${D.purple}22` }}>
                  <div style={{ width:36, height:36, borderRadius:'50%', background:`linear-gradient(135deg,${D.purple},${D.blue})`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:18, flexShrink:0 }}>{u.avatar}</div>
                  <div>
                    <div style={{ fontSize:12, fontWeight:700, color:D.white }}>{u.user} <span style={{ fontWeight:400, color:D.muted }}>· {u.role}</span></div>
                    <div style={{ fontSize:10, color:D.muted, marginTop:2 }}>{u.action}</div>
                    <div style={{ fontSize:9, color:D.muted, marginTop:2 }}>{u.time}</div>
                  </div>
                </div>
              ))}
            </GlowCard>

            <GlowCard color={D.green} style={{ padding:24 }}>
              <div style={{ fontSize:13, fontWeight:800, color:D.white, marginBottom:16 }}>🕐 Scheduled Reports</div>
              {[
                {name:'Daily Threat Summary',schedule:'Every day 06:00',recipients:'SOC Team',format:'PDF + Email'},
                {name:'Weekly Executive Brief',schedule:'Every Monday 08:00',recipients:'Board',format:'PDF'},
                {name:'Monthly Compliance',schedule:'1st of month',recipients:'Legal, CISO',format:'PDF + CSV'},
                {name:'Real-Time Incident',schedule:'On incident trigger',recipients:'All SOC',format:'Push + Email'},
                {name:'Environmental Impact',schedule:'Quarterly',recipients:'Sustainability',format:'PDF'},
              ].map(r=>(
                <div key={r.name} style={{ padding:'9px 12px', background:'#081420', borderRadius:8, marginBottom:8 }}>
                  <div style={{ fontSize:11, color:D.white, fontWeight:700 }}>{r.name}</div>
                  <div style={{ fontSize:9, color:D.muted, marginTop:3 }}>{r.schedule} · To: {r.recipients} · {r.format}</div>
                </div>
              ))}
              <button onClick={()=>showToast('⏰ Report schedule saved.',D.green)} style={{ marginTop:8, width:'100%', padding:'9px', borderRadius:8, border:`1px solid ${D.green}44`, background:'rgba(0,255,136,0.08)', color:D.green, fontWeight:700, fontSize:12, cursor:'pointer' }}>+ Add Schedule</button>
            </GlowCard>
          </div>
        </div>
      );

      default: return (
        <div style={{ textAlign:'center', padding:80, color:D.muted }}>
          <div style={{ fontSize:48, marginBottom:16 }}>🦁</div>
          <div style={{ fontSize:16, fontWeight:700 }}>LeoNet Defense</div>
          <div style={{ fontSize:12, marginTop:4 }}>Select a module from the navigation</div>
        </div>
      );
    }
  };

  return (
    <div style={{ display:'flex', flexDirection:'column', minHeight:'100vh', background:D.bg }}>
      <Toast />
      <Sidebar />
      <TopBar />

      {/* Desktop nav tabs */}
      <div style={{ background:D.surface, borderBottom:`1px solid ${D.border}`, padding:'0 20px', display:'flex', gap:2, overflowX:'auto' }}>
        {NAV.map(n => (
          <button key={n.id} onClick={()=>setView(n.id)} style={{ padding:'10px 16px', background:'none', border:'none', borderBottom: view===n.id?`2px solid ${D.cyan}`:'2px solid transparent', color: view===n.id?D.white:D.muted, cursor:'pointer', fontSize:12, fontWeight: view===n.id?700:400, whiteSpace:'nowrap', transition:'color 0.15s', flexShrink:0 }}>
            {n.icon} {n.label}
          </button>
        ))}
      </div>

      <div style={{ flex:1, padding:'24px 20px 80px', maxWidth:1400, margin:'0 auto', width:'100%' }}>
        {renderView()}
      </div>

      <BottomTabs />

      {/* Matrix rain background effect (subtle) */}
      <div style={{ position:'fixed', inset:0, pointerEvents:'none', zIndex:-1, overflow:'hidden', opacity:0.03 }}>
        {Array.from({length:20}).map((_,i) => (
          <div key={i} style={{ position:'absolute', top:0, left:`${i*5}%`, color:D.green, fontFamily:'monospace', fontSize:14, lineHeight:1.5, animation:`matrix-fall ${4+i*0.3}s linear ${i*0.2}s infinite`, userSelect:'none' }}>
            {Array.from({length:30}).map((_,j) => String.fromCharCode(0x30A0+Math.floor(Math.random()*96))).join('\n')}
          </div>
        ))}
      </div>
    </div>
  );
}
