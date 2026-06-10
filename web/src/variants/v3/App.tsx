/**
 * Variant 3: Corporate SOC / Enterprise SIEM
 * Professional enterprise layout with collapsible sidebar, header, breadcrumbs.
 * Splunk/Elastic-inspired clean aesthetic.
 *
 * Now the primary (and only shipped) variant. Other variants live under /dev/N for development only.
 */
import React, { useState, useEffect, useCallback } from 'react';
import { Routes, Route, NavLink, Navigate, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  Radio,
  Shield,
  Search,
  Globe,
  ListTree,
  ArrowLeft,
  ChevronRight,
  PanelLeftClose,
  PanelLeftOpen,
  Bell,
  ShieldCheck,
  Sliders,
  Link2,
  BarChart3,
  TrendingUp,
  FileText,
  Crosshair,
  FileSearch,
  Antenna,
  Upload,
  Settings as SettingsIcon,
  Binary,
  AlertOctagon,
  Server,
  Menu,
  X,
  ArrowRightLeft,
  Lock,
} from 'lucide-react';
import { format } from 'date-fns';
import Dashboard from './pages/Dashboard';
import Connections from './pages/Connections';
import Beacons from './pages/Beacons';
import DnsThreats from './pages/DnsThreats';
import Threats from './pages/Threats';
import HostRanking from './pages/HostRanking';
import HostDeepDive from './pages/HostDeepDive';
import HuntResults from './pages/HuntResults';
import Hypotheses from './pages/Hypotheses';
import TimelinePage from './pages/Timeline';
import Sessions from './pages/Sessions';
import Tuning from './pages/Tuning';
import Analytics from './pages/Analytics';
import Trends from './pages/Trends';
import Anomalies from './pages/Anomalies';
import Intel from './pages/Intel';
import Capture from './pages/Capture';
import Reports from './pages/Reports';
import Cases from './pages/Cases';
import Workflow from './pages/Workflow';
import Settings from './pages/Settings';
import Rules from './pages/Rules';
import Packets from './pages/Packets';
import TlsIntel from './pages/TlsIntel';
import Webhooks from './pages/Webhooks';
import HttpAnalysisPage from './pages/HttpAnalysisPage';
import LateralMovementPage from './pages/LateralMovementPage';
import GlobalSearch from '../../components/GlobalSearch';
import NotificationToast from '../../components/NotificationToast';
import './styles.css';

const API_BASE = import.meta.env.VITE_API_BASE || '';

interface V3AppProps {
  /** Base path prefix for routes. '/' in production, '/dev/3' in dev mode. */
  basePath?: string;
}

function buildNav(base: string) {
  const b = base === '/' ? '' : base;
  return [
    { to: base, icon: LayoutDashboard, label: 'Dashboard', end: true },
    { to: `${b}/connections`, icon: Network, label: 'Connections', end: false },
    { to: `${b}/beacons`, icon: Radio, label: 'Beacons', end: false },
    { to: `${b}/dns`, icon: Globe, label: 'DNS Threats', end: false },
    { to: `${b}/threats`, icon: Shield, label: 'Threats', end: false },
    { to: `${b}/hosts`, icon: Server, label: 'Host Ranking', end: false },
    { to: `${b}/hunts`, icon: Search, label: 'Hunt Results', end: false },
    { to: `${b}/hypotheses`, icon: FileSearch, label: 'Hypotheses', end: false },
    { to: `${b}/timeline`, icon: ListTree, label: 'Threat Timeline', end: false },
    { to: `${b}/sessions`, icon: Link2, label: 'Sessions', end: false },
    { to: `${b}/packets`, icon: Binary, label: 'Packets', end: false },
    { to: `${b}/analytics`, icon: BarChart3, label: 'Analytics', end: false },
    { to: `${b}/trends`, icon: TrendingUp, label: 'Trends', end: false },
    { to: `${b}/anomalies`, icon: AlertOctagon, label: 'Anomalies', end: false },
    { to: `${b}/intel`, icon: Crosshair, label: 'Threat Intel', end: false },
    { to: `${b}/capture`, icon: Antenna, label: 'Live Capture', end: false },
    { to: `${b}/reports`, icon: FileText, label: 'Reports', end: false },
    { to: `${b}/cases`, icon: FileText, label: 'Cases', end: false },
    { to: `${b}/workflow`, icon: Upload, label: 'PCAP Workflow', end: false },
    { to: `${b}/tuning`, icon: Sliders, label: 'Tuning', end: false },
    { to: `${b}/rules`, icon: Shield, label: 'Rules', end: false },
    { to: `${b}/tls`, icon: Lock, label: 'TLS Intel', end: false },
    { to: `${b}/http`, icon: Globe, label: 'HTTP Analysis', end: false },
    { to: `${b}/lateral`, icon: ArrowRightLeft, label: 'Lateral Movement', end: false },
    { to: `${b}/webhooks`, icon: Bell, label: 'Webhooks', end: false },
    { to: `${b}/settings`, icon: SettingsIcon, label: 'Settings', end: false },
  ];
}

function buildBreadcrumbs(base: string): Record<string, string> {
  const b = base === '/' ? '' : base;
  const map: Record<string, string> = {};
  map[base] = 'Dashboard';
  const pages = ['connections', 'beacons', 'dns', 'threats', 'hosts', 'hunts', 'hypotheses', 'timeline', 'sessions', 'packets', 'analytics', 'trends', 'anomalies', 'intel', 'capture', 'reports', 'cases', 'workflow', 'tuning', 'rules', 'tls', 'http', 'lateral', 'webhooks', 'settings'];
  const labels = ['Connections', 'Beacons', 'DNS Threats', 'Threats', 'Host Ranking', 'Hunt Results', 'Hunt Hypotheses', 'Threat Timeline', 'Sessions', 'Packets', 'Analytics', 'Trend Analysis', 'Anomalies', 'Threat Intel', 'Live Capture', 'Reports', 'Cases', 'PCAP Workflow', 'Tuning', 'Rules', 'TLS Intel', 'HTTP Analysis', 'Lateral Movement', 'Webhooks', 'Settings'];
  pages.forEach((p, i) => { map[`${b}/${p}`] = labels[i]; });
  map[`${b}/hosts`] = 'Host Ranking';
  map[`${b}/hypotheses`] = 'Hunt Hypotheses';
  return map;
}

const Clock: React.FC = () => {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="v3-header-time" aria-label="Current time">
      {format(now, 'MMM d, yyyy')} · {format(now, 'HH:mm:ss')}
    </span>
  );
};

const V3App: React.FC<V3AppProps> = ({ basePath = '/' }) => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const [critCount, setCritCount] = useState(0);

  const NAV_ITEMS = buildNav(basePath);
  const BREADCRUMB_MAP = buildBreadcrumbs(basePath);
  const [mobileNav, setMobileNav] = useState(false);
  const closeMobileNav = useCallback(() => setMobileNav(false), []);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/analytics/threat-heatmap`);
        if (!res.ok) return;
        const data = await res.json();
        const critical = (data?.heatmap || []).filter((entry: any) => (entry?.threat_score || 0) >= 0.75).length;
        setCritCount(critical);
      } catch (error) {
        console.error('Failed to fetch critical alert count', error);
      }
    })();
  }, []);

  // Close mobile nav on route change
  useEffect(() => { setMobileNav(false); }, [location.pathname]);

  const isDevMode = basePath !== '/';

  const currentPage = BREADCRUMB_MAP[location.pathname] || 'Dashboard';
  const homeLink = basePath;

  return (
    <div className={`v3-root${collapsed ? ' collapsed' : ''}`}>
      <GlobalSearch />
      <NotificationToast />
      {/* Sidebar */}
      <nav className="v3-sidebar" aria-label="Main navigation">
        <div className="v3-sidebar-brand">
          <ShieldCheck size={22} aria-hidden="true" />
          <span className="v3-sidebar-brand-text">Vervet</span>
        </div>

        <div className="v3-sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `v3-nav-item${isActive ? ' active' : ''}`
              }
              title={item.label}
              aria-label={item.label}
            >
              <item.icon size={20} aria-hidden="true" />
              <span className="v3-nav-label">{item.label}</span>
            </NavLink>
          ))}
        </div>

        <div className="v3-sidebar-footer">
          <button
            className="v3-collapse-btn"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <PanelLeftOpen size={16} aria-hidden="true" /> : <PanelLeftClose size={16} aria-hidden="true" />}
            {!collapsed && <span>Collapse</span>}
          </button>
          {isDevMode && (
            <Link to="/dev" aria-label="Back to dev variants">
              <ArrowLeft size={14} aria-hidden="true" />
              {!collapsed && <span>Dev Variants</span>}
            </Link>
          )}
        </div>
      </nav>

      {/* Mobile Nav Overlay */}
      {mobileNav && (
        <div className="v3-mobile-overlay" onClick={closeMobileNav}>
          <nav className="v3-mobile-nav" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
              <span style={{ fontWeight: 700, color: '#fff' }}>Vervet</span>
              <button onClick={closeMobileNav} style={{ background: 'none', border: 'none', color: '#888', cursor: 'pointer' }}><X size={20} /></button>
            </div>
            <div style={{ padding: '8px' }}>
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) => `v3-mobile-nav-item${isActive ? ' active' : ''}`}
                  onClick={closeMobileNav}
                >
                  <item.icon size={18} />
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          </nav>
        </div>
      )}

      {/* Header */}
      <header className="v3-header">
        <div className="v3-header-left">
          <button className="v3-mobile-menu-btn" onClick={() => setMobileNav(true)} aria-label="Open navigation">
            <Menu size={20} />
          </button>
          <nav className="v3-breadcrumb" aria-label="Breadcrumb">
            <Link to={homeLink}>SOC</Link>
            <ChevronRight size={12} className="v3-breadcrumb-sep" aria-hidden="true" />
            <span className="v3-breadcrumb-current" aria-current="page">{currentPage}</span>
          </nav>
        </div>

        <div className="v3-header-search" onClick={() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))}>
          <Search size={14} aria-hidden="true" />
          <input
            type="text"
            placeholder="Search (Ctrl+K)…"
            aria-label="Search IPs, domains, techniques"
            readOnly
            style={{ cursor: 'pointer' }}
          />
        </div>

        <div className="v3-header-right">
          <Clock />
          {isDevMode && (
            <span className="text-xs px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-mono">DEV</span>
          )}
          <div
            role="status"
            aria-label={`${critCount} critical alerts`}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 12px',
              borderRadius: 9999,
              background: critCount > 0 ? 'rgba(220, 38, 38, 0.08)' : 'rgba(22, 163, 74, 0.08)',
              color: critCount > 0 ? '#DC2626' : '#16A34A',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            <Bell size={14} aria-hidden="true" />
            {critCount} Critical
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="v3-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route path="connections" element={<Connections />} />
          <Route path="beacons" element={<Beacons />} />
          <Route path="dns" element={<DnsThreats />} />
          <Route path="threats" element={<Threats />} />
          <Route path="hosts" element={<HostRanking />} />
          <Route path="host/:ip" element={<HostDeepDive />} />
          <Route path="hunts" element={<HuntResults />} />
          <Route path="hypotheses" element={<Hypotheses />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="packets" element={<Packets />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="trends" element={<Trends />} />
          <Route path="anomalies" element={<Anomalies />} />
          <Route path="intel" element={<Intel />} />
          <Route path="capture" element={<Capture />} />
          <Route path="reports" element={<Reports />} />
          <Route path="cases" element={<Cases />} />
          <Route path="workflow" element={<Workflow />} />
          <Route path="tuning" element={<Tuning />} />
          <Route path="rules" element={<Rules />} />
          <Route path="tls" element={<TlsIntel />} />
          <Route path="webhooks" element={<Webhooks />} />
          <Route path="http" element={<HttpAnalysisPage />} />
          <Route path="lateral" element={<LateralMovementPage />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to={homeLink} replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V3App;
