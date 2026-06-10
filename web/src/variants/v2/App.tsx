/**
 * Variant 2: Hacker Terminal / Matrix Operator
 * Terminal layout shell with command-menu sidebar and prompt top bar.
 */
import React, { useState, useEffect } from 'react';
import { Routes, Route, NavLink, Navigate, Link } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  Radio,
  Shield,
  Search,
  Globe,
  ArrowLeft,
  Terminal,
} from 'lucide-react';
import { format } from 'date-fns';
import { mockDashboardStats } from '../../data/mockData';
import Dashboard from './pages/Dashboard';
import Connections from './pages/Connections';
import Beacons from './pages/Beacons';
import DnsThreats from './pages/DnsThreats';
import Threats from './pages/Threats';
import HuntResults from './pages/HuntResults';
import './styles.css';

const NAV_ITEMS = [
  { to: '/dev/2', icon: LayoutDashboard, label: 'sys_report', end: true },
  { to: '/dev/2/connections', icon: Network, label: 'conn_dump', end: false },
  { to: '/dev/2/beacons', icon: Radio, label: 'beacon_scan', end: false },
  { to: '/dev/2/dns', icon: Globe, label: 'dns_intel', end: false },
  { to: '/dev/2/threats', icon: Shield, label: 'threat_map', end: false },
  { to: '/dev/2/hunts', icon: Search, label: 'hunt_log', end: false },
];

const Uptime: React.FC = () => {
  const [secs, setSecs] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSecs((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return (
    <span className="v2-uptime" aria-label="Session uptime">
      uptime {String(h).padStart(2, '0')}:{String(m).padStart(2, '0')}:{String(s).padStart(2, '0')}
    </span>
  );
};

const V2App: React.FC = () => {
  const critCount = mockDashboardStats.criticalAlerts;

  return (
    <div className="v2-root v2-crt">
      {/* Sidebar */}
      <nav className="v2-sidebar" aria-label="Main navigation">
        <div className="v2-sidebar-header">
          <Terminal aria-hidden="true" />
          BRO_HUNTER
        </div>

        <div className="v2-sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `v2-nav-item${isActive ? ' active' : ''}`
              }
              aria-label={item.label}
            >
              <item.icon aria-hidden="true" />
              {item.label}
            </NavLink>
          ))}
        </div>

        <div className="v2-sidebar-footer">
          <Link to="/dev" aria-label="Back to all variants">
            <ArrowLeft size={14} aria-hidden="true" />
            exit_variant
          </Link>
        </div>
      </nav>

      {/* Top Bar */}
      <header className="v2-topbar">
        <div className="v2-prompt" aria-hidden="true">
          <span className="v2-prompt-user">root</span>
          <span className="v2-prompt-host">@vervet</span>
          <span className="v2-prompt-path">:~$</span>
          <span style={{ color: '#00FF41' }}>./bro_hunter --mode=live</span>
          <span className="v2-prompt-cursor" />
        </div>
        <div className="v2-topbar-right">
          <Uptime />
          <span className="v2-dim">{format(new Date(), 'yyyy-MM-dd')}</span>
          {critCount > 0 && (
            <span className="v2-threat-indicator" role="status" aria-label={`${critCount} critical alerts`}>
              <span className="pulse-dot" aria-hidden="true" />
              [{critCount}] CRITICAL
            </span>
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="v2-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route path="connections" element={<Connections />} />
          <Route path="beacons" element={<Beacons />} />
          <Route path="dns" element={<DnsThreats />} />
          <Route path="threats" element={<Threats />} />
          <Route path="hunts" element={<HuntResults />} />
          <Route path="*" element={<Navigate to="/dev/2" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V2App;
