/**
 * Variant 4: Cyberpunk / Neon Threat Map
 * Blade Runner meets Tron — aggressive neon, angular edges, glowing everything.
 * Full-width angular nav with clip-path, neon glow accents.
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
  Zap,
  AlertTriangle,
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
  { to: '/dev/4', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/dev/4/connections', icon: Network, label: 'Connections', end: false },
  { to: '/dev/4/beacons', icon: Radio, label: 'Beacons', end: false },
  { to: '/dev/4/dns', icon: Globe, label: 'DNS Intel', end: false },
  { to: '/dev/4/threats', icon: Shield, label: 'Threats', end: false },
  { to: '/dev/4/hunts', icon: Search, label: 'Hunt Ops', end: false },
];

const NeonClock: React.FC = () => {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="v4-nav-clock" aria-label="Current time">
      {format(now, 'HH:mm:ss')}
    </span>
  );
};

const V4App: React.FC = () => {
  const critCount = mockDashboardStats.criticalAlerts;

  return (
    <div className="v4-root">
      {/* Angular Top Nav */}
      <nav className="v4-nav" aria-label="Main navigation">
        <Link to="/dev/4" className="v4-nav-brand" aria-label="Vervet home">
          <Zap size={20} aria-hidden="true" />
          <span className="v4-nav-brand-text">Vervet</span>
        </Link>

        <div className="v4-nav-items">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `v4-nav-link${isActive ? ' active' : ''}`
              }
              aria-label={item.label}
            >
              <item.icon size={14} aria-hidden="true" />
              {item.label}
            </NavLink>
          ))}
        </div>

        <div className="v4-nav-right">
          <NeonClock />
          <div
            role="status"
            aria-label={`${critCount} critical alerts`}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 12px',
              fontFamily: "'Orbitron', sans-serif",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: '0.08em',
              textTransform: 'uppercase' as const,
              color: critCount > 0 ? '#FF00FF' : '#39FF14',
              textShadow: critCount > 0
                ? '0 0 10px rgba(255, 0, 255, 0.6)'
                : '0 0 10px rgba(57, 255, 20, 0.6)',
              background: critCount > 0
                ? 'rgba(255, 0, 255, 0.1)'
                : 'rgba(57, 255, 20, 0.1)',
              border: `1px solid ${critCount > 0 ? 'rgba(255, 0, 255, 0.3)' : 'rgba(57, 255, 20, 0.3)'}`,
              clipPath: 'polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%)',
            }}
          >
            <AlertTriangle size={12} aria-hidden="true" />
            {critCount} CRITICAL
          </div>
          <Link to="/dev" className="v4-nav-back" aria-label="Back to all variants">
            <ArrowLeft size={12} aria-hidden="true" />
            EXIT
          </Link>
        </div>
      </nav>

      {/* Main Content */}
      <main className="v4-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route path="connections" element={<Connections />} />
          <Route path="beacons" element={<Beacons />} />
          <Route path="dns" element={<DnsThreats />} />
          <Route path="threats" element={<Threats />} />
          <Route path="hunts" element={<HuntResults />} />
          <Route path="*" element={<Navigate to="/dev/4" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V4App;
