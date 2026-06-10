/**
 * Variant 1: NOC Operator / Dark Mission Control
 * Layout shell with persistent sidebar, top bar, and page routing.
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
  Crosshair,
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
  { to: '/dev/1', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/dev/1/connections', icon: Network, label: 'Connections', end: false },
  { to: '/dev/1/beacons', icon: Radio, label: 'Beacons', end: false },
  { to: '/dev/1/dns', icon: Globe, label: 'DNS Threats', end: false },
  { to: '/dev/1/threats', icon: Shield, label: 'Threats', end: false },
  { to: '/dev/1/hunts', icon: Search, label: 'Hunt Results', end: false },
];

const Clock: React.FC = () => {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="v1-clock" aria-live="off" aria-label="Current time">
      {format(now, 'yyyy-MM-dd')}
      <span style={{ opacity: 0.4, margin: '0 4px' }} aria-hidden="true">|</span>
      {format(now, 'HH:mm:ss')}
      <span style={{ opacity: 0.3, marginLeft: 4, fontSize: 10 }}>UTC</span>
    </span>
  );
};

const V1App: React.FC = () => {
  const critCount = mockDashboardStats.criticalAlerts;

  return (
    <div className="v1-root v1-scanline">
      {/* Sidebar */}
      <nav className="v1-sidebar" aria-label="Main navigation">
        <div className="v1-sidebar-logo" aria-hidden="true">
          <Crosshair size={24} />
        </div>

        <div className="v1-sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `v1-nav-item${isActive ? ' active' : ''}`
              }
              aria-label={item.label}
            >
              <item.icon aria-hidden="true" />
              <span className="v1-nav-label">{item.label}</span>
            </NavLink>
          ))}
        </div>

        <div className="v1-sidebar-footer">
          <Link to="/dev" aria-label="Back to all variants">
            <ArrowLeft size={16} aria-hidden="true" />
            <span className="v1-nav-label">All Variants</span>
          </Link>
        </div>
      </nav>

      {/* Top Bar */}
      <header className="v1-topbar">
        <div className="v1-topbar-brand">
          <Crosshair size={20} aria-hidden="true" />
          <span>Vervet</span>
          <span style={{ fontSize: 10, fontWeight: 400, opacity: 0.4, letterSpacing: 1 }}>
            v1 NOC
          </span>
        </div>
        <div className="v1-topbar-right">
          <Clock />
          <div className="v1-threat-badge" role="status" aria-label={`${critCount} critical alerts`}>
            <span className="pulse-dot" aria-hidden="true" />
            {critCount} CRITICAL
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="v1-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route path="connections" element={<Connections />} />
          <Route path="beacons" element={<Beacons />} />
          <Route path="dns" element={<DnsThreats />} />
          <Route path="threats" element={<Threats />} />
          <Route path="hunts" element={<HuntResults />} />
          <Route path="*" element={<Navigate to="/dev/1" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V1App;
