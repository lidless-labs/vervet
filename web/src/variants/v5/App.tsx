/**
 * Variant 5: Minimal Analyst — Editorial Data Journalism
 * NYT/FT-inspired layout. No sidebar. Horizontal top nav, document flow.
 * Paper-white, serif headlines, generous whitespace.
 */
import React from 'react';
import { Routes, Route, NavLink, Navigate, Link } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  Radio,
  Globe,
  Shield,
  Search,
  ArrowLeft,
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import Connections from './pages/Connections';
import Beacons from './pages/Beacons';
import DnsThreats from './pages/DnsThreats';
import Threats from './pages/Threats';
import HuntResults from './pages/HuntResults';
import './styles.css';

const NAV_ITEMS = [
  { to: '/dev/5', icon: LayoutDashboard, label: 'Overview', end: true },
  { to: '/dev/5/connections', icon: Network, label: 'Connections', end: false },
  { to: '/dev/5/beacons', icon: Radio, label: 'Beacons', end: false },
  { to: '/dev/5/dns', icon: Globe, label: 'DNS', end: false },
  { to: '/dev/5/threats', icon: Shield, label: 'Threats', end: false },
  { to: '/dev/5/hunts', icon: Search, label: 'Intelligence', end: false },
];

const V5App: React.FC = () => {
  return (
    <div className="v5-root">
      {/* Horizontal top nav */}
      <nav className="v5-nav" aria-label="Main navigation">
        <div className="v5-nav-inner">
          <Link to="/dev/5" className="v5-nav-brand" aria-label="Vervet home">
            Vervet
          </Link>

          <div className="v5-nav-links">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `v5-nav-link${isActive ? ' active' : ''}`
                }
                aria-label={item.label}
              >
                {item.label}
              </NavLink>
            ))}
          </div>

          <Link to="/dev" className="v5-nav-back" aria-label="Back to all variants">
            <ArrowLeft size={14} aria-hidden="true" />
            Variants
          </Link>
        </div>
      </nav>

      {/* Document-flow main content */}
      <main className="v5-container v5-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route path="connections" element={<Connections />} />
          <Route path="beacons" element={<Beacons />} />
          <Route path="dns" element={<DnsThreats />} />
          <Route path="threats" element={<Threats />} />
          <Route path="hunts" element={<HuntResults />} />
          <Route path="*" element={<Navigate to="/dev/5" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V5App;
