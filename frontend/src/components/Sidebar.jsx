import React from 'react';
import { 
  LayoutDashboard, 
  Terminal, 
  AlertTriangle, 
  Briefcase, 
  Sliders, 
  Search, 
  Cpu, 
  Network,
  FileCode2 
} from 'lucide-react';

export function Sidebar({ activeTab, onTabChange, metrics }) {
  const navItems = [
    { id: 'dashboard', label: 'Main Grid', icon: LayoutDashboard },
    { id: 'logs', label: 'Data Streams', icon: Terminal, count: metrics?.total_logs_ingested },
    { id: 'alerts', label: 'Breach Alerts', icon: AlertTriangle, count: metrics?.active_open_alerts, badgeClass: 'critical' },
    { id: 'incidents', label: 'Crisis Matrix', icon: Briefcase, count: metrics?.open_incidents },
    { id: 'rules', label: 'Logic Protocols', icon: Sliders },
    { id: 'threat-intel', label: 'Syndicate Intel', icon: Search },
    { id: 'cyberchef', label: 'Crypto Tool', icon: FileCode2 },
    { id: 'mitre', label: 'Adversary Tactics', icon: Network },
    { id: 'pcap', label: 'Network Wiretap', icon: Cpu },
  ];

  return (
    <aside className="sidebar top-nav-mode">
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <div
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => onTabChange(item.id)}
            >
              <Icon size={16} color={item.highlight && !isActive ? 'var(--color-high)' : undefined} />
              <span className="nav-label">{item.label}</span>
              {item.count !== undefined && item.count > 0 && (
                <span className={`nav-badge ${item.badgeClass || 'count'}`}>
                  {item.count}
                </span>
              )}
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
