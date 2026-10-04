import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { DashboardTab } from './components/DashboardTab';
import { LogExplorerTab } from './components/LogExplorerTab';
import { AlertsTab } from './components/AlertsTab';
import { IncidentsTab } from './components/IncidentsTab';
import { RulesTab } from './components/RulesTab';
import { ThreatIntelTab } from './components/ThreatIntelTab';
import { CyberChefTab } from './components/CyberChefTab';
import { MitreMatrixTab } from './components/MitreMatrixTab';
import { PcapInspectorTab } from './components/PcapInspectorTab';
import { IncidentReportModal } from './components/IncidentReportModal';
import { RawLogInjestModal } from './components/RawLogInjestModal';
import { Login } from './components/Login';
import { UserProfileModal } from './components/UserProfileModal';
import { api } from './services/api';

export function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [metrics, setMetrics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [isLiveStreaming, setIsLiveStreaming] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Modals & Navigation state
  const [selectedThreatIndicator, setSelectedThreatIndicator] = useState('185.220.101.5');
  const [reportIncidentId, setReportIncidentId] = useState(null);
  const [showRawInjector, setShowRawInjector] = useState(false);
  const [showUserProfile, setShowUserProfile] = useState(false);

  const wsRef = useRef(null);

  // Fetch core SOC metrics & alerts
  const refreshData = async () => {
    setIsRefreshing(true);
    try {
      const [mRes, aRes] = await Promise.all([
        api.getMetrics().catch(() => null),
        api.getAlerts({ limit: 100 }).catch(() => ({ alerts: [] }))
      ]);
      if (mRes) setMetrics(mRes);
      if (aRes?.alerts) setAlerts(aRes.alerts);
    } catch (err) {
      console.error('Error fetching SOC data:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Initial load and periodic polling fallback
  useEffect(() => {
    if (!isAuthenticated) return;
    refreshData();
    const interval = setInterval(refreshData, 8000);
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  // WebSocket Live Connection
  useEffect(() => {
    if (!isAuthenticated) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = import.meta.env.VITE_WS_URL || `${protocol}//${host}/ws/live`;

    let socket;
    try {
      socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setIsLiveStreaming(true);
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'ALERT_GENERATED' || data.type === 'LOG_INGESTED') {
            refreshData();
          }
        } catch (e) {
          // Heartbeat pong
        }
      };

      socket.onclose = () => {
        setIsLiveStreaming(false);
      };

      socket.onerror = () => {
        setIsLiveStreaming(false);
      };
    } catch (err) {
      console.warn('WebSocket init error:', err);
    }

    return () => {
      if (socket) socket.close();
    };
  }, []);

  // Handlers
  const handleSelectThreatIntel = (ipOrHash) => {
    setSelectedThreatIndicator(ipOrHash);
    setActiveTab('threat-intel');
  };

  const handleQuickSimulate = async (scenarioId) => {
    try {
      await api.runScenario(scenarioId);
      refreshData();
      alert(`Simulation completed! Checked detection rules and generated alerts.`);
    } catch (err) {
      alert('Simulation failed: ' + err.message);
    }
  };

  if (!isAuthenticated) {
    return <Login onLoginSuccess={() => setIsAuthenticated(true)} />;
  }

  return (
    <div className="app-container">
      {/* Top Header */}
      <Header 
        metrics={metrics}
        onRefresh={refreshData}
        isRefreshing={isRefreshing}
        onQuickSimulate={handleQuickSimulate}
        isLiveStreaming={isLiveStreaming}
        onOpenProfile={() => setShowUserProfile(true)}
      />

      <div className="main-layout">
        {/* Navigation Sidebar */}
        <Sidebar 
          activeTab={activeTab}
          onTabChange={setActiveTab}
          metrics={metrics}
        />

        {/* Content Area */}
        <main className="content-area">
          {activeTab === 'dashboard' && (
            <DashboardTab 
              metrics={metrics}
              alerts={alerts}
              onSelectAlert={(a) => {
                setActiveTab('alerts');
              }}
              onNavigateTab={setActiveTab}
              onQuickSimulate={handleQuickSimulate}
            />
          )}

          {activeTab === 'logs' && (
            <LogExplorerTab 
              onOpenRawInjector={() => setShowRawInjector(true)}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsTab 
              alerts={alerts}
              onRefresh={refreshData}
              onNavigateTab={setActiveTab}
              onSelectThreatIntel={handleSelectThreatIntel}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentsTab 
              onOpenReportModal={(id) => setReportIncidentId(id)}
            />
          )}

          {activeTab === 'rules' && (
            <RulesTab />
          )}

          {activeTab === 'threat-intel' && (
            <ThreatIntelTab 
              initialIndicator={selectedThreatIndicator}
            />
          )}

          {activeTab === 'cyberchef' && (
            <CyberChefTab />
          )}

          {activeTab === 'mitre' && (
            <MitreMatrixTab />
          )}

          {activeTab === 'pcap' && (
            <PcapInspectorTab />
          )}
        </main>
      </div>

      {/* Incident Report Modal */}
      {reportIncidentId && (
        <IncidentReportModal 
          incidentId={reportIncidentId}
          onClose={() => setReportIncidentId(null)}
        />
      )}

      {/* Raw Log Ingestion Modal */}
      {showRawInjector && (
        <RawLogInjestModal 
          onClose={() => setShowRawInjector(false)}
          onSuccess={refreshData}
        />
      )}

      {showUserProfile && (
        <UserProfileModal onClose={() => setShowUserProfile(false)} />
      )}
    </div>
  );
}

export default App;
