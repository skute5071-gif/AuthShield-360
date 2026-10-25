import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar } from './components/layout/Sidebar';
import { DashboardView } from './components/dashboard/DashboardView';
import { LoginSecurityView } from './components/login-security/LoginSecurityView';
import { SecurityEventsView } from './components/security-events/SecurityEventsView';
import { PhishingCheckerView } from './components/phishing/PhishingCheckerView';
import { PaymentRiskView } from './components/payment-risk/PaymentRiskView';
import { FileIntegrityView } from './components/file-integrity/FileIntegrityView';
import { ReportsView } from './components/reports/ReportsView';
import { SettingsView } from './components/settings/SettingsView';
import { AuthModal } from './components/auth/AuthModal';
import { VerificationChecklistModal } from './components/auth/VerificationChecklistModal';
import { SecurityStats, SecurityEvent, SecurityAlert, SecuritySettings, User } from './types/security';
import { api } from './services/api';
import { Menu, X, ShieldAlert } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [settings, setSettings] = useState<SecuritySettings | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Modals
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('login');
  const [checklistModalOpen, setChecklistModalOpen] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 4000);
  };

  const loadData = useCallback(async () => {
    try {
      const [fetchedUser, fetchedStats, fetchedEvents, fetchedAlerts, fetchedSettings] =
        await Promise.all([
          api.getMe().catch(() => null),
          api.getStats().catch(() => null),
          api.getEvents({ limit: 100 }).catch(() => []),
          api.getAlerts().catch(() => []),
          api.getSettings().catch(() => null),
        ]);

      if (fetchedUser) {
        setCurrentUser(fetchedUser);
      }
      if (fetchedStats) setStats(fetchedStats);
      if (fetchedEvents) setEvents(fetchedEvents);
      if (fetchedAlerts) setAlerts(fetchedAlerts);
      if (fetchedSettings) setSettings(fetchedSettings);
    } catch (err: any) {
      console.error('Error fetching security telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Poll telemetry periodically every 15s to keep dashboard live
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleOpenAuthModal = (mode: 'login' | 'register' = 'login') => {
    setAuthModalMode(mode);
    setAuthModalOpen(true);
  };

  const handleAuthSuccess = (user: User) => {
    setCurrentUser(user);
    showToast(`Signed in successfully as ${user.name} (${user.role.toUpperCase()})`);
    loadData();
  };

  const handleLogout = async () => {
    await api.logout();
    setCurrentUser(null);
    showToast('Session ended. You have been logged out.');
    loadData();
  };

  const handleResetDemo = async () => {
    try {
      await api.resetDemo();
      await loadData();
      showToast('AuthShield 360 restored to baseline demo dataset.');
    } catch (err: any) {
      showToast('Failed to reset demo: ' + err.message);
    }
  };

  const handleUpdateAlertStatus = async (id: string, status: SecurityAlert['status'], note?: string) => {
    try {
      await api.updateAlertStatus(id, status, note);
      await loadData();
      showToast(`Alert status updated to ${status}.`);
    } catch (err: any) {
      showToast('Error updating alert: ' + err.message);
    }
  };

  const handleBlockIp = async (ip: string) => {
    if (!currentUser) {
      handleOpenAuthModal('login');
      showToast('Authentication required to modify firewall drop table.');
      return;
    }
    if (currentUser.role !== 'admin') {
      showToast('Action Forbidden: Administrator privileges required to ban IPs.');
      return;
    }
    try {
      await api.blockIp(ip);
      await loadData();
      showToast(`IP ${ip} appended to perimeter drop table.`);
    } catch (err: any) {
      showToast('Error blocking IP: ' + err.message);
    }
  };

  const handleUpdateSettings = async (newSettings: Partial<SecuritySettings>) => {
    if (!currentUser) {
      handleOpenAuthModal('login');
      showToast('Authentication required to alter detection thresholds.');
      return;
    }
    if (currentUser.role !== 'admin') {
      showToast('Action Forbidden: Administrator privileges required to alter settings.');
      return;
    }
    try {
      const updated = await api.updateSettings(newSettings);
      setSettings(updated);
      await loadData();
      showToast('Perimeter security thresholds updated successfully.');
    } catch (err: any) {
      showToast('Failed to save settings: ' + err.message);
    }
  };

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <Header
        stats={stats}
        currentUser={currentUser}
        onResetDemo={handleResetDemo}
        onSelectTab={setActiveTab}
        activeTab={activeTab}
        onOpenAuthModal={handleOpenAuthModal}
        onOpenChecklistModal={() => setChecklistModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Mobile Nav Toggle Button */}
      <div className="lg:hidden flex items-center justify-between border-b border-slate-800 bg-[#070b16] px-4 py-2.5">
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="flex items-center gap-2 text-xs font-semibold text-slate-300 hover:text-white"
        >
          {mobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4 text-cyan-400" />}
          <span>Navigation Menu</span>
        </button>
        <span className="font-mono text-xs text-cyan-400 capitalize">
          {activeTab.replace('-', ' ')}
        </span>
      </div>

      {/* Main Body with Sidebar */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          mobileOpen={mobileMenuOpen}
          onCloseMobile={() => setMobileMenuOpen(false)}
        />

        {/* Content Container */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full">
          {activeTab === 'dashboard' && (
            <DashboardView
              stats={stats}
              events={events}
              alerts={alerts}
              isLoading={isLoading}
              onSelectTab={setActiveTab}
              onUpdateAlertStatus={handleUpdateAlertStatus}
              onBlockIp={handleBlockIp}
              onRefresh={loadData}
            />
          )}

          {activeTab === 'login-security' && (
            <LoginSecurityView
              onEventCreated={loadData}
              onSelectTab={setActiveTab}
            />
          )}

          {activeTab === 'security-events' && (
            <SecurityEventsView
              events={events}
              isLoading={isLoading}
              onRefresh={loadData}
            />
          )}

          {activeTab === 'phishing-checker' && (
            <PhishingCheckerView />
          )}

          {activeTab === 'payment-risk' && (
            <PaymentRiskView
              onEventCreated={loadData}
              onSelectTab={setActiveTab}
            />
          )}

          {activeTab === 'file-integrity' && (
            <FileIntegrityView
              onEventCreated={loadData}
              onSelectTab={setActiveTab}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsView
              stats={stats}
              events={events}
              currentUser={currentUser}
              onChecklistUpdated={loadData}
              onOpenAuthModal={handleOpenAuthModal}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              settings={settings}
              currentUser={currentUser}
              onUpdateSettings={handleUpdateSettings}
              onResetDemo={handleResetDemo}
              onUserUpdated={(u) => setCurrentUser(u)}
              onOpenAuthModal={() => handleOpenAuthModal('login')}
            />
          )}

          {/* Fallback shortcut when header alert bell is clicked */}
          {activeTab === 'alerts' && (
            <DashboardView
              stats={stats}
              events={events}
              alerts={alerts}
              isLoading={isLoading}
              onSelectTab={setActiveTab}
              onUpdateAlertStatus={handleUpdateAlertStatus}
              onBlockIp={handleBlockIp}
              onRefresh={loadData}
            />
          )}
        </main>
      </div>

      {/* Auth Modal (Login / Register / 2FA / Password Reset) */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthSuccess={handleAuthSuccess}
        initialMode={authModalMode}
      />

      {/* Verification Checklist Modal (Automated Test Suite for Viva Evaluation) */}
      <VerificationChecklistModal
        isOpen={checklistModalOpen}
        onClose={() => setChecklistModalOpen(false)}
      />

      {/* Global Notification Toast */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 flex items-center gap-2.5 rounded-xl border border-cyan-500/40 bg-slate-900/95 px-4 py-3 text-xs font-medium text-slate-100 shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-2">
          <ShieldAlert className="h-4 w-4 text-cyan-400" />
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}
