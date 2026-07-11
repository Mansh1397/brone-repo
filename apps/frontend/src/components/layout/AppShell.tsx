import React, { useState, useEffect } from "react";
import { GlobalHeader } from "./GlobalHeader";
import {
  HomeFeed,
  ReportingHub,
  JuryDuties,
  CapitalLedger,
} from "../dashboard/views/WorkspaceViews";
import { AuthGateway } from "../auth/AuthGateway";
import { loadAndDecryptState } from "../../utils/storage";

export type ViewTabId = "home" | "report" | "active" | "stats";

interface BottomTabItem {
  id: ViewTabId;
  label: string;
  icon: React.ReactNode;
}

export const AppShell: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ViewTabId>("home");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function checkSession() {
      try {
        const stored = await loadAndDecryptState();
        if (stored && stored.privateKeyJwk && stored.publicKeyHex) {
          const privateKey = await window.crypto.subtle.importKey(
            "jwk",
            stored.privateKeyJwk,
            {
              name: "ECDSA",
              namedCurve: "P-256",
            },
            true,
            ["sign"]
          );
          (window as any).__brone_keypair = {
            privateKey,
            publicKeyHex: stored.publicKeyHex,
          };
          setIsAuthenticated(true);
        }
      } catch (err) {
        console.error("Session restoration failed:", err);
      } finally {
        setIsLoading(false);
      }
    }
    checkSession();
  }, []);

  const renderActiveView = () => {
    switch (activeTab) {
      case "home":
        return <HomeFeed />;
      case "report":
        return <ReportingHub />;
      case "active":
        return <JuryDuties />;
      case "stats":
        return <CapitalLedger />;
      default:
        const exhaustiveCheck: never = activeTab;
        return <HomeFeed />;
    }
  };

  const tabs: BottomTabItem[] = [
    {
      id: "home",
      label: "Home",
      icon: (
        <svg className="w-5 h-5 mb-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
        </svg>
      ),
    },
    {
      id: "report",
      label: "Report",
      icon: (
        <svg className="w-5 h-5 mb-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      id: "active",
      label: "Active",
      icon: (
        <svg className="w-5 h-5 mb-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      id: "stats",
      label: "Stats",
      icon: (
        <svg className="w-5 h-5 mb-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
    },
  ];

  if (isLoading) {
    return (
      <div className="h-screen w-screen bg-[#0B0F19] flex flex-col items-center justify-center space-y-4">
        <svg className="animate-spin h-8 w-8 text-[#00E5FF]" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span className="font-mono text-xs uppercase text-gray-500 tracking-widest animate-pulse">
          Decrypting Secure Vault...
        </span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <AuthGateway onAuthSuccess={() => setIsAuthenticated(true)} />;
  }

  return (
    <div className="h-screen w-screen max-h-screen max-w-screen overflow-hidden flex flex-col bg-[#0B0F19] text-gray-100 font-sans">
      <GlobalHeader />

      <main className="flex-1 overflow-y-auto bg-[#0B0F19] focus:outline-none pb-24">
        {renderActiveView()}
      </main>

      <nav className="fixed bottom-0 left-0 right-0 h-20 bg-[#121826]/95 backdrop-blur-md border-t border-[#1F2937] z-50 flex items-center justify-around px-4">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex flex-col items-center justify-center w-20 h-full relative transition-all duration-200 select-none ${isActive ? "text-[#00E5FF]" : "text-gray-500 hover:text-gray-300"
                }`}
            >
              {isActive && (
                <div className="absolute top-0 left-3 right-3 h-1 bg-[#00E5FF] rounded-b-md shadow-[0_0_10px_rgba(0,229,255,0.6)]" />
              )}
              {tab.icon}
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider">
                {tab.label}
              </span>
            </button>
          );
        })}
      </nav>
    </div>
  );
};