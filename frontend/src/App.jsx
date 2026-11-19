import React, { useState } from 'react';
import Navbar from './components/Navbar';
import LivePlayground from './components/LivePlayground';
import SessionMonitor from './components/SessionMonitor';
import ComplianceMatrix from './components/ComplianceMatrix';
import { Cpu, Terminal, Scale, Shield, Sparkles, Database, Lock, CheckCircle, ArrowRight } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('playground');
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handleSessionUpdated = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] bg-grid-pattern text-slate-100 flex flex-col justify-between">
      {/* Navbar */}
      <Navbar />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto w-full px-6 py-8 space-y-8 flex-1">
        {/* Hero Section */}
        <div className="relative rounded-3xl p-8 glass-panel overflow-hidden border border-slate-800/80">
          <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-0 left-1/3 w-80 h-80 bg-violet-600/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 max-w-3xl space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold">
              <Sparkles className="w-3.5 h-3.5" /> Google DeepMind & Google Cloud Buildathon India 2026
            </div>

            <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white leading-tight">
              Stop the leak. <br />
              <span className="bg-gradient-to-r from-indigo-400 via-violet-400 to-cyan-400 bg-clip-text text-transparent">
                And prove it.
              </span>
            </h1>

            <p className="text-sm md:text-base text-slate-300 leading-relaxed max-w-2xl">
              AI agents reconstruct fragmented customer data across tools and memory, creating silent data leaks to external foundation models. 
              <strong className="text-white"> Chainmark AI</strong> intercepts split fragments, swaps them for format-preserving typed tokens, and compiles a tamper-evident, cryptographically signed Merkle DAG for regulators.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-2 text-xs text-slate-400">
              <div className="flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span>Zero Agent Code Modification</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span>Deterministic Verhoeff & Luhn Checksums</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span>Air-Gapped Offline Verifier CLI</span>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
          <button
            onClick={() => setActiveTab('playground')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all ${
              activeTab === 'playground'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Cpu className="w-4 h-4" />
            Live Agent Sandbox
          </button>

          <button
            onClick={() => setActiveTab('monitor')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all ${
              activeTab === 'monitor'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Terminal className="w-4 h-4" />
            CISO Flight Desk & Evidence DAG
          </button>

          <button
            onClick={() => setActiveTab('compliance')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all ${
              activeTab === 'compliance'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Scale className="w-4 h-4" />
            Regulatory Compliance Matrix
          </button>
        </div>

        {/* Tab Views */}
        {activeTab === 'playground' && (
          <LivePlayground onSessionUpdated={handleSessionUpdated} />
        )}

        {activeTab === 'monitor' && (
          <SessionMonitor refreshTrigger={refreshTrigger} />
        )}

        {activeTab === 'compliance' && (
          <ComplianceMatrix />
        )}
      </main>

      {/* Footer */}
      <footer className="glass-panel border-t border-slate-800/80 px-6 py-4 mt-12">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500">
          <div>
            Built by <strong className="text-slate-400">Team Avengers</strong> for Google DeepMind & Google Cloud Startup Buildathon India 2026.
          </div>
          <div className="flex items-center space-x-4">
            <span>FastAPI Backend (Port 8000)</span>
            <span>•</span>
            <span>React Frontend (Port 5173)</span>
            <span>•</span>
            <span>ECDSA P-256 + SHA-256 Merkle Proofs</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
