import React, { useState } from 'react';
import { Play, Shield, ShieldAlert, Cpu, Sparkles, AlertTriangle, ArrowRight, CheckCircle2, Lock, FileCode, Layers } from 'lucide-react';

const SCENARIOS = {
  aadhaar_jigsaw: {
    title: 'Multi-Turn Split Aadhaar (India DPDP Rule 4)',
    desc: 'Simulates user and CRM tool returning fragmented pieces of an Indian Aadhaar ID across 3 turns.',
    messages: [
      { role: 'user', content: 'Hello, please verify my government identity. First part is AADH-4567.' },
      { role: 'assistant', content: 'Checking verification database... Calling CRM tool.' },
      { role: 'tool', content: 'CRM Tool result: Customer profile found middle sequence 8901.' },
      { role: 'user', content: 'Yes, and the final digits on the card are 2341.' },
    ],
  },
  clinical_mrn: {
    title: 'Clinical Trial Patient Screening (HIPAA / FDA Part 11)',
    desc: 'Clinical AI agent processing fragmented EHR records and oncology eligibility criteria.',
    messages: [
      { role: 'user', content: 'Screen patient for NCT05494138 trial. Patient record MRN-902184.' },
      { role: 'tool', content: 'EHR Tool: Stage III Colorectal adenocarcinoma, ALT 45 U/L, eGFR 72.' },
      { role: 'user', content: 'Please summarize trial inclusion criteria and determine match without leaking PHI.' },
    ],
  },
  card_pan: {
    title: 'Fintech Agent Split Card & PAN Leak',
    desc: 'Customer support bot collecting payment credentials across multiple turns.',
    messages: [
      { role: 'user', content: 'My registered PAN is ABCPE1234F for merchant settlement.' },
      { role: 'assistant', content: 'Understood. Please provide card authorization prefix.' },
      { role: 'user', content: 'Card prefix is 4992-7398 and ending is 716.' },
    ],
  },
};

export default function LivePlayground({ onSessionUpdated }) {
  const [selectedScenarioKey, setSelectedScenarioKey] = useState('aadhaar_jigsaw');
  const [messages, setMessages] = useState(SCENARIOS.aadhaar_jigsaw.messages);
  const [protectedMode, setProtectedMode] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSelectScenario = (key) => {
    setSelectedScenarioKey(key);
    setMessages(SCENARIOS[key].messages);
    setResult(null);
    setError(null);
  };

  const handleUpdateMessage = (index, newContent) => {
    const updated = [...messages];
    updated[index].content = newContent;
    setMessages(updated);
  };

  const handleAddMessage = () => {
    setMessages([...messages, { role: 'user', content: '' }]);
  };

  const handleRemoveMessage = (index) => {
    if (messages.length <= 1) return;
    setMessages(messages.filter((_, i) => i !== index));
  };

  const executeSimulation = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: `sim_${selectedScenarioKey}_${Date.now()}`,
          messages: messages,
          protected: protectedMode,
        }),
      });

      if (!res.ok) {
        throw new Error(`Simulation failed: ${res.statusText}`);
      }

      const data = await res.json();
      setResult(data);
      if (onSessionUpdated) {
        onSessionUpdated();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Scenario Selector */}
      <div className="glass-panel rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Cpu className="w-5 h-5 text-indigo-400" />
              Live Agent Interception & Jigsaw Sandbox
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Simulate an autonomous AI agent conversing with tools and users. Test how Chainmark detects split fragments and prevents leaks.
            </p>
          </div>

          {/* Protected / Unprotected Toggle */}
          <div className="flex items-center gap-3 bg-slate-900/80 p-2 rounded-xl border border-slate-800">
            <span className={`text-xs font-semibold ${!protectedMode ? 'text-rose-400' : 'text-slate-400'}`}>
              Unprotected (Raw LLM)
            </span>
            <button
              onClick={() => setProtectedMode(!protectedMode)}
              className={`w-14 h-7 rounded-full transition-colors relative p-1 ${
                protectedMode ? 'bg-indigo-600' : 'bg-rose-600'
              }`}
            >
              <div
                className={`w-5 h-5 rounded-full bg-white transition-transform ${
                  protectedMode ? 'translate-x-7' : 'translate-x-0'
                }`}
              />
            </button>
            <span className={`text-xs font-semibold ${protectedMode ? 'text-emerald-400' : 'text-slate-400'}`}>
              Chainmark Guard (Active)
            </span>
          </div>
        </div>

        {/* Preset Scenarios Buttons */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {Object.entries(SCENARIOS).map(([key, item]) => (
            <button
              key={key}
              onClick={() => handleSelectScenario(key)}
              className={`text-left p-3.5 rounded-xl border transition-all ${
                selectedScenarioKey === key
                  ? 'bg-indigo-950/40 border-indigo-500/50 shadow-md shadow-indigo-500/10'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/70'
              }`}
            >
              <div className="font-semibold text-xs text-white mb-1">{item.title}</div>
              <div className="text-[11px] text-slate-400 line-clamp-2">{item.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Multi-Turn Conversation Editor */}
        <div className="lg:col-span-5 glass-panel rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-sm text-slate-200 flex items-center gap-2">
                <Layers className="w-4 h-4 text-slate-400" />
                Session Conversation Turns
              </h3>
              <button
                onClick={handleAddMessage}
                className="text-xs px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-indigo-300 transition"
              >
                + Add Turn
              </button>
            </div>

            <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
              {messages.map((msg, idx) => (
                <div key={idx} className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span
                      className={`font-mono px-2 py-0.5 rounded font-medium ${
                        msg.role === 'user'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                          : msg.role === 'tool'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                      }`}
                    >
                      Turn {idx + 1}: {msg.role.toUpperCase()}
                    </span>
                    {messages.length > 1 && (
                      <button
                        onClick={() => handleRemoveMessage(idx)}
                        className="text-slate-500 hover:text-rose-400 text-xs"
                      >
                        ✕
                      </button>
                    )}
                  </div>
                  <textarea
                    rows={2}
                    value={msg.content}
                    onChange={(e) => handleUpdateMessage(idx, e.target.value)}
                    className="w-full bg-slate-950/70 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 transition font-mono resize-none"
                  />
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-slate-800">
            <button
              onClick={executeSimulation}
              disabled={loading}
              className={`w-full py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition shadow-lg ${
                protectedMode
                  ? 'bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white shadow-indigo-500/25'
                  : 'bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white shadow-rose-500/25'
              } disabled:opacity-50`}
            >
              {loading ? (
                <>Processing Interception Pipeline...</>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Execute Agent Pipeline ({protectedMode ? 'Chainmark Protected' : 'Direct Egress'})
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Real-Time Egress & Evidence Inspection */}
        <div className="lg:col-span-7 space-y-4">
          {error && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!result && !error && (
            <div className="glass-panel rounded-2xl p-12 text-center text-slate-400 flex flex-col items-center justify-center min-h-[460px]">
              <Cpu className="w-12 h-12 text-slate-600 mb-3 animate-pulse" />
              <div className="font-semibold text-slate-300">Ready to Inspect Pipeline</div>
              <p className="text-xs max-w-sm mt-1">
                Click "Execute Agent Pipeline" to inspect how the Session Taint engine catches split fragments and sanitizes the outgoing LLM payload.
              </p>
            </div>
          )}

          {result && (
            <div className="space-y-4">
              {/* Verdict Header */}
              <div
                className={`p-4 rounded-xl border flex items-center justify-between ${
                  result.mode === 'CHAINMARK_PROTECTED'
                    ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                    : 'bg-rose-950/20 border-rose-500/40 text-rose-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  {result.mode === 'CHAINMARK_PROTECTED' ? (
                    <div className="p-2 rounded-lg bg-emerald-500/20">
                      <Shield className="w-6 h-6 text-emerald-400" />
                    </div>
                  ) : (
                    <div className="p-2 rounded-lg bg-rose-500/20">
                      <ShieldAlert className="w-6 h-6 text-rose-400" />
                    </div>
                  )}
                  <div>
                    <div className="font-bold text-sm">
                      {result.mode === 'CHAINMARK_PROTECTED'
                        ? 'Zero Sensitive Egress — Sanitized with HMAC Tokens'
                        : 'CRITICAL SECURITY BREACH — Plaintext Sensitive Leak!'}
                    </div>
                    <div className="text-xs opacity-80">
                      {result.mode === 'CHAINMARK_PROTECTED'
                        ? 'External LLM received ONLY tokens; local AES-256 vault preserved detokenization key.'
                        : 'External LLM provider received raw reconstructed personal identifiers in prompt context.'}
                    </div>
                  </div>
                </div>

                <div className="text-right">
                  <span
                    className={`text-xs px-2.5 py-1 rounded-full font-mono font-semibold ${
                      result.mode === 'CHAINMARK_PROTECTED'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    }`}
                  >
                    {result.mode === 'CHAINMARK_PROTECTED' ? 'DPDP / HIPAA PASS' : 'VIOLATION DETECTED'}
                  </span>
                </div>
              </div>

              {/* Detected Entities & Provenance */}
              <div className="glass-panel rounded-xl p-4">
                <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
                  <span>Session Taint Engine Detections</span>
                  <span className="text-[11px] text-indigo-400">
                    {result.detected_entities.length} sensitive entity types identified
                  </span>
                </div>

                {result.detected_entities.length === 0 ? (
                  <div className="text-xs text-slate-500 italic">No sensitive entities found.</div>
                ) : (
                  <div className="space-y-2">
                    {result.detected_entities.map((ent, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between text-xs font-mono"
                      >
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-bold">
                            {ent.entity_type}
                          </span>
                          <span className="text-slate-300">{ent.raw_value}</span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px]">
                          {ent.is_fragment_assembly && (
                            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                              ⚡ Multi-Turn Jigsaw Assembled
                            </span>
                          )}
                          <span className="text-slate-400">
                            Turns: [{ent.provenance_turns.map((t) => `Turn ${t + 1}`).join(', ')}]
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Wire Comparison: What Upstream LLM Receives */}
              <div className="glass-panel rounded-xl p-4">
                <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5 text-slate-400" />
                    External Egress Wire (What Gemini / OpenAI Sees)
                  </span>
                  <span className="font-mono text-[10px] text-slate-400">
                    {result.mode === 'CHAINMARK_PROTECTED' ? 'Tokens Only' : 'Plaintext Leak'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 font-mono text-xs overflow-x-auto max-h-36 text-slate-300 border border-slate-800">
                  <pre>{JSON.stringify(result.egress_payload, null, 2)}</pre>
                </div>
              </div>

              {/* Client Detokenized Completion */}
              {result.mode === 'CHAINMARK_PROTECTED' && (
                <div className="glass-panel rounded-xl p-4 border-l-4 border-l-indigo-500">
                  <div className="text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
                    <span>Authorized Client View (Seamless Detokenization)</span>
                    <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                      <Lock className="w-3 h-3" /> Restored via AES-256 Vault
                    </span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
                    {result.detokenized_client_response}
                  </div>
                </div>
              )}

              {/* Cryptographic Proof Node */}
              {result.audit_trail_recorded && (
                <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span className="text-slate-300">Recorded in Merkle DAG:</span>
                    <span className="font-mono text-slate-400 text-[11px] truncate max-w-xs">
                      Root: {result.merkle_root}
                    </span>
                  </div>
                  <span className="text-indigo-400 text-[11px] font-mono">
                    Node #{result.total_events} Sealed
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
