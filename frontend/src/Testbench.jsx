import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Lock, Unlock, Copy, Check, RefreshCw, Download, Terminal, Zap, ArrowRight, Eye, EyeOff } from 'lucide-react';

const SAMPLES = [
  {
    label: 'Aadhaar (Verhoeff)',
    text: 'Please verify account for customer with Aadhaar 456789012341.',
  },
  {
    label: 'Split Jigsaw Aadhaar',
    text: 'Customer provided prefix 4567-8901 and earlier provided suffix was 2341.',
  },
  {
    label: 'PAN Card',
    text: 'Tax return authorization granted for PAN ABCPE1234F under Section 139.',
  },
  {
    label: 'Split Payment Card (Luhn)',
    text: 'Hey Jeet Gorai Charge card 4992 7398716 for subscription renewal of $49.00.',
  },
  {
    label: 'Patient MRN (HIPAA)',
    text: 'Oncology screening patient record MRN-902184 diagnosed with stage 3 adenocarcinoma.',
  },
];

export default function Testbench() {
  const [inputText, setInputText] = useState(SAMPLES[0].text);
  const [requestId, setRequestId] = useState(`req_${Math.random().toString(36).substring(2, 9)}`);
  const [loadingCloak, setLoadingCloak] = useState(false);
  const [loadingUncloak, setLoadingUncloak] = useState(false);
  
  const [cloakResult, setCloakResult] = useState(null);
  const [uncloakInput, setUncloakInput] = useState('');
  const [uncloakResult, setUncloakResult] = useState(null);
  
  const [gatewayOnline, setGatewayOnline] = useState(true);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(null);

  // Check health on mount
  useEffect(() => {
    fetch('/health')
      .then((res) => setGatewayOnline(res.ok))
      .catch(() => setGatewayOnline(false));
  }, []);

  const handleGenerateNewId = () => {
    const newId = `req_${Math.random().toString(36).substring(2, 9)}`;
    setRequestId(newId);
    setCloakResult(null);
    setUncloakResult(null);
    setUncloakInput('');
    setError(null);
  };

  const handleCloak = async () => {
    if (!inputText.trim()) return;
    setLoadingCloak(true);
    setError(null);
    try {
      const res = await fetch('/cloak', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: inputText,
          cloak_request_id: requestId,
        }),
      });

      if (!res.ok) {
        throw new Error(`Cloak failed (${res.status}): ${await res.text()}`);
      }

      const data = await res.json();
      setCloakResult(data);
      // Auto-populate uncloak test box with simulated LLM response containing the token
      setUncloakInput(`External LLM response: Verified identity for ${data.cloaked_text} successfully.`);
      setUncloakResult(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingCloak(false);
    }
  };

  const handleUncloak = async () => {
    if (!uncloakInput.trim()) return;
    setLoadingUncloak(true);
    setError(null);
    try {
      const res = await fetch(`/uncloak/${requestId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cloaked_text: uncloakInput,
        }),
      });

      if (!res.ok) {
        throw new Error(`Uncloak failed (${res.status}): ${await res.text()}`);
      }

      const data = await res.json();
      setUncloakResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingUncloak(false);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadEvidence = () => {
    window.location.href = `/v1/evidence/export/${requestId}`;
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 p-4 sm:p-6 md:p-8 flex flex-col justify-between max-w-6xl mx-auto font-sans">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-6 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-600/30">
            <Lock className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white">Chainmark AI</h1>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                /cloak & /uncloak testbench
              </span>
            </div>
            <p className="text-xs text-slate-400">Deterministic PII parsing, tokenization & reversible AES vault</p>
          </div>
        </div>

        {/* Status & Request ID */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            <span className="text-slate-500">Scope:</span>
            <span className="text-indigo-300 font-semibold">{requestId}</span>
            <button
              onClick={handleGenerateNewId}
              title="Generate new request scope"
              className="text-slate-400 hover:text-white transition ml-1"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
            <span className={`w-2 h-2 rounded-full ${gatewayOnline ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
            <span className="text-slate-300 font-medium">{gatewayOnline ? 'Port 8000 Online' : 'Gateway Offline'}</span>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 my-6 flex-1">
        
        {/* PANE 1: INPUT & CLOAK */}
        <div className="flex flex-col justify-between p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Eye className="w-4 h-4 text-indigo-400" />
                Raw Input Text
              </label>
              <span className="text-[11px] text-slate-500">Detects Aadhaar, PAN, Cards, SSN, MRN</span>
            </div>

            {/* Quick Samples */}
            <div className="flex flex-wrap gap-1.5">
              {SAMPLES.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setInputText(s.text)}
                  className="px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] font-medium border border-slate-700/60 transition"
                >
                  {s.label}
                </button>
              ))}
            </div>

            <textarea
              rows={6}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Enter text containing sensitive IDs or multi-turn split fragments..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 font-mono resize-none transition"
            />
          </div>

          <div>
            <button
              onClick={handleCloak}
              disabled={loadingCloak || !inputText.trim()}
              className="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20 transition disabled:opacity-50"
            >
              {loadingCloak ? (
                <>Parsing & Tokenizing...</>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  Execute /cloak
                </>
              )}
            </button>
          </div>
        </div>

        {/* PANE 2: CLOAKED OUTPUT & DETECTIONS */}
        <div className="flex flex-col justify-between p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <EyeOff className="w-4 h-4 text-emerald-400" />
                Cloaked Output (What LLM Receives)
              </label>
              {cloakResult && (
                <button
                  onClick={() => handleCopy(cloakResult.cloaked_text)}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white transition"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              )}
            </div>

            <div className="w-full min-h-[140px] bg-slate-950 border border-slate-800 rounded-xl p-3 text-sm font-mono text-slate-300">
              {cloakResult ? (
                <div className="whitespace-pre-wrap break-all leading-relaxed">
                  {cloakResult.cloaked_text}
                </div>
              ) : (
                <div className="text-slate-600 text-xs italic flex items-center justify-center h-full pt-10">
                  Click "Execute /cloak" to tokenize sensitive fragments.
                </div>
              )}
            </div>

            {/* Entities Found Badges */}
            {cloakResult && (
              <div className="space-y-2 pt-1">
                <div className="text-[11px] font-semibold text-slate-400">
                  Detected Entities ({cloakResult.detected_entities.length}):
                </div>
                {cloakResult.detected_entities.length === 0 ? (
                  <div className="text-xs text-slate-500 italic">No sensitive entities detected.</div>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto">
                    {cloakResult.detected_entities.map((ent, idx) => (
                      <div
                        key={idx}
                        className="p-2 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs font-mono"
                      >
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-bold text-[10px]">
                            {ent.entity_type}
                          </span>
                          <span className="text-rose-300 line-through text-[11px]">{ent.raw_value}</span>
                          <span className="text-slate-500">→</span>
                          <span className="text-emerald-400 font-semibold text-[11px]">{ent.token}</span>
                        </div>

                        {ent.is_fragment_assembly && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            ⚡ Jigsaw Assembled
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {cloakResult && (
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
              <span>Event Seq #{cloakResult.event_sequence}</span>
              <span className="truncate max-w-[200px]">Merkle: {cloakResult.merkle_root.substring(0, 16)}...</span>
            </div>
          )}
        </div>
      </div>

      {/* SECTION 2: UNCLOAK TESTBENCH */}
      <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Unlock className="w-4 h-4 text-cyan-400" />
              Test /uncloak/{'{cloakrequestid}'} (Reversible Restoration)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulate an external LLM returning an answer containing the tokens. Verify the local AES-256 vault restores the original data.
            </p>
          </div>

          <button
            onClick={handleUncloak}
            disabled={loadingUncloak || !uncloakInput.trim()}
            className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow-md shadow-cyan-600/20 transition disabled:opacity-50"
          >
            {loadingUncloak ? 'Uncloaking...' : 'Execute /uncloak'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-[11px] font-semibold text-slate-400 mb-1.5 block">
              Cloaked Text to Restore (Containing Tokens):
            </label>
            <textarea
              rows={3}
              value={uncloakInput}
              onChange={(e) => setUncloakInput(e.target.value)}
              placeholder="Paste text with [CM_TOKEN_...] to test uncloaking..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono resize-none transition"
            />
          </div>

          <div>
            <label className="text-[11px] font-semibold text-slate-400 mb-1.5 block">
              Restored Output (Original Plaintext Returned to Client):
            </label>
            <div className="w-full min-h-[72px] bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs font-mono text-emerald-300 whitespace-pre-wrap break-all">
              {uncloakResult ? (
                uncloakResult.uncloaked_text
              ) : (
                <span className="text-slate-600 italic">Click "Execute /uncloak" to restore tokens.</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Bar: Evidence & CLI */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 text-slate-400 font-mono">
          <Terminal className="w-4 h-4 text-indigo-400" />
          <span>Offline Audit CLI:</span>
          <code className="text-emerald-400 bg-slate-950 px-2 py-0.5 rounded text-[11px] select-all">
            uv run chainmark-verify evidence_pack_{requestId}.zip
          </code>
        </div>

        <button
          onClick={handleDownloadEvidence}
          className="flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition font-medium"
        >
          <Download className="w-3.5 h-3.5" />
          Download Evidence Pack (.zip)
        </button>
      </div>

      {error && (
        <div className="mt-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {error}
        </div>
      )}
    </div>
  );
}
