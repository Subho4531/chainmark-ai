import React, { useState, useEffect } from 'react';
import { Download, ShieldCheck, ShieldAlert, AlertOctagon, Terminal, RefreshCw, Key, Check, AlertCircle } from 'lucide-react';

export default function SessionMonitor({ refreshTrigger }) {
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [sessionDetail, setSessionDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [tamperMessage, setTamperMessage] = useState(null);

  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/sessions');
      if (res.ok) {
        const data = await res.json();
        setSessions(data);
        if (data.length > 0 && !selectedSessionId) {
          setSelectedSessionId(data[0].session_id);
        }
      }
    } catch (e) {
      console.error('Failed to fetch sessions', e);
    }
  };

  const fetchSessionDetail = async (sid) => {
    if (!sid) return;
    setLoading(true);
    setTamperMessage(null);
    try {
      const res = await fetch(`/api/sessions/${sid}`);
      if (res.ok) {
        const data = await res.json();
        setSessionDetail(data);
      }
    } catch (e) {
      console.error('Failed to fetch session detail', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
  }, [refreshTrigger]);

  useEffect(() => {
    if (selectedSessionId) {
      fetchSessionDetail(selectedSessionId);
    }
  }, [selectedSessionId]);

  const handleDownloadPack = (sid) => {
    window.location.href = `/v1/evidence/export/${sid}`;
  };

  const handleSimulateTamper = async () => {
    if (!selectedSessionId) return;
    try {
      const res = await fetch(`/api/tamper/${selectedSessionId}`, { method: 'POST' });
      const data = await res.json();
      setTamperMessage(data);
      fetchSessionDetail(selectedSessionId);
      fetchSessions();
    } catch (e) {
      console.error('Tamper simulation error', e);
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-indigo-400" />
            CISO & DPO Evidence Flight Desk
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Every tokenization decision is sequenced into an append-only SHA-256 Merkle chain signed with ECDSA P-256.
          </p>
        </div>

        <button
          onClick={fetchSessions}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Audit Trail
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Sessions List */}
        <div className="lg:col-span-4 space-y-3">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
            Active Recorded Sessions ({sessions.length})
          </div>

          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {sessions.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
                No active sessions yet. Run a prompt simulation above to see live hash chaining!
              </div>
            ) : (
              sessions.map((sess) => (
                <div
                  key={sess.session_id}
                  onClick={() => setSelectedSessionId(sess.session_id)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    selectedSessionId === sess.session_id
                      ? 'bg-indigo-950/40 border-indigo-500/50 shadow-md shadow-indigo-500/10'
                      : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/70'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono font-medium text-slate-200 truncate max-w-[170px]">
                      {sess.session_id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        sess.tamper_evident_valid
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      {sess.tamper_evident_valid ? 'SEAL VALID' : 'TAMPERED'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                    <span>{sess.event_count} Chained Events</span>
                    <span className="text-[10px] font-mono truncate max-w-[120px]">
                      Root: {sess.merkle_root.substring(0, 10)}...
                    </span>
                  </div>

                  {sess.entities_detected.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {sess.entities_detected.map((ent, i) => (
                        <span
                          key={i}
                          className="px-1.5 py-0.5 rounded bg-slate-800 text-[9px] text-indigo-300 font-mono"
                        >
                          {ent}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Merkle DAG & Evidence Actions */}
        <div className="lg:col-span-8 space-y-4">
          {!sessionDetail ? (
            <div className="glass-panel rounded-2xl p-12 text-center text-slate-500 min-h-[460px] flex items-center justify-center">
              Select a session on the left to inspect its cryptographic audit chain.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Tamper Warning Banner if tampered */}
              {(!sessionDetail.is_valid || tamperMessage) && (
                <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/60 text-rose-300 text-xs flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertOctagon className="w-5 h-5 text-rose-400 flex-shrink-0" />
                    <div>
                      <div className="font-bold">CRYPTOGRAPHIC INTEGRITY FAILURE DETECTED</div>
                      <div className="text-[11px] opacity-90">
                        {sessionDetail.error || tamperMessage?.detected_error || 'Node hash discrepancy detected in audit chain!'}
                      </div>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded bg-rose-500/20 border border-rose-500/40 font-mono font-bold text-[10px]">
                    AUDIT FAILED
                  </span>
                </div>
              )}

              {/* Session Evidence Header */}
              <div className="glass-panel rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-400">Inspecting Session:</span>
                    <span className="font-mono text-sm font-bold text-white">{sessionDetail.session_id}</span>
                  </div>
                  <div className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
                    <span>Merkle Root:</span>
                    <span className="text-indigo-300">{sessionDetail.merkle_root}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleDownloadPack(sessionDetail.session_id)}
                    className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition shadow-md shadow-indigo-500/20"
                  >
                    <Download className="w-4 h-4" />
                    Download Evidence Pack (.zip)
                  </button>

                  <button
                    onClick={handleSimulateTamper}
                    title="Simulate an adversary attempting to alter an event in the database"
                    className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-rose-950/60 hover:text-rose-300 text-slate-300 text-xs border border-slate-700 transition"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                    Simulate Tamper
                  </button>
                </div>
              </div>

              {/* Event Chain Timeline */}
              <div className="glass-panel rounded-xl p-4 space-y-3">
                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                  <span>Sequential SHA-256 Hash Chain ({sessionDetail.events.length} Nodes)</span>
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                    <Key className="w-3 h-3" /> Signed with ECDSA P-256
                  </span>
                </div>

                <div className="space-y-2.5 max-h-[350px] overflow-y-auto pr-1">
                  {sessionDetail.events.map((evt, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/80 space-y-1.5 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-300 flex items-center justify-center font-bold text-[10px]">
                            {evt.sequence}
                          </span>
                          <span className="font-semibold text-slate-200">{evt.event_type}</span>
                        </div>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                          {evt.policy_action}
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-400 pt-1 border-t border-slate-800/60">
                        <div>
                          <span className="text-slate-500">Prev Hash: </span>
                          <span className="truncate">{evt.prev_hash.substring(0, 16)}...</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Node Hash: </span>
                          <span className="text-indigo-300 truncate">{evt.node_hash.substring(0, 16)}...</span>
                        </div>
                      </div>

                      {evt.tokens_mapped.length > 0 && (
                        <div className="text-[10px] text-slate-400 flex items-center gap-1.5 pt-1">
                          <span className="text-slate-500">Tokens:</span>
                          <span className="text-cyan-300">{evt.tokens_mapped.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Offline Verification Snippet */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                <div className="text-slate-400 font-semibold text-[11px] flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                  Independent Offline Verification Command (For DPOs / Regulators):
                </div>
                <div className="font-mono text-emerald-400 bg-slate-900/90 p-2 rounded-lg text-[11px] select-all">
                  uv run chainmark-verify evidence_pack_{sessionDetail.session_id}.zip
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
