import React from 'react';
import { ShieldCheck, Scale, Award, FileText, CheckCircle2 } from 'lucide-react';

export default function ComplianceMatrix() {
  const frameworks = [
    {
      name: 'Digital Personal Data Protection Act (DPDP India 2026)',
      penalty: 'Up to ₹250 Crore penalty protection',
      rule: 'Section 8 & Rule 4 Mandates',
      status: '100% Compliant',
      features: [
        'Aadhaar (Verhoeff) & PAN checksum verification',
        'Multi-turn jigsaw fragment joining prevention',
        'Signed cryptographic evidence packs ready for DPO submission',
      ],
    },
    {
      name: 'HIPAA Safe Harbor & Clinical Trials (US)',
      penalty: 'Up to $2,000,000 annual penalty protection',
      rule: '45 CFR § 164.514(b) & ICH GCP',
      status: '100% Compliant',
      features: [
        '18 HIPAA identifiers stripped before cloud LLM egress',
        'Medical Record Number (MRN) and oncology chart protection',
        'Clinical trial recruitment agent privacy guard',
      ],
    },
    {
      name: 'FDA 21 CFR Part 11 (Electronic Records & Signatures)',
      penalty: 'Regulatory clinical trial disqualification defense',
      rule: '21 CFR § 11.10(e) Audit Trails',
      status: '100% Compliant',
      features: [
        'Computer-generated, time-stamped immutable audit trails',
        'ECDSA P-256 digital signatures on all transaction batches',
        'Air-gapped offline verifier CLI for FDA and IRB auditors',
      ],
    },
  ];

  return (
    <div className="glass-panel rounded-2xl p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Scale className="w-5 h-5 text-indigo-400" />
            Regulatory Defense & Compliance Matrix
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            How Chainmark transforms ephemeral developer logs into legally admissible, tamper-evident testimony.
          </p>
        </div>

        <span className="px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          3 / 3 Frameworks Active
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
        {frameworks.map((fw, idx) => (
          <div key={idx} className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold text-indigo-300">{fw.rule}</span>
              <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-semibold">
                <CheckCircle2 className="w-3.5 h-3.5" /> {fw.status}
              </span>
            </div>

            <div>
              <div className="font-bold text-sm text-slate-100">{fw.name}</div>
              <div className="text-xs text-rose-400 font-medium mt-0.5">{fw.penalty}</div>
            </div>

            <ul className="space-y-1.5 pt-2 border-t border-slate-800/80">
              {fw.features.map((feat, fIdx) => (
                <li key={fIdx} className="text-xs text-slate-400 flex items-start gap-1.5">
                  <span className="text-indigo-400 text-[10px] mt-0.5">▸</span>
                  <span>{feat}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
