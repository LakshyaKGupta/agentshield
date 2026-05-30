import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

/* ─── animation variants ─────────────────────────────── */
const fadeUp = (delay = 0) => ({
  initial:    { opacity: 0, y: 20 },
  animate:    { opacity: 1, y: 0 },
  transition: { duration: 0.65, delay, ease: [0.16, 1, 0.3, 1] },
});

const fadeIn = (delay = 0) => ({
  initial:    { opacity: 0 },
  animate:    { opacity: 1 },
  transition: { duration: 0.7, delay, ease: "easeOut" },
});

/* ─── mock dashboard preview ────────────────────────── */
const EVENTS = [
  { id: 1024, verdict: "BLOCKED", agent: "ResearchAgent", tool: "file.write",   sev: "HIGH" },
  { id: 1025, verdict: "ALLOWED", agent: "MonitorAgent",  tool: "api.call",     sev: "LOW"  },
  { id: 1026, verdict: "FLAGGED", agent: "DataAgent",     tool: "db.query",     sev: "MED"  },
  { id: 1027, verdict: "ALLOWED", agent: "PipelineAgent", tool: "web.search",   sev: "LOW"  },
  { id: 1028, verdict: "BLOCKED", agent: "ExecAgent",     tool: "shell.exec",   sev: "CRIT" },
];

const VERDICT_COLOR: Record<string, string> = {
  BLOCKED: "#DC2626",
  ALLOWED: "#16A34A",
  FLAGGED: "#D97706",
};
const VERDICT_BG: Record<string, string> = {
  BLOCKED: "#FEF2F2",
  ALLOWED: "#F0FDF4",
  FLAGGED: "#FFFBEB",
};

function ProductPreview() {
  return (
    <div style={{
      background: "#FFFFFF",
      border: "1px solid #E8E6E0",
      borderRadius: 16,
      overflow: "hidden",
      boxShadow: "0 0 0 1px rgba(0,0,0,.04), 0 32px 80px rgba(0,0,0,.10), 0 8px 20px rgba(0,0,0,.05)",
      width: "100%",
      userSelect: "none",
    }}>
      {/* Window chrome */}
      <div style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "12px 16px", background: "#FAFAF8",
        borderBottom: "1px solid #E8E6E0",
      }}>
        <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FF5F57", display: "block" }}/>
        <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#FEBC2E", display: "block" }}/>
        <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#28C840", display: "block" }}/>
        <span style={{ flex: 1, textAlign: "center", fontSize: 12, fontWeight: 600, color: "#9B9B9D", fontFamily: "Inter, sans-serif", letterSpacing: "-.01em" }}>
          AgentShield · Security Console
        </span>
        <span style={{
          display: "inline-flex", alignItems: "center", gap: 5,
          padding: "3px 9px", borderRadius: 99,
          background: "#F0FDF4", border: "1px solid #BBF7D0",
          fontSize: 11, fontWeight: 700, color: "#16A34A", fontFamily: "Inter, sans-serif"
        }}>
          <span style={{ width: 5, height: 5, borderRadius: "50%", background: "#16A34A", display: "inline-block", animation: "pulse-dot 2s ease-in-out infinite" }}/>
          Live
        </span>
      </div>

      {/* Body */}
      <div style={{ display: "flex", minHeight: 320 }}>
        {/* Sidebar */}
        <div style={{
          width: 180, flexShrink: 0,
          background: "#FAFAF8", borderRight: "1px solid #E8E6E0",
          padding: "16px 12px", display: "flex", flexDirection: "column", gap: 2,
        }}>
          {[
            { icon: "🛡", label: "Dashboard", active: true },
            { icon: "🤖", label: "Agents",    active: false },
            { icon: "📋", label: "Ledger",    active: false },
            { icon: "⚡", label: "Attack Sim", active: false },
          ].map(item => (
            <div key={item.label} style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "8px 10px", borderRadius: 8,
              background: item.active ? "#F0F0EE" : "transparent",
              fontSize: 13, fontWeight: item.active ? 600 : 500,
              color: item.active ? "#111" : "#6B6B6D",
              fontFamily: "Inter, sans-serif",
            }}>
              <span style={{ fontSize: 14 }}>{item.icon}</span>
              {item.label}
            </div>
          ))}
          <div style={{ marginTop: "auto", paddingTop: 16, borderTop: "1px solid #E8E6E0", display: "flex", flexDirection: "column", gap: 6 }}>
            {[
              { label: "Events",  val: "2,847" },
              { label: "Threats", val: "12" },
              { label: "Agents",  val: "6 active" },
            ].map(m => (
              <div key={m.label} style={{ padding: "6px 10px" }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "#9B9B9D", textTransform: "uppercase", letterSpacing: ".06em", fontFamily: "Inter, sans-serif" }}>{m.label}</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: "#111", letterSpacing: "-.025em", fontFamily: "Inter, sans-serif" }}>{m.val}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1, padding: "16px 20px", minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <span style={{ fontSize: 14, fontWeight: 700, color: "#111", letterSpacing: "-.015em", fontFamily: "Inter, sans-serif" }}>Event Feed</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: "#9B9B9D", fontFamily: "Inter, sans-serif" }}>Last 5 events</span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {EVENTS.map((e, i) => (
              <motion.div
                key={e.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.4, delay: 0.9 + i * 0.08, ease: [0.16,1,.3,1] }}
                style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "8px 12px", borderRadius: 8,
                  background: "#FAFAF8", border: "1px solid #E8E6E0",
                  borderLeft: `3px solid ${VERDICT_COLOR[e.verdict]}`,
                  fontFamily: "Inter, sans-serif",
                }}>
                <span style={{
                  padding: "2px 8px", borderRadius: 99,
                  fontSize: 10, fontWeight: 800, letterSpacing: ".04em",
                  background: VERDICT_BG[e.verdict], color: VERDICT_COLOR[e.verdict],
                  flexShrink: 0, fontFamily: "Inter, sans-serif",
                }}>{e.verdict}</span>
                <span style={{ fontSize: 13, fontWeight: 600, color: "#111", fontFamily: "Inter, sans-serif" }}>{e.agent}</span>
                <span style={{ fontSize: 12, color: "#9B9B9D", flex: 1, fontFamily: "ui-monospace, monospace" }}>{e.tool}</span>
                <span style={{ fontSize: 11, color: "#C4C4C6", fontFamily: "Inter, sans-serif" }}>#{e.id}</span>
              </motion.div>
            ))}
          </div>

          {/* Chain footer */}
          <motion.div
            {...fadeIn(1.5)}
            style={{
              marginTop: 14, padding: "10px 14px", borderRadius: 8,
              background: "#F0FDF4", border: "1px solid #BBF7D0",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              fontFamily: "Inter, sans-serif",
            }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "#16A34A" }}>✓ Chain verified — 2,847 entries, 0 broken</span>
            <span style={{ fontSize: 11, color: "#9B9B9D" }}>avg 142ms</span>
          </motion.div>
        </div>
      </div>
    </div>
  );
}

/* ─── floating glass cards ──────────────────────────── */
interface GlassCardProps {
  children: React.ReactNode;
  style?: React.CSSProperties;
  floatDelay?: number;
}
function GlassCard({ children, style = {}, floatDelay = 0 }: GlassCardProps) {
  return (
    <motion.div
      animate={{ y: [0, -8, 0] }}
      transition={{ duration: 4 + floatDelay, repeat: Infinity, ease: "easeInOut", delay: floatDelay }}
      style={{
        position: "absolute",
        background: "rgba(255,255,255,0.92)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        border: "1px solid rgba(0,0,0,.07)",
        borderRadius: 14,
        boxShadow: "0 8px 32px rgba(0,0,0,.07), 0 2px 8px rgba(0,0,0,.04)",
        padding: "12px 16px",
        display: "flex", alignItems: "center", gap: 10,
        fontFamily: "Inter, sans-serif",
        zIndex: 2,
        whiteSpace: "nowrap",
        ...style,
      }}>
      {children}
    </motion.div>
  );
}

/* ─── LOGOS ─────────────────────────────────────────── */
const LOGOS = ["Acme AI","NeuralOps","FlowLabs","Axiom","Synthex","DataMesh","CoreAI","PulseML","Vertex","Echo AI"];

/* ─── HERO ──────────────────────────────────────────── */
export default function Hero({ setView }: { setView: (v: string) => void }) {
  const [chatVal, setChatVal] = useState("");

  return (
    <section style={{
      position: "relative",
      minHeight: "100vh",
      background: "#FAFAF8",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      overflow: "hidden",
      paddingTop: 60, // nav height
    }}>
      {/* Subtle background grid */}
      <div aria-hidden="true" style={{
        position: "absolute", inset: 0, zIndex: 0,
        backgroundImage: "radial-gradient(circle, rgba(0,0,0,.045) 1px, transparent 1px)",
        backgroundSize: "28px 28px",
        maskImage: "radial-gradient(ellipse 80% 80% at 50% 50%, black 30%, transparent 100%)",
        WebkitMaskImage: "radial-gradient(ellipse 80% 80% at 50% 50%, black 30%, transparent 100%)",
        pointerEvents: "none",
      }}/>

      {/* Very subtle top glow */}
      <div aria-hidden="true" style={{
        position: "absolute", top: -60, left: "50%", transform: "translateX(-50%)",
        width: 900, height: 400,
        background: "radial-gradient(ellipse, rgba(99,102,241,.06) 0%, transparent 70%)",
        filter: "blur(40px)", zIndex: 0, pointerEvents: "none",
      }}/>

      {/* ── Above-fold copy ────────────────────────────── */}
      <div style={{
        position: "relative", zIndex: 1,
        display: "flex", flexDirection: "column", alignItems: "center",
        textAlign: "center",
        padding: "72px clamp(20px,5vw,56px) 48px",
        width: "100%",
      }}>
        {/* Badge */}
        <motion.div {...fadeUp(0)}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            padding: "6px 14px", borderRadius: 999,
            background: "#FFFFFF",
            border: "1px solid #E8E6E0",
            boxShadow: "0 1px 4px rgba(0,0,0,.05)",
            fontSize: 12.5, fontWeight: 600, color: "#555558",
            fontFamily: "Inter, sans-serif", letterSpacing: "-.01em",
            marginBottom: 28,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#16A34A", flexShrink: 0, boxShadow: "0 0 6px rgba(22,163,74,.5)" }}/>
            Deterministic AI agent security — v1.0
          </div>
        </motion.div>

        {/* H1 */}
        <motion.h1 {...fadeUp(0.1)} style={{
          fontFamily: "'Playfair Display', Georgia, serif",
          fontSize: "clamp(48px, 7.5vw, 86px)",
          fontWeight: 300, letterSpacing: "-.045em", lineHeight: 1.02,
          color: "#111111", margin: "0 0 24px",
          maxWidth: 860,
        }}>
          The security layer<br/>every <em style={{ fontStyle: "italic" }}>AI agent</em> needs
        </motion.h1>

        {/* Subtitle */}
        <motion.p {...fadeUp(0.18)} style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "clamp(15px,1.5vw,18px)", lineHeight: 1.75,
          color: "#555558", maxWidth: 520,
          margin: "0 0 36px",
        }}>
          Identity verification, permission enforcement, and tamper-evident audit —
          synchronous protection on every message and tool call.
        </motion.p>

        {/* CTAs */}
        <motion.div {...fadeUp(0.26)} style={{ display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center" }}>
          <button
            onClick={() => setView("signup")}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.opacity = ".84"; (e.currentTarget as HTMLButtonElement).style.transform = "translateY(-2px)"; }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.opacity = "1"; (e.currentTarget as HTMLButtonElement).style.transform = "translateY(0)"; }}
            style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              padding: "14px 28px", borderRadius: 999,
              background: "#111111", color: "#fff",
              border: "none", fontSize: 15, fontWeight: 600,
              fontFamily: "Inter, sans-serif", letterSpacing: "-.01em",
              boxShadow: "0 4px 12px rgba(17,17,17,.18)",
              cursor: "none", transition: "all 200ms ease",
            }}>
            Create workspace →
          </button>
          <button
            onClick={() => setView("product")}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(17,17,17,.04)"; (e.currentTarget as HTMLButtonElement).style.transform = "translateY(-1px)"; }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = "#fff"; (e.currentTarget as HTMLButtonElement).style.transform = "translateY(0)"; }}
            style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              padding: "14px 24px", borderRadius: 999,
              background: "#fff", color: "#111",
              border: "1.5px solid #E8E6E0", fontSize: 15, fontWeight: 600,
              fontFamily: "Inter, sans-serif", letterSpacing: "-.01em",
              cursor: "none", transition: "all 200ms ease",
            }}>
            See how it works
          </button>
        </motion.div>
      </div>

      {/* ── Product preview + floating cards ─────────── */}
      <motion.div
        initial={{ opacity: 0, y: 48, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.85, delay: 0.38, ease: [0.16, 1, 0.3, 1] }}
        style={{
          position: "relative", zIndex: 1,
          width: "100%", maxWidth: 900,
          padding: "0 clamp(20px,5vw,56px)",
          marginBottom: 120, // space for logo ticker
        }}>

        {/* Floating card — top left */}
        <GlassCard floatDelay={0} style={{ top: -18, left: "clamp(0px,4%,48px)" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#DC2626", flexShrink: 0 }}/>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#111" }}>Injection blocked</div>
            <div style={{ fontSize: 11, color: "#9B9B9D" }}>POLICY_DENIED · 142ms</div>
          </div>
        </GlassCard>

        {/* Floating card — top right */}
        <GlassCard floatDelay={1.2} style={{ top: -18, right: "clamp(0px,4%,48px)" }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#16A34A", flexShrink: 0 }}/>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#111" }}>Chain verified</div>
            <div style={{ fontSize: 11, color: "#9B9B9D" }}>2,847 entries · SHA-256</div>
          </div>
        </GlassCard>

        {/* Floating card — bottom right */}
        <GlassCard floatDelay={0.7} style={{ bottom: -18, right: "clamp(0px,4%,48px)", zIndex: 3 }}>
          <span style={{ fontSize: 16 }}>🛡</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#111" }}>Trust score</div>
            <div style={{ fontSize: 11, color: "#16A34A", fontWeight: 700 }}>0.94 — Excellent</div>
          </div>
        </GlassCard>

        {/* The preview card */}
        <ProductPreview />
      </motion.div>

      {/* ── Logo ticker ──────────────────────────────── */}
      <div style={{
        position: "absolute", bottom: 0, left: 0, right: 0,
        borderTop: "1px solid #E8E6E0",
        background: "rgba(250,250,248,.9)",
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
        padding: "14px 0",
        zIndex: 2,
      }}>
        <p style={{
          textAlign: "center", fontSize: 11, fontWeight: 700,
          letterSpacing: ".1em", textTransform: "uppercase",
          color: "#9B9B9D", marginBottom: 10,
          fontFamily: "Inter, sans-serif",
        }}>Trusted by teams building autonomous systems</p>
        <div style={{
          overflow: "hidden",
          maskImage: "linear-gradient(to right, transparent, black 10%, black 90%, transparent)",
          WebkitMaskImage: "linear-gradient(to right, transparent, black 10%, black 90%, transparent)",
        }}>
          <motion.div
            animate={{ x: [0, -1200] }}
            transition={{ duration: 28, repeat: Infinity, ease: "linear" }}
            style={{ display: "flex", gap: 0, width: "max-content" }}>
            {[...Array(3)].flatMap(() => LOGOS.map((n, i) => (
              <span key={`${n}-${i}`} style={{
                padding: "0 32px", fontSize: 14, fontWeight: 700,
                letterSpacing: "-.01em", color: "#111", opacity: .18,
                whiteSpace: "nowrap", fontFamily: "Inter, sans-serif",
              }}>{n}</span>
            )))}
          </motion.div>
        </div>
      </div>

      {/* Inline keyframe for the green dot pulse */}
      <style>{`
        @keyframes pulse-dot {
          0%,100%{ opacity:1; transform:scale(1); }
          50%{ opacity:.5; transform:scale(1.5); }
        }
      `}</style>
    </section>
  );
}
