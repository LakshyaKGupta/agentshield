import React from "react";
import { motion } from "framer-motion";
import HeroWave from "./HeroOrb";

/* ─── animation helpers ──────────────────────────────── */
const fadeUp = (delay = 0) => ({
  initial:    { opacity: 0, y: 22 },
  animate:    { opacity: 1, y: 0  },
  transition: { duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] },
});

/* ─── inline SVG icons ───────────────────────────────── */
function IconShield() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
}
function IconLock() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>;
}
function IconZap() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>;
}
function IconEye() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>;
}
function IconKey() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l-1 1M18.5 4.5l-1 1"/></svg>;
}
function IconLink() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>;
}
function IconCheck() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>;
}
function IconDatabase() {
  return <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>;
}

/* ─── floating icon positions ─────────────────────────── */
interface FloatIcon { Icon: React.FC; x: string; y: string; delay: number; color: string; dur: number; rotateRange: number }
const FLOAT_ICONS: FloatIcon[] = [
  { Icon: IconShield,   x: "10%",  y: "20%", delay: 0,   color: "#818cf8", dur: 5.0, rotateRange: 8  },
  { Icon: IconLock,     x: "84%",  y: "18%", delay: 0.8, color: "#38bdf8", dur: 6.2, rotateRange: -6 },
  { Icon: IconZap,      x: "6%",   y: "62%", delay: 1.6, color: "#34d399", dur: 5.5, rotateRange: 10 },
  { Icon: IconEye,      x: "88%",  y: "55%", delay: 0.4, color: "#a78bfa", dur: 4.8, rotateRange: -9 },
  { Icon: IconKey,      x: "16%",  y: "76%", delay: 1.2, color: "#7dd3fc", dur: 5.8, rotateRange: 7  },
  { Icon: IconLink,     x: "80%",  y: "72%", delay: 2.0, color: "#6ee7b7", dur: 6.0, rotateRange: -7 },
  { Icon: IconCheck,    x: "50%",  y: "12%", delay: 0.6, color: "#f9a8d4", dur: 5.3, rotateRange: 5  },
  { Icon: IconDatabase, x: "40%",  y: "78%", delay: 1.8, color: "#93c5fd", dur: 4.6, rotateRange: -8 },
];

/* ─── logo list ──────────────────────────────────────── */
const LOGOS = ["Acme AI","NeuralOps","FlowLabs","Axiom","Synthex","DataMesh","CoreAI","PulseML","Vertex","Echo AI"];

/* ─── HERO ──────────────────────────────────────────── */
export default function Hero({ setView, authenticated = false }: { setView: (v: string) => void; authenticated?: boolean }) {
  return (
    <section style={{
      position: "relative",
      height: "100vh", minHeight: 680,
      background: "#FAFAF8",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      overflow: "hidden",
      paddingTop: 60, /* nav height */
    }}>
      {/* ── Wave canvas (bottom layer) ─────────────────── */}
      <HeroWave />

      {/* ── Floating animated icons ────────────────────── */}
      {FLOAT_ICONS.map(({ Icon, x, y, delay, color, dur, rotateRange }, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, scale: 0.6 }}
          animate={{
            opacity:  [0, 0.18, 0.22, 0.18],
            scale:    [0.6, 1, 1, 1],
            y:        [0, -14, 0, 14, 0],
            rotate:   [0, rotateRange, 0, -rotateRange, 0],
          }}
          transition={{
            duration: dur,
            repeat:   Infinity,
            ease:     "easeInOut",
            delay,
            times:    [0, 0.25, 0.5, 0.75, 1],
          }}
          style={{
            position:  "absolute",
            left: x, top: y,
            color,
            zIndex:    1,
            pointerEvents: "none",
            filter:    "drop-shadow(0 2px 8px currentColor)",
          }}
        >
          <Icon />
        </motion.div>
      ))}

      {/* ── Subtle dot-grid overlay ─────────────────────── */}
      <div aria-hidden="true" style={{
        position: "absolute", inset: 0, zIndex: 0,
        backgroundImage: "radial-gradient(circle, rgba(0,0,0,.04) 1px, transparent 1px)",
        backgroundSize: "28px 28px",
        maskImage: "radial-gradient(ellipse 75% 75% at 50% 40%, black, transparent)",
        WebkitMaskImage: "radial-gradient(ellipse 75% 75% at 50% 40%, black, transparent)",
        pointerEvents: "none",
      }}/>

      {/* ── Main centered copy ─────────────────────────── */}
      <div style={{
        position: "relative", zIndex: 2,
        display: "flex", flexDirection: "column", alignItems: "center",
        textAlign: "center",
        padding: "80px clamp(20px,5vw,56px) 48px",
        width: "100%", maxWidth: 960, margin: "0 auto",
        gap: 0,
      }}>
        {/* H1 */}
        <motion.h1 {...fadeUp(0.05)} style={{
          fontFamily: "'Playfair Display', Georgia, serif",
          fontSize: "clamp(50px, 8vw, 92px)",
          fontWeight: 300,
          letterSpacing: "-.045em",
          lineHeight: 1.02,
          color: "#111111",
          margin: "0 0 26px",
          maxWidth: 860,
        }}>
          The security layer<br/>every <em style={{ fontStyle: "italic" }}>AI agent</em> needs
        </motion.h1>

        {/* Subtitle */}
        <motion.p {...fadeUp(0.16)} style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "clamp(15px,1.5vw,18px)",
          lineHeight: 1.76,
          color: "#555558",
          maxWidth: 520,
          margin: "0 0 38px",
        }}>
          Identity verification, permission enforcement, and tamper-evident audit —
          synchronous protection on every message and tool call.
        </motion.p>

        {/* CTAs */}
        <motion.div {...fadeUp(0.24)} style={{
          display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center",
        }}>
          <button
            onClick={() => setView(authenticated ? "app" : "signup")}
            onMouseEnter={e => Object.assign((e.currentTarget as HTMLElement).style, { opacity: ".82", transform: "translateY(-2px)" })}
            onMouseLeave={e => Object.assign((e.currentTarget as HTMLElement).style, { opacity: "1", transform: "translateY(0)" })}
            style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              padding: "14px 30px", borderRadius: 999,
              background: "#111111", color: "#fff", border: "none",
              fontSize: 15, fontWeight: 600, fontFamily: "Inter, sans-serif",
              letterSpacing: "-.01em",
              boxShadow: "0 4px 14px rgba(17,17,17,.2)",
              cursor: "none", transition: "all 200ms ease",
            }}>
            {authenticated ? "Go to Console →" : "Create workspace →"}
          </button>

          <button
            onClick={() => setView("product")}
            onMouseEnter={e => Object.assign((e.currentTarget as HTMLElement).style, { background: "rgba(17,17,17,.04)", transform: "translateY(-1px)" })}
            onMouseLeave={e => Object.assign((e.currentTarget as HTMLElement).style, { background: "#fff", transform: "translateY(0)" })}
            style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              padding: "14px 24px", borderRadius: 999,
              background: "#fff", color: "#111", fontSize: 15, fontWeight: 600,
              fontFamily: "Inter, sans-serif", letterSpacing: "-.01em",
              border: "1.5px solid #E8E6E0",
              cursor: "none", transition: "all 200ms ease",
            }}>
            See how it works
          </button>
        </motion.div>
      </div>

      {/* ── Logo ticker strip (absolute bottom) ─────────── */}
      <div style={{
        position: "absolute", bottom: 0, left: 0, right: 0, zIndex: 3,
        borderTop: "1px solid rgba(232,230,224,.9)",
        background: "rgba(250,250,248,.88)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        padding: "12px 0",
      }}>
        <p style={{
          textAlign: "center", fontSize: 10.5, fontWeight: 700,
          letterSpacing: ".12em", textTransform: "uppercase",
          color: "#9B9B9D", marginBottom: 9,
          fontFamily: "Inter, sans-serif",
        }}>Trusted by teams building autonomous AI</p>
        <div style={{
          overflow: "hidden",
          maskImage: "linear-gradient(to right, transparent, black 12%, black 88%, transparent)",
          WebkitMaskImage: "linear-gradient(to right, transparent, black 12%, black 88%, transparent)",
        }}>
          <motion.div
            animate={{ x: [0, -1200] }}
            transition={{ duration: 26, repeat: Infinity, ease: "linear" }}
            style={{ display: "flex", width: "max-content" }}>
            {[...Array(3)].flatMap(() => LOGOS.map((n, i) => (
              <span key={`${n}-${i}`} style={{
                padding: "0 28px", fontSize: 13.5, fontWeight: 700,
                letterSpacing: "-.01em", color: "#111", opacity: .17,
                whiteSpace: "nowrap", fontFamily: "Inter, sans-serif",
              }}>{n}</span>
            )))}
          </motion.div>
        </div>
      </div>
    </section>
  );
}
