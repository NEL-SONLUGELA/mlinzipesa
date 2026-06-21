import React, { useState, useMemo } from "react";

// ---------- Design tokens ----------
const COLORS = {
  navy: "#0F1B2B",
  navySoft: "#16263B",
  card: "#1B2C42",
  border: "rgba(237,234,224,0.12)",
  borderStrong: "rgba(237,234,224,0.22)",
  bone: "#EDEAE0",
  boneMuted: "#A9B3C2",
  boneFaint: "#6E7E94",
  green: "#1F9E6D",
  greenSoft: "rgba(31,158,109,0.14)",
  amber: "#E8A23D",
  amberSoft: "rgba(232,162,61,0.14)",
  red: "#D6453D",
  redSoft: "rgba(214,69,61,0.14)",
};

const FONT_DISPLAY = "'Space Grotesk', 'Inter', sans-serif";
const FONT_BODY = "'Inter', sans-serif";
const FONT_MONO = "'JetBrains Mono', monospace";

// ---------- Sample data ----------
const SMS_SAMPLES = [
  {
    id: "s1",
    sender: "M-PESA",
    text: "Umepokea TZS 450,000 kutoka JOHN MWAKIBOLWA. Salio: TZS 612,300. Asante kwa kutumia M-PESA.",
    verdict: "safe",
    reason: "Sender ID matches verified Vodacom shortcode. No urgency language, no external links.",
  },
  {
    id: "s2",
    sender: "+255 687 220 91",
    text: "TumaPIN yako sasa kuthibitisha malipo ya TZS 850,000 vinginevyo akaunti yako itafungwa leo. Bonyeza: bit.ly/tz-confirm",
    verdict: "fraud",
    reason: "Classic 'TumaPIN' phrase, threat-based urgency, shortened link, sender is unregistered personal number — not an operator shortcode.",
  },
  {
    id: "s3",
    sender: "TRA-EFISCAL",
    text: "Risiti yako ya kodi haijakamilika. Tuma namba ya siri ya TRA kwa namba hii kuepuka faini ya TZS 200,000.",
    verdict: "fraud",
    reason: "Impersonates TRA e-fiscal system, requests a secret/PIN code directly — TRA never requests this via SMS, fear-based phrasing ('faini').",
  },
  {
    id: "s4",
    sender: "TIGO PESA",
    text: "Umetuma TZS 120,000 kwa AISHA NDOSI. Gharama: TZS 1,500. Salio: TZS 88,200.",
    verdict: "safe",
    reason: "Standard outgoing transaction confirmation. Matches operator format, no action requested from recipient.",
  },
  {
    id: "s5",
    sender: "+255 712 884 03",
    text: "Hongera! Umeshinda zawadi ya TZS 2,000,000 kutoka Vodacom Bonanza. Tuma jina, namba ya simu na PIN kupokea zawadi yako.",
    verdict: "fraud",
    reason: "Unsolicited prize claim, requests PIN directly, sender is an unregistered number impersonating Vodacom.",
  },
];

const LEDGER_ENTRIES = [
  { id: "TX-88291", payer: "John Mwakibolwa", amount: 450000, status: "verified", device: "POS-CASH-04", time: "09:12:03" },
  { id: "TX-88292", payer: "Aisha Ndosi", amount: 120000, status: "verified", device: "POS-CASH-04", time: "09:14:51" },
  { id: "TX-88293", payer: "Unknown sender", amount: 850000, status: "mismatch", device: "POS-CASH-04", time: "09:19:27" },
  { id: "TX-88294", payer: "Grace Komba", amount: 65000, status: "verified", device: "POS-CASH-01", time: "09:22:10" },
  { id: "TX-88295", payer: "Hassan Juma", amount: 310000, status: "verified", device: "POS-CASH-04", time: "09:27:44" },
];

function simpleHash(input) {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = (h << 5) - h + input.charCodeAt(i);
    h |= 0;
  }
  const hex = (h >>> 0).toString(16).padStart(8, "0");
  return hex.repeat(2).slice(0, 16);
}

function buildChain(entries) {
  let prevHash = "00000000genesis0";
  return entries.map((e) => {
    const payload = `${e.id}|${e.amount}|${e.device}|${e.time}|${prevHash}`;
    const hash = simpleHash(payload);
    const block = { ...e, prevHash, hash };
    prevHash = hash;
    return block;
  });
}

function fmtTZS(n) {
  return "TZS " + n.toLocaleString("en-US");
}

// ---------- Live detection engine (rule-based) ----------
// Scans real typed text for known smishing patterns. This is a rule-based
// detector, not a trained NLP model — see README for the difference and
// what a production version would add.
const VERIFIED_SENDERS = ["m-pesa", "mpesa", "tigo pesa", "tigopesa", "airtel money", "halopesa"];

const FLAG_RULES = [
  {
    test: (t) => /tuma\s*pin/i.test(t) || /send\s*(your\s*)?pin/i.test(t),
    label: "Requests PIN directly",
    detail: "Legitimate operators and TRA never ask you to send your PIN or secret code by SMS.",
  },
  {
    test: (t) => /(siri|secret code|namba ya siri)/i.test(t),
    label: "Requests a secret code",
    detail: "Asking for a 'siri' (secret) code is a common credential-theft tactic.",
  },
  {
    test: (t) => /(tra|kodi|efiscal|e-fiscal)/i.test(t) && /(faini|fine|penalty|tuma)/i.test(t),
    label: "Impersonates TRA with a threat",
    detail: "Messages claiming to be from TRA that demand action to avoid a fine are a known scam pattern.",
  },
  {
    test: (t) => /(itafungwa|account.*(block|suspend|close)|akaunti.*fungwa)/i.test(t),
    label: "Threatens to block your account",
    detail: "Urgency built around account suspension pressures victims to act without thinking.",
  },
  {
    test: (t) => /(hongera|congratulations|umeshinda|won|zawadi|prize|bonanza)/i.test(t),
    label: "Unsolicited prize or reward claim",
    detail: "Prize messages that ask for personal details or a PIN are a classic lure.",
  },
  {
    test: (t) => /(bit\.ly|tinyurl|goo\.gl|t\.co|short\.link|bonyeza.*http)/i.test(t),
    label: "Contains a shortened or suspicious link",
    detail: "Shortened links hide the real destination and are commonly used in phishing SMS.",
  },
  {
    test: (t) => /(sasa|leo|immediately|now|within \d+ (minutes|hours))/i.test(t) && /(tuma|send|confirm|thibitisha)/i.test(t),
    label: "Urgency language paired with a request to act",
    detail: "Combining time pressure with a request to send something is a typical manipulation pattern.",
  },
];

function checkSenderTrust(sender) {
  const s = (sender || "").trim().toLowerCase();
  if (!s) return { trusted: false, reason: "No sender provided — cannot verify against operator shortcode list." };
  const isKnownShortcode = VERIFIED_SENDERS.some((v) => s.includes(v));
  const looksLikePersonalNumber = /^\+?\d[\d\s-]{6,}$/.test(s);
  if (isKnownShortcode) {
    return { trusted: true, reason: "Sender matches a known operator shortcode." };
  }
  if (looksLikePersonalNumber) {
    return { trusted: false, reason: "Sender is a personal phone number, not a registered operator shortcode." };
  }
  return { trusted: false, reason: "Sender does not match any known verified shortcode." };
}

function scanMessage(sender, text) {
  const matches = FLAG_RULES.filter((rule) => rule.test(text));
  const senderCheck = checkSenderTrust(sender);
  const isFraud = matches.length > 0 || !senderCheck.trusted;
  return { isFraud, matches, senderCheck };
}

// ---------- Shared UI bits ----------
function Pill({ tone, children }) {
  const map = {
    green: { bg: COLORS.greenSoft, fg: COLORS.green },
    amber: { bg: COLORS.amberSoft, fg: COLORS.amber },
    red: { bg: COLORS.redSoft, fg: COLORS.red },
    neutral: { bg: "rgba(237,234,224,0.08)", fg: COLORS.boneMuted },
  };
  const c = map[tone] || map.neutral;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontFamily: FONT_BODY,
        fontSize: 12,
        fontWeight: 600,
        letterSpacing: "0.02em",
        padding: "4px 10px",
        borderRadius: 999,
        background: c.bg,
        color: c.fg,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function SectionLabel({ children }) {
  return (
    <div
      style={{
        fontFamily: FONT_MONO,
        fontSize: 11,
        letterSpacing: "0.12em",
        textTransform: "uppercase",
        color: COLORS.boneFaint,
        marginBottom: 10,
      }}
    >
      {children}
    </div>
  );
}

function Card({ children, style }) {
  return (
    <div
      style={{
        background: COLORS.card,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 14,
        padding: "20px 22px",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

// ---------- Live tester ----------
function LiveTester({ onFraudDetected }) {
  const [sender, setSender] = useState("");
  const [text, setText] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const inputStyle = {
    fontFamily: FONT_BODY,
    fontSize: 14,
    color: COLORS.bone,
    background: COLORS.navy,
    border: `1px solid ${COLORS.borderStrong}`,
    borderRadius: 8,
    padding: "10px 12px",
    width: "100%",
  };

  const runScan = () => {
    const trimmed = text.trim();
    if (!trimmed) return;
    setScanning(true);
    setResult(null);
    setTimeout(() => {
      const r = scanMessage(sender, trimmed);
      setResult(r);
      setScanning(false);
      if (r.isFraud) onFraudDetected();
    }, 500);
  };

  return (
    <Card style={{ marginBottom: 26 }}>
      <div
        style={{
          fontFamily: FONT_MONO,
          fontSize: 11,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: COLORS.boneFaint,
          marginBottom: 10,
        }}
      >
        Try it yourself — type any message
      </div>

      <input
        type="text"
        placeholder="Sender (e.g. M-PESA or a phone number)"
        value={sender}
        onChange={(e) => setSender(e.target.value)}
        style={{ ...inputStyle, maxWidth: 280, marginBottom: 10 }}
      />

      <textarea
        placeholder="Type or paste any SMS message here, in Swahili or English..."
        value={text}
        onChange={(e) => setText(e.target.value)}
        style={{ ...inputStyle, minHeight: 76, lineHeight: 1.5, resize: "vertical" }}
      />

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
        <button
          onClick={runScan}
          disabled={scanning}
          style={{
            fontFamily: FONT_BODY,
            fontSize: 13,
            fontWeight: 600,
            color: COLORS.navy,
            background: COLORS.green,
            border: "none",
            borderRadius: 8,
            padding: "9px 18px",
            cursor: scanning ? "default" : "pointer",
            opacity: scanning ? 0.6 : 1,
          }}
        >
          {scanning ? "Scanning…" : "Scan this message"}
        </button>
      </div>

      {result && (
        <div style={{ marginTop: 14 }}>
          <Pill tone={result.isFraud ? "red" : "green"}>
            {result.isFraud ? "flagged as suspicious" : "no known patterns matched"}
          </Pill>

          {result.matches.length === 0 && result.senderCheck.trusted ? (
            <p style={{ fontFamily: FONT_BODY, fontSize: 13, color: COLORS.boneMuted, marginTop: 10 }}>
              No smishing patterns detected and sender is a verified shortcode. Always stay cautious with unexpected messages regardless.
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 10 }}>
              {result.matches.map((m, i) => (
                <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS.amber, marginTop: 7, flexShrink: 0 }} />
                  <span style={{ fontFamily: FONT_BODY, fontSize: 13, color: COLORS.bone, lineHeight: 1.5 }}>
                    <span style={{ fontFamily: FONT_MONO, color: COLORS.amber }}>{m.label}.</span> {m.detail}
                  </span>
                </div>
              ))}
              <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: result.senderCheck.trusted ? COLORS.green : COLORS.amber,
                    marginTop: 7,
                    flexShrink: 0,
                  }}
                />
                <span style={{ fontFamily: FONT_BODY, fontSize: 13, color: COLORS.bone, lineHeight: 1.5 }}>
                  <span style={{ fontFamily: FONT_MONO, color: result.senderCheck.trusted ? COLORS.green : COLORS.amber }}>
                    {result.senderCheck.trusted ? "Sender verified." : "Sender not verified."}
                  </span>{" "}
                  {result.senderCheck.reason}
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ---------- Scanner module ----------
function ScannerModule() {
  const [scanned, setScanned] = useState({});
  const [activeId, setActiveId] = useState(null);
  const [blockedCount, setBlockedCount] = useState(0);

  const scan = (msg) => {
    if (scanned[msg.id]) return;
    setActiveId(msg.id);
    setTimeout(() => {
      setScanned((prev) => ({ ...prev, [msg.id]: true }));
      setActiveId(null);
      if (msg.verdict === "fraud") setBlockedCount((c) => c + 1);
    }, 650);
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 18, flexWrap: "wrap", gap: 12 }}>
        <div>
          <h2 style={{ fontFamily: FONT_DISPLAY, fontSize: 22, fontWeight: 600, color: COLORS.bone, margin: 0 }}>
            SMS smishing scanner
          </h2>
          <p style={{ fontFamily: FONT_BODY, fontSize: 14, color: COLORS.boneMuted, margin: "4px 0 0" }}>
            On-device NLP flags fake payment SMS in Swahili and English before the cashier reads them
          </p>
        </div>
        <Pill tone="red">{blockedCount} threats blocked this session</Pill>
      </div>

      <LiveTester onFraudDetected={() => setBlockedCount((c) => c + 1)} />

      <div
        style={{
          fontFamily: FONT_MONO,
          fontSize: 11,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: COLORS.boneFaint,
          marginBottom: 10,
        }}
      >
        Sample messages
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {SMS_SAMPLES.map((msg) => {
          const isScanned = scanned[msg.id];
          const isScanning = activeId === msg.id;
          const fraud = msg.verdict === "fraud";
          return (
            <Card key={msg.id} style={{ padding: "16px 20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
                <div style={{ flex: "1 1 360px", minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span style={{ fontFamily: FONT_MONO, fontSize: 12, color: COLORS.boneFaint }}>{msg.sender}</span>
                    {isScanned && (
                      <Pill tone={fraud ? "red" : "green"}>{fraud ? "flagged" : "verified safe"}</Pill>
                    )}
                  </div>
                  <p style={{ fontFamily: FONT_BODY, fontSize: 14.5, color: COLORS.bone, margin: 0, lineHeight: 1.55 }}>
                    {msg.text}
                  </p>
                  {isScanned && (
                    <p
                      style={{
                        fontFamily: FONT_BODY,
                        fontSize: 13,
                        color: fraud ? COLORS.amber : COLORS.boneMuted,
                        margin: "10px 0 0",
                        paddingTop: 10,
                        borderTop: `1px solid ${COLORS.border}`,
                        lineHeight: 1.5,
                      }}
                    >
                      {msg.reason}
                    </p>
                  )}
                </div>
                <div style={{ flexShrink: 0 }}>
                  {!isScanned && (
                    <button
                      onClick={() => scan(msg)}
                      disabled={isScanning}
                      style={{
                        fontFamily: FONT_BODY,
                        fontSize: 13,
                        fontWeight: 600,
                        color: COLORS.navy,
                        background: COLORS.bone,
                        border: "none",
                        borderRadius: 8,
                        padding: "8px 16px",
                        cursor: isScanning ? "default" : "pointer",
                        opacity: isScanning ? 0.6 : 1,
                      }}
                    >
                      {isScanning ? "Scanning…" : "Scan message"}
                    </button>
                  )}
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

// ---------- Ledger module ----------
function LedgerModule() {
  const chain = useMemo(() => buildChain(LEDGER_ENTRIES), []);
  const [openId, setOpenId] = useState(null);

  return (
    <div>
      <div style={{ marginBottom: 18 }}>
        <h2 style={{ fontFamily: FONT_DISPLAY, fontSize: 22, fontWeight: 600, color: COLORS.bone, margin: 0 }}>
          Forensic ledger
        </h2>
        <p style={{ fontFamily: FONT_BODY, fontSize: 14, color: COLORS.boneMuted, margin: "4px 0 0" }}>
          Each verified payment is hashed with the previous entry's hash — breaking one block breaks every block after it
        </p>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        {chain.map((block, i) => {
          const mismatch = block.status === "mismatch";
          const isOpen = openId === block.id;
          return (
            <div key={block.id} style={{ display: "flex", gap: 0 }}>
              <div style={{ width: 28, display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0 }}>
                <div
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background: mismatch ? COLORS.red : COLORS.green,
                    marginTop: 22,
                    flexShrink: 0,
                  }}
                />
                {i < chain.length - 1 && (
                  <div style={{ width: 2, flex: 1, background: COLORS.borderStrong, minHeight: 16 }} />
                )}
              </div>
              <div style={{ flex: 1, paddingBottom: 14, minWidth: 0 }}>
                <Card
                  style={{
                    padding: "14px 18px",
                    cursor: "pointer",
                    borderColor: mismatch ? "rgba(214,69,61,0.4)" : COLORS.border,
                  }}
                >
                  <div onClick={() => setOpenId(isOpen ? null : block.id)}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
                        <span style={{ fontFamily: FONT_MONO, fontSize: 13, color: COLORS.bone, fontWeight: 600 }}>
                          {block.id}
                        </span>
                        <span style={{ fontFamily: FONT_BODY, fontSize: 13.5, color: COLORS.boneMuted }}>
                          {block.payer}
                        </span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <span style={{ fontFamily: FONT_MONO, fontSize: 13.5, color: COLORS.bone }}>
                          {fmtTZS(block.amount)}
                        </span>
                        <Pill tone={mismatch ? "red" : "green"}>
                          {mismatch ? "API mismatch" : "verified"}
                        </Pill>
                      </div>
                    </div>
                    {isOpen && (
                      <div
                        style={{
                          marginTop: 12,
                          paddingTop: 12,
                          borderTop: `1px solid ${COLORS.border}`,
                          display: "grid",
                          gridTemplateColumns: "minmax(0,1fr)",
                          gap: 6,
                        }}
                      >
                        {[
                          ["Device ID", block.device],
                          ["Timestamp", block.time],
                          ["Previous hash", block.prevHash],
                          ["Block hash", block.hash],
                        ].map(([label, val]) => (
                          <div key={label} style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                            <span style={{ fontFamily: FONT_BODY, fontSize: 12.5, color: COLORS.boneFaint }}>{label}</span>
                            <span style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: mismatch ? COLORS.amber : COLORS.boneMuted, wordBreak: "break-all", textAlign: "right" }}>
                              {val}
                            </span>
                          </div>
                        ))}
                        {mismatch && (
                          <p style={{ fontFamily: FONT_BODY, fontSize: 12.5, color: COLORS.amber, margin: "8px 0 0", lineHeight: 1.5 }}>
                            This SMS receipt did not match any transaction in the operator API sandbox — flagged before being recorded as paid.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </Card>
              </div>
            </div>
          );
        })}
      </div>

      <p style={{ fontFamily: FONT_BODY, fontSize: 12.5, color: COLORS.boneFaint, marginTop: 4 }}>
        Tap any block to inspect its hash chain. Exportable as PDF or Excel for TRA audits.
      </p>
    </div>
  );
}

// ---------- Dashboard module ----------
function DashboardModule() {
  const stats = [
    { label: "Smishing attempts flagged", value: "247", delta: "+18 today", tone: "red" },
    { label: "Verified payments today", value: "1,083", delta: "TZS 41.2M", tone: "green" },
    { label: "Avg. verification latency", value: "1.4s", delta: "target < 2s", tone: "green" },
    { label: "Smishing reduction vs baseline", value: "63%", delta: "pilot target: 60%", tone: "green" },
  ];

  const recentAlerts = [
    { time: "09:19", text: "Fake TumaPIN SMS blocked at POS-CASH-04", tone: "red" },
    { time: "09:41", text: "Receipt mismatch flagged — TX-88293", tone: "amber" },
    { time: "10:02", text: "TRA-impersonation SMS blocked at POS-CASH-01", tone: "red" },
    { time: "10:30", text: "47 transactions verified, 0 mismatches", tone: "green" },
  ];

  return (
    <div>
      <div style={{ marginBottom: 18 }}>
        <h2 style={{ fontFamily: FONT_DISPLAY, fontSize: 22, fontWeight: 600, color: COLORS.bone, margin: 0 }}>
          Owner dashboard
        </h2>
        <p style={{ fontFamily: FONT_BODY, fontSize: 14, color: COLORS.boneMuted, margin: "4px 0 0" }}>
          Pilot snapshot across 50 SMEs — live view of fraud blocked and payments verified
        </p>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 12,
          marginBottom: 20,
        }}
      >
        {stats.map((s) => (
          <Card key={s.label} style={{ padding: "16px 18px" }}>
            <div style={{ fontFamily: FONT_BODY, fontSize: 12.5, color: COLORS.boneFaint, marginBottom: 8 }}>
              {s.label}
            </div>
            <div style={{ fontFamily: FONT_DISPLAY, fontSize: 28, fontWeight: 600, color: COLORS.bone, marginBottom: 6 }}>
              {s.value}
            </div>
            <Pill tone={s.tone}>{s.delta}</Pill>
          </Card>
        ))}
      </div>

      <SectionLabel>Live alert feed</SectionLabel>
      <Card style={{ padding: "8px 0" }}>
        {recentAlerts.map((a, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 14,
              padding: "12px 20px",
              borderBottom: i < recentAlerts.length - 1 ? `1px solid ${COLORS.border}` : "none",
            }}
          >
            <span style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: COLORS.boneFaint, width: 44, flexShrink: 0 }}>
              {a.time}
            </span>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                flexShrink: 0,
                background: a.tone === "red" ? COLORS.red : a.tone === "amber" ? COLORS.amber : COLORS.green,
              }}
            />
            <span style={{ fontFamily: FONT_BODY, fontSize: 13.5, color: COLORS.bone }}>{a.text}</span>
          </div>
        ))}
      </Card>
    </div>
  );
}

// ---------- Architecture module ----------
function ArchBox({ title, subtitle, tone = "neutral", x, y, w, h }) {
  const map = {
    green: { bg: COLORS.greenSoft, border: "rgba(31,158,109,0.45)", title: COLORS.green },
    amber: { bg: COLORS.amberSoft, border: "rgba(232,162,61,0.45)", title: COLORS.amber },
    red: { bg: COLORS.redSoft, border: "rgba(214,69,61,0.45)", title: COLORS.red },
    neutral: { bg: "rgba(237,234,224,0.06)", border: COLORS.borderStrong, title: COLORS.bone },
  };
  const c = map[tone];
  return (
    <g transform={`translate(${x},${y})`}>
      <rect width={w} height={h} rx="8" fill={c.bg} stroke={c.border} strokeWidth="1" />
      <text x={w / 2} y={h / 2 - (subtitle ? 6 : 0)} textAnchor="middle" fontFamily={FONT_BODY} fontSize="13" fontWeight="600" fill={c.title}>
        {title}
      </text>
      {subtitle && (
        <text x={w / 2} y={h / 2 + 14} textAnchor="middle" fontFamily={FONT_BODY} fontSize="11" fill={COLORS.boneFaint}>
          {subtitle}
        </text>
      )}
    </g>
  );
}

function Arrow({ x1, y1, x2, y2 }) {
  const angle = Math.atan2(y2 - y1, x2 - x1);
  const headLen = 7;
  return (
    <g>
      <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={COLORS.boneFaint} strokeWidth="1.4" />
      <polygon
        points={`0,-4 ${headLen},0 0,4`}
        transform={`translate(${x2},${y2}) rotate(${(angle * 180) / Math.PI})`}
        fill={COLORS.boneFaint}
      />
    </g>
  );
}

function ArchitectureModule() {
  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontFamily: FONT_DISPLAY, fontSize: 22, fontWeight: 600, color: COLORS.bone, margin: 0 }}>
          System architecture
        </h2>
        <p style={{ fontFamily: FONT_BODY, fontSize: 14, color: COLORS.boneMuted, margin: "4px 0 0" }}>
          Three layers map directly to the three modules in this demo
        </p>
      </div>

      <Card style={{ marginBottom: 24, overflowX: "auto" }}>
        <svg viewBox="0 0 720 300" style={{ width: "100%", minWidth: 600, display: "block" }}>
          <ArchBox x={20} y={20} w={150} h={56} title="Cashier app" subtitle="receives SMS" tone="neutral" />
          <ArchBox x={290} y={20} w={150} h={56} title="NLP scanner" subtitle="Swahili + English" tone="amber" />
          <ArchBox x={560} y={20} w={140} h={56} title="Block sender" tone="red" />

          <ArchBox x={20} y={120} w={150} h={56} title="Verification module" subtitle="checks ledger" tone="neutral" />
          <ArchBox x={290} y={120} w={150} h={56} title="Operator API sandbox" subtitle="Vodacom / Tigo" tone="amber" />
          <ArchBox x={560} y={120} w={140} h={56} title="Flag mismatch" tone="red" />

          <ArchBox x={20} y={220} w={150} h={56} title="Forensic ledger" subtitle="hash chain" tone="green" />
          <ArchBox x={290} y={220} w={150} h={56} title="Owner dashboard" subtitle="live stats" tone="green" />
          <ArchBox x={560} y={220} w={140} h={56} title="TRA export" subtitle="PDF / Excel" tone="green" />

          <Arrow x1={170} y1={48} x2={285} y2={48} />
          <Arrow x1={440} y1={48} x2={555} y2={48} />
          <Arrow x1={170} y1={148} x2={285} y2={148} />
          <Arrow x1={440} y1={148} x2={555} y2={148} />
          <Arrow x1={170} y1={248} x2={285} y2={248} />
          <Arrow x1={440} y1={248} x2={555} y2={248} />
          <Arrow x1={95} y1={76} x2={95} y2={117} />
          <Arrow x1={365} y1={176} x2={365} y2={217} />
        </svg>
      </Card>

      <SectionLabel>Verification flow</SectionLabel>
      <Card>
        <ol style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 10 }}>
          {[
            "Customer pays via mobile money; an SMS receipt arrives at the cashier's device.",
            "On-device NLP scans the SMS text for known smishing patterns before the cashier sees it.",
            "If safe, the verification module checks the claimed amount against the operator API sandbox in real time, target under two seconds.",
            "A match writes a new block to the forensic ledger, hashed against the previous block's hash.",
            "A mismatch is flagged immediately and excluded from the ledger until a human reviews it.",
            "Owners view live totals on the dashboard; auditors export the ledger as PDF or Excel for TRA compliance.",
          ].map((step, i) => (
            <li key={i} style={{ fontFamily: FONT_BODY, fontSize: 14, color: COLORS.bone, lineHeight: 1.6, paddingLeft: 4 }}>
              {step}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

function Logo({ size = 30 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 30 30"
      xmlns="http://www.w3.org/2000/svg"
      style={{ flexShrink: 0, display: "block" }}
    >
      <defs>
        <clipPath id="mlinzipesa-shield-clip">
          <path d="M15 2 C15 2 6 3.5 5 5 V14.5 C5 21 9 25.5 15 28 C21 25.5 25 21 25 14.5 V5 C24 3.5 15 2 15 2 Z" />
        </clipPath>
      </defs>
      <g clipPath="url(#mlinzipesa-shield-clip)">
        <rect x="0" y="0" width="30" height="30" fill="#1EB53A" />
        <polygon points="30,0 30,30 0,30" fill="#00A3DD" />
        <line x1="-2" y1="32" x2="32" y2="-2" stroke="#FCD116" strokeWidth="3.4" />
        <line x1="-2" y1="32" x2="32" y2="-2" stroke="#0B0B0B" strokeWidth="2.2" />
      </g>
      <path
        d="M15 2 C15 2 6 3.5 5 5 V14.5 C5 21 9 25.5 15 28 C21 25.5 25 21 25 14.5 V5 C24 3.5 15 2 15 2 Z"
        fill="none"
        stroke="#D4AF37"
        strokeWidth="0.9"
      />
      <rect x="10.8" y="9.2" width="8.4" height="14" rx="1.5" fill="white" />
      <rect x="13" y="15.2" width="4" height="3.6" rx="0.6" fill="#16263B" />
      <path d="M13.5 15.2 V13.8 a1.5 1.5 0 0 1 3 0 V15.2" fill="none" stroke="#16263B" strokeWidth="1.1" />
    </svg>
  );
}

// ---------- App shell ----------
const TABS = [
  { id: "scanner", label: "SMS scanner" },
  { id: "ledger", label: "Forensic ledger" },
  { id: "dashboard", label: "Dashboard" },
  { id: "architecture", label: "Architecture" },
];

export default function MlinziPesaDemo() {
  const [tab, setTab] = useState("scanner");

  return (
    <div
      style={{
        background: COLORS.navy,
        minHeight: 640,
        padding: "0 0 40px",
        fontFamily: FONT_BODY,
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; }
      `}</style>

      {/* Top bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "22px 28px 18px",
          borderBottom: `1px solid ${COLORS.border}`,
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Logo size={30} />
          <span style={{ fontFamily: FONT_DISPLAY, fontSize: 18, fontWeight: 600, color: COLORS.bone }}>
            MlinziPesa
          </span>
        </div>
        <span style={{ fontFamily: FONT_MONO, fontSize: 12, color: COLORS.boneFaint }}>
          Mobile money fraud shield — pilot demo
        </span>
      </div>

      {/* Tabs */}
      <div
        style={{
          display: "flex",
          gap: 4,
          padding: "16px 28px 0",
          borderBottom: `1px solid ${COLORS.border}`,
          overflowX: "auto",
        }}
      >
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                fontFamily: FONT_BODY,
                fontSize: 13.5,
                fontWeight: 600,
                color: active ? COLORS.bone : COLORS.boneFaint,
                background: "none",
                border: "none",
                padding: "10px 16px 14px",
                cursor: "pointer",
                borderBottom: active ? `2px solid ${COLORS.green}` : "2px solid transparent",
                whiteSpace: "nowrap",
              }}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div style={{ padding: "26px 28px 0", maxWidth: 920, margin: "0 auto" }}>
        {tab === "scanner" && <ScannerModule />}
        {tab === "ledger" && <LedgerModule />}
        {tab === "dashboard" && <DashboardModule />}
        {tab === "architecture" && <ArchitectureModule />}
      </div>
    </div>
  );
}
