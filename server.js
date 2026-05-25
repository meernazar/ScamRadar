/* ScamRadar - standalone Express server */
const path = require("path");
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---------- Gemini ----------
async function callGemini(systemPrompt, parts) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY is not configured");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: "user", parts }],
      generationConfig: { responseMimeType: "application/json", temperature: 0.2 },
    }),
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`AI error ${res.status}: ${txt.slice(0, 300)}`);
  }
  const json = await res.json();
  const text = json?.candidates?.[0]?.content?.parts?.[0]?.text ?? "{}";
  try {
    return JSON.parse(text);
  } catch {
    const m = text.match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : {};
  }
}

// ---------- URL intelligence ----------
async function checkVirusTotal(target) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { error: "VirusTotal not configured" };
  try {
    const id = Buffer.from(target).toString("base64")
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": key },
    });
    if (res.status === 404) {
      const form = new URLSearchParams({ url: target });
      await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { "x-apikey": key, "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
    }
    if (!res.ok) return { error: `VT ${res.status}` };
    const json = await res.json();
    const s = json?.data?.attributes?.last_analysis_stats ?? {};
    return {
      malicious: s.malicious ?? 0,
      suspicious: s.suspicious ?? 0,
      harmless: s.harmless ?? 0,
      undetected: s.undetected ?? 0,
    };
  } catch (e) {
    return { error: e.message || "VT failed" };
  }
}

async function checkSafeBrowsing(target) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return { error: "Safe Browsing not configured" };
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "scamradar", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: target }],
          },
        }),
      }
    );
    if (!res.ok) return { error: `SafeBrowsing ${res.status}` };
    const json = await res.json();
    const threats = (json?.matches ?? []).map((m) => m.threatType);
    return { threats };
  } catch (e) {
    return { error: e.message || "SafeBrowsing failed" };
  }
}

// ---------- Endpoints ----------
app.post("/api/scan", async (req, res) => {
  try {
    const { mode, content, imageMimeType, deep } = req.body || {};
    if (!["text", "url", "image"].includes(mode)) {
      return res.status(400).json({ error: "Invalid mode" });
    }
    if (!content || typeof content !== "string") {
      return res.status(400).json({ error: "Missing content" });
    }

    let urlIntel = null;
    if (mode === "url") {
      const [vt, sb] = await Promise.all([checkVirusTotal(content), checkSafeBrowsing(content)]);
      urlIntel = { virusTotal: vt, safeBrowsing: sb };
    }

    const sys = `You are ScamRadar, an expert scam detection analyst. Analyze the provided ${
      mode === "url" ? "URL (with security scanner findings)" :
      mode === "image" ? "screenshot image — first read ALL visible text/UI in the image, then judge whether it is a scam" :
      "message text"
    } and return ONLY a strict JSON object matching this schema (no markdown, no commentary):

{
  "verdict": "SCAM" | "LIKELY SCAM" | "SUSPICIOUS" | "LOOKS LEGIT",
  "confidence": number 0-100,
  "scamType": "short label e.g. Phishing, Romance Scam, Crypto Investment, Lottery, Tech Support, Impersonation, Malware, None",
  "summary": "2-3 sentence professional summary",
  "redFlags": [{ "severity": "high"|"medium"|"low", "flag": "short label", "explanation": "concise explanation" }],
  "advice": ["actionable security recommendation", ...]
}

${deep ? "Perform DEEP analysis: examine linguistic patterns, urgency cues, social engineering tactics, technical indicators, sender legitimacy." : ""}
If LOOKS LEGIT, redFlags may be an empty array.`;

    let parts;
    if (mode === "image") {
      const match = content.match(/^data:([^;]+);base64,(.+)$/);
      const mime = match?.[1] || imageMimeType || "image/png";
      const b64 = match?.[2] || content;
      parts = [
        { text: "Analyze this screenshot for signs of a scam. Read all visible text, sender info, links, and UI cues, then return the JSON verdict." },
        { inline_data: { mime_type: mime, data: b64 } },
      ];
    } else if (mode === "url") {
      parts = [{
        text: `URL: ${content}\n\nSecurity scanner findings:\n${JSON.stringify(urlIntel, null, 2)}\n\nFactor these findings heavily into the verdict. Any VirusTotal malicious/suspicious detections or Safe Browsing threat matches should push toward SCAM/LIKELY SCAM.`,
      }];
    } else {
      parts = [{ text: `Message to analyze:\n\n${content}` }];
    }

    const result = await callGemini(sys, parts);
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Scan failed" });
  }
});

app.post("/api/simplify", async (req, res) => {
  try {
    const { result } = req.body || {};
    if (!result) return res.status(400).json({ error: "Missing result" });

    const sys = `Rewrite a scam-detection result in very simple, plain English for an elderly reader. Return ONLY JSON:

{
  "verdictLabel": "one of: 'THIS IS A SCAM — Delete immediately' (for SCAM or LIKELY SCAM), 'BE CAREFUL — Something feels off' (for SUSPICIOUS), 'LOOKS SAFE — Stay alert' (for LOOKS LEGIT)",
  "summary": "ONE short, plain-language sentence. Avoid jargon.",
  "redFlags": [{ "severity": "high|medium|low", "flag": "very short label", "explanation": "one short simple sentence" }],
  "advice": ["short bullet starting with an action word like Delete, Block, Call, Do not, Tell, Check", ...]
}

Use words a 75-year-old would understand. No technical terms.`;

    const userContent = `Original verdict: ${result.verdict}
Scam type: ${result.scamType}
Summary: ${result.summary}
Red flags: ${JSON.stringify(result.redFlags)}
Advice: ${JSON.stringify(result.advice)}`;

    const simplified = await callGemini(sys, [{ text: userContent }]);
    res.json(simplified);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Simplify failed" });
  }
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    gemini: !!process.env.GEMINI_API_KEY,
    virusTotal: !!process.env.VIRUSTOTAL_API_KEY,
    safeBrowsing: !!process.env.GOOGLE_SAFE_BROWSING_KEY,
  });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ScamRadar running on port ${PORT}`);
});
