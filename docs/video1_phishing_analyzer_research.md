# 🎥 Video #1 Research — Phishing Email Analyzer Skill

> Filled-in version using the Video Research Template.
> All research current as of late May 2026.

---

## 1. Skill & Video Identity

| Field | Value |
|---|---|
| Skill name | `phishing-email-analyzer` |
| Video number | #1 (channel pivot launch) |
| One-line description | Paste any suspicious email; get a verdict, reasoning, and red-flag breakdown via Claude Code. |
| Video target length | 10–12 minutes |
| Planned record date | _to be set after skill is built_ |
| Planned publish date | _2 weeks from record_ |

---

## 2. The Audience Question

**Primary viewer:** A developer or technically-curious professional (25–45, English-speaking, US/India/EU) who has heard about Claude Code, follows AI news, and recently received a sketchy email at work. They're not a security expert — they're a builder who likes practical AI tools.

**Secondary viewer:** Small business owner, IT admin at a small firm, or compliance person who'd install the skill to use it themselves without writing code.

**What they already know:** Comfortable with terminal, has used Claude or ChatGPT, may have heard of "skills" or "MCP" but hasn't built one.

**The problem they're sitting with:** Their inbox is hostile. Their company's email filter misses things. They've forwarded a "is this real?" email to a colleague at least once in the past month.

**Why click THIS video over alternatives:**
> "Because this is the only one that shows me how to build an AI security tool I actually keep installed — not a research project, not a vendor demo, not a 30-tip listicle."

---

## 3. Keyword Research Findings

### Search A — "phishing email analyzer"
- **Dominators:** SaaS vendor pages (Keepnet, Check Point, Proofpoint, Cofense). Almost no individual creators.
- **Top YouTube results:** Vendor explainer videos, TryHackMe walkthroughs.
- **View counts:** Mostly 5K–50K range. No breakout hits in the last 6 months.

### Search B — "how to build phishing detector"
- **Tutorial supply:** Light. Most results are dev.to / hackathon writeups, not videos.
- **Quality of existing videos:** Mid. Mostly old (2022–2024), using scikit-learn / Flask. Nothing using modern AI tooling or skill format.

### Search C — Trending angle
- **Riding wave:** "Claude Mythos" launched April 2026 — massive press coverage of "AI breaking cybersecurity." Search interest for `claude cybersecurity`, `AI security tool`, `built with claude code` all rising fast.
- **Anthropic released Claude Code Security** in Feb 2026 — direct precedent for tooling content.
- **Window:** This wave has 3–6 months of momentum left. Video #1 needs to ship inside it.

### Search D — Adjacent buyer pain
- Reddit r/Scams, r/phishing, r/cybersecurity_help — thousands of posts/month asking "is this email real?"
- Quora similar.
- A working installable tool is the answer to those threads. The tutorial video is how those people find you.

### Verdict
✅ **Green field.** Tutorial supply is low, news wave is hot, target keywords have intent.
The angle "I built a phishing detector as a Claude Code skill" has near-zero direct competition.

---

## 4. Competition Snapshot

| Video | Approx. Views | Strengths | Gaps you exploit |
|---|---|---|---|
| Keepnet "Phishing Analysis Tools" (vendor) | 10K–50K | Polished, brand authority | Pitches their SaaS, not a tutorial — no install, no agency |
| TryHackMe "Phishing Email Analysis" SOC walkthroughs | 50K+ each | Technical depth | Built for SOC analysts, not for builders — no install for normal use |
| Generic "I built ML phishing detector" hackathon videos | 1K–10K | Educational | Outdated stack, no Claude Code, no skill format |
| "Claude Code: Build an AI agent that finds vulnerabilities" (Skool community) | new, ~5K | Rides the Claude Code wave | Focused on vulns, not phishing; community-gated |

**Your unfair advantage:**
> You're the first to combine the Claude Code skill format with the most universal cyber pain (phishing emails), packaged so any viewer can install and use it in 30 seconds.

---

## 5. The Hook (3 variants)

1. **Story-driven:**
   > "Last month a 40-person accounting firm in Texas lost $180,000 to a single phishing email. Their spam filter let it through. I'm going to build something better in the next 10 minutes."

2. **Challenge-driven:**
   > "I asked Claude Code to catch every phishing email I receive for a week — and turned it into something you can install in 30 seconds. Here's how."

3. **Claim-driven:**
   > "In 30 minutes I built a phishing email analyzer that's smarter than the one your bank uses. And by the end of this video, you'll have it installed too."

**Chosen hook:** **Variant 2** — strongest mix of curiosity + payoff + clear deliverable. Variant 1 is great if you have a *real* recent attack story you can verify; otherwise it sounds invented.

> 📝 *If you have a real anonymized story from your professional network, use Variant 1 and make it true.*

---

## 6. Title (5 variants)

1. ❌ "How to build a phishing email detector with AI" — too generic, won't get clicked
2. ✅ "I built a phishing email analyzer in 30 minutes (with Claude Code)"
3. ✅ "I gave Claude one job: catch every phishing email — it works"
4. ✅ "Your spam filter is missing this — I built something better"
5. ⚠️ "Claude Code vs phishing emails: I built an analyzer in one sitting" — okay but "vs" framing reads click-baity

**Chosen title:** **#2** — "I built a phishing email analyzer in 30 minutes (with Claude Code)"
- Specific time → curiosity
- Concrete deliverable → search intent match
- "(with Claude Code)" hooks the news wave

**Backup for A/B test:** **#3** — "I gave Claude one job: catch every phishing email — it works"

---

## 7. Thumbnail Brief

- **Text overlay (4 words):** "PHISHING. CAUGHT."  *(or)* "BUILT IN 30 MIN"
- **Face expression:** focused, slightly raised eyebrow — *not* shocked-face, *not* mouth-open. We're targeting builders, not normies.
- **Primary visual:** split-screen — left side a clearly-suspicious email (red border, "URGENT: Verify Your Account!!!" subject visible), right side a terminal showing Claude Code output with a green ✅ verdict.
- **Background mood:** dark navy + electric teal accent (matches the brand colors from the blueprint). Avoid red — overused in cyber thumbnails.
- **Bold contrast element:** a single red circle around the most suspicious word in the email, with an arrow.
- **Mobile check:** the words "PHISHING. CAUGHT." must be readable at 200px width.

---

## 8. The Promise

> "By the end of this video, you'll have a working Claude Code skill that analyzes any suspicious email, explains exactly why it's phishing, and runs locally with one install command."

---

## 9. Structure Outline

**0:00 – 0:15 — Hook**
The chosen hook from §5, delivered confident and tight. No "hey everyone, welcome back" — that kills retention. Just open with the line.

**0:15 – 1:30 — Problem setup**
- 2–3 real phishing examples on screen (sanitized — *do not show real targets*)
- Why your default spam filter misses these (impersonation, low-volume, urgency tactics)
- What you're going to build, and why a Claude Code skill is the right format
- Quick visual: "by the end of this video, you'll be able to do this →" (cut to demo preview)

**1:30 – 8:00 — The build**
Show, narrate, build. Three sub-segments:

- **1:30–3:30 — Setting up the skill folder.** Show the `SKILL.md` structure. Explain frontmatter (name, description). Don't lecture — *do*.
- **3:30–6:00 — The detection logic.** This is the meat. Walk through what the skill instructs Claude to check: sender domain, reply-to mismatch, urgency language, link unmasking, brand impersonation cues. Add ONE struggle moment (a real one — when you tested it, what initially didn't work?). Keep it.
- **6:00–8:00 — Adding a script.** Show one supporting script (e.g., a Python helper to extract URLs from headers and check them). This proves the skill is more than just a prompt.

**8:00 – 11:00 — Demo**
Run the skill against 4 sanitized real emails:
1. Obvious phish (it should catch easily) — confidence builder
2. Sophisticated phish (good lure, mild red flags) — shows the AI reasoning
3. Legitimate email that LOOKS suspicious — show it doesn't false-positive
4. Recent real attack (e.g., a notable 2026 campaign, if available) — flex moment

For each one, narrate what the skill outputs, why that matters.

**11:00 – end — CTA + payoff**
- "If you want this exact skill, here's how to install it in 30 seconds" — show the install command on screen.
- "GitHub link is in the description. The whole skill pack lives there — I'm building one new cybersecurity skill per video."
- "If this was useful: subscribe, and tell me in the comments — what would you build next?"
- Don't beg. Say it once, clean, and end.

**Total: 11–12 minutes.** Resist going longer. Quality plays > long plays at this stage.

---

## 10. Skill Release Plan

| Item | Status |
|---|---|
| `SKILL.md` written and under 500 lines | [ ] |
| Tested against 5+ real examples (sanitized) | [ ] |
| Repo: `bk-cybersecurity-skills` exists with proper README | [ ] |
| Branch: `skill/phishing-email-analyzer` | [ ] |
| Install command tested from fresh machine | [ ] |
| Release tag planned: `v0.1.0` | [ ] |
| README links the YouTube video | [ ] |

---

## 11. Distribution Plan

- [ ] **2 Shorts** — (a) the "struggle moment" reaction (most engaging 30s), (b) the demo flex on the sophisticated phish example
- [ ] **LinkedIn post** — "Spent the weekend building a phishing detector with Claude Code. Here's what surprised me." (3–5 short paragraphs, no jargon, link in comments)
- [ ] **Twitter/X thread** — 6–8 tweets walking through the build, screenshots of SKILL.md
- [ ] **Newsletter issue #1** — full story, the install command, the GitHub link, and one "what I'd build next" tease
- [ ] **Reddit** — post genuinely (not promotionally) in r/ClaudeCode and r/cybersecurity. Title: "I built a phishing email analyzer as a Claude Code skill — open source, would love feedback." Lead with the GitHub link.
- [ ] **GitHub release** — proper notes, install instructions, screenshot of the demo

---

## 12. Pre-Record Self-Check

- [ ] Promise statable in one sentence ✅ (see §8)
- [ ] Hook makes YOU want to keep watching ✅ (test it tomorrow morning out loud)
- [ ] Title would make YOU click in your own feed ✅
- [ ] Skill works end-to-end on a fresh machine
- [ ] 5+ sanitized test cases ready for demo
- [ ] Thumbnail sketched in Canva
- [ ] All 6 distribution items queued

---

## 13. Post-Publish Review

*(Fill in 7 days after publish)*

| Metric | Target (Video #1) | Actual |
|---|---|---|
| Views in 48h | 500+ | __ |
| Views in 7d | 2,000+ | __ |
| CTR % | 4%+ | __ |
| Avg view duration | 50%+ | __ |
| GitHub stars | 20+ | __ |
| Comments asking follow-ups | 5+ | __ |

> Channel-pivot videos often underperform the first few. Don't panic at low numbers — the algorithm is recalibrating who you serve. The metric that matters most for video #1 is **how many people install the skill** and **what they comment**, not pure view count.

---

## Open Questions (resolve before recording)

1. **Story for the hook:** Do you have a real, anonymizable phishing story from your professional network you can use for Variant 1, or do we stick with Variant 2?
2. **Voice on camera:** Are you comfortable using your real name and showing your face, given the service-rules situation? Recommendation: yes, as "BK" / "@bkcodes", with no police references anywhere on the channel.
3. **Test email corpus:** Do you have 4–5 real (sanitized) phishing emails you can show on camera, or should we use a public dataset like the Nazario phishing corpus?
4. **Recording environment:** Where are you recording? Quiet room with one window light is enough — we don't need a studio.
