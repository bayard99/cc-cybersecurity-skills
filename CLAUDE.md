# cc-cybersecurity-skills

One Claude Code skill per video. Each skill is a standalone slash command that any user can install and run locally — no servers, no API keys (for Level 1–2 skills), no vendor lock-in.

## What's in this repo

| Path | What it is |
|---|---|
| `.claude/commands/*.md` | The slash command files Claude reads |
| `skills/<name>/scripts/` | Supporting Python scripts for each skill |
| `skills/<name>/requirements.txt` | Per-skill Python dependencies |
| `docs/` | Video research and planning docs |

## How Claude Code skills work

When a user has this repo open in Claude Code and types `/phishing-email-analyzer`, Claude reads `.claude/commands/phishing-email-analyzer.md` and follows the instructions inside it. The skill can tell Claude to run bash commands, read files, call scripts — anything Claude Code can do.

Installing a skill is as simple as cloning this repo and opening it in Claude Code. No global install step needed.

## Dev workflow

```
# 1. Create a new skill branch
git checkout -b skill/<name>

# 2. Write the skill file
# .claude/commands/<name>.md

# 3. Add supporting scripts (if Level 2)
# skills/<name>/scripts/<helper>.py
# skills/<name>/requirements.txt

# 4. Install deps and test
pip install -r skills/<name>/requirements.txt
# Open Claude Code in this directory and run /<name>

# 5. Test against 5+ real examples before tagging
git tag v0.x.0
```

## Adding a new skill

1. Copy the folder structure from an existing skill as a reference
2. The `.claude/commands/<name>.md` filename becomes the slash command name
3. Keep `SKILL.md` under 500 lines — Claude reads the whole thing every time
4. Run the skill against at least 5 real inputs before the video

## Python script conventions

- Scripts output **JSON to stdout** — Claude reads and reasons over it
- Errors go in the `"errors"` array in the JSON, never to stderr as exceptions
- Use a 5-second timeout on any network call (WHOIS, DNS, HTTP)
- Gracefully degrade: if WHOIS fails, set `domain_age_days: null` and add to errors

## Repo structure (current)

```
cc-cybersecurity-skills/
├── CLAUDE.md
├── .claude/
│   └── commands/
│       └── phishing-email-analyzer.md
└── skills/
    └── phishing-email-analyzer/
        ├── requirements.txt
        └── scripts/
            └── analyze_email.py
```
