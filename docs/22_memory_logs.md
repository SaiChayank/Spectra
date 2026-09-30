# Memory Logs
## FinShield AI

**Version:** 0.1 (Draft Template) | **Classification:** Internal

---

## 1. Purpose
A running project-memory format so context (decisions, open questions, terminology) persists across team members, sessions, and any AI-assisted tooling used on the project — separate from formal ADRs, which are for irreversible/architectural decisions specifically.

## 2. Log Entry Format

```
Date:
Logged by:
Category: [Decision / Open Question / Terminology / Context Note]
Summary:
Details:
Related docs:
Status: [Active / Resolved / Superseded]
```

## 3. Project Memory — Seed Entries (from initial documentation review)

```
Date: 2026-08-11
Logged by: Assistant (session log)
Category: Context Note
Summary: Project is pre-development; concept documentation exists, no code/data/infra yet.
Details: All 24 requested governance/technical documents were generated as
drafts or templates accordingly. Documents referencing "evidence" of testing
(VAPT, SAST results, model validation, security sign-off) are blank templates,
not fabricated results.
Related docs: All 25 documents in this set.
Status: Active
```

```
Date: 2026-08-11
Logged by: Assistant (session log)
Category: Terminology
Summary: "Sector" always refers to one of: fintech, healthcare, smart_city.
Details: Used consistently across schema (sector_tag enum), API specs, and
routing conventions. Any new sector requires updates across Data Governance,
DPIA, and API Specs simultaneously.
Related docs: 03, 06, 18, 19
Status: Active
```

```
Date: 2026-08-11
Logged by: Assistant (session log)
Category: Open Question
Summary: Multiple numeric thresholds left as TBD across documents.
Details: Precision/recall targets, retraining thresholds, shadow-mode
duration, retention periods pending legal/jurisdictional confirmation,
KMS rotation interval — all marked [TBD] and owned by named roles per doc.
Related docs: 01, 03, 09, 10, 14
Status: Active
```

## 4. How to Use This Log
- Append, don't rewrite history — mark superseded entries as `Status: Superseded` with a pointer to the replacing entry rather than deleting.
- Review at the start of each Phase gate to resurface unresolved Open Questions.
- Any AI agent picking up work on this project should read this log first for context, per the Guardrails Context AI-tooling rules.

*Living document — this seed content reflects the state as of initial documentation generation.*
