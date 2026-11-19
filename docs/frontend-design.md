# Frontend design system ("Cyntra" visual language)

Status: **steps 1–2 of 7 done, 2026-11-19** (tokens, component library, styleguide). Colours **measured** on 2026-11-19 from the
four reference screenshots the owner supplied, by pixel sampling (median/brightest/darkest pixels of each element). The images are
compressed and downscaled, so values are rounded to clean steps; small differences of a few RGB units are expected.

* Tokens: `frontend/src/styles/tokens.css` (scoped to `.sx`, so the current console keeps its look until the new shell lands).
* Components: `frontend/src/components/ui/` (`index.ts` exports all; tests in `ui.test.tsx`).
* Gallery: `npm run dev` or `npm run dev:mock`, then open `#/styleguide`. It is dev-only and not in `npm run build`.

## What the screenshots changed versus the brief's estimates

The reference is more neutral and darker than the brief assumed: near-pure black backgrounds, grey (not blue-tinted) glass, a
deeper and less saturated blue, a softer gold, and **light-weight** (≈300) display type rather than 400–500.

| Element | Brief estimate | Measured in reference | Token now |
|---|---|---|---|
| Page background | `#030407` | `#000000` | `--bg-0 #000000` |
| Hero / canvas | `#07090E` | `#0C0D10`–`#0D0D0D` | `--bg-1 #0A0B0D` |
| Cards | `#0B0E14` | `#111111` | `--surface-1 #111214` |
| Nav tab glass | `#11151D` | `#16171D`, top edge `#AEB0B4` | `--surface-2 #17181D`, 22 % white top highlight |
| Active nav tab | blue-tinted | `#0F1923` fill, `#233A6A` edge | `--tab-active-fill #0F1923`, blue edge |
| Headings | `#F2F4F8` | `#F5F5F5` | `--text-1 #F5F5F5` |
| Body | `#A7AFBD` | `#9C9C9C` | `--text-2 #A3A3A6` (nudged up, see departures) |
| Primary button | `#2F6BFF → #1C4DFF` | top edge `#5DA2F7`, middle `#1A57BB`, bottom `#15418A` | gradient `#2A66CC → #1A57BB → #15418A` + `#5DA2F7` 1 px top highlight |
| Links / focus | `#4C8DFF` | (button highlight) `#5DA2F7` | `--blue-400 #5DA2F7` |
| Beam core | `#7DB2FF` | `#95C1C6`–`#95C1F0` | `--blue-300 #95C1F0` |
| Outer frame | `#1C4DFF → #3FA8FF` | `#4699F5` | `--frame-blue #4699F5` |
| Light button | `#EEF0F3` / `#0A0C10` | `#F2F2F2` / `#1F1F1F` | same as measured |
| Gold word | `#F3C98B → #C9893F` | `#DEC397 → #D9B57E` | `--gold-1 #E3C89C → --gold-2 #D2A970` |
| Viewfinder brackets | blue | light grey `#ABAEB4` | `--bracket #ABAEB4` |
| Dot grid | 4–8 % | dots ≈ `#2A2D32` on `#0C1015` | 7 % (unchanged) |
| Display weight | 400–500 | thin strokes, ≈300 | 300 |

## Contrast (WCAG 2.1 AA, checked by script and by a unit test)

| Text token | bg-0 `#000` | surface-1 `#111214` | surface-3 `#202227` |
|---|---|---|---|
| `--text-1 #F5F5F5` | 19.3 | 17.2 | 14.6 |
| `--text-2 #A3A3A6` | 8.4 | 7.5 | 6.3 |
| `--text-3 #8E8E93` | 6.4 | 5.8 | 4.9 |
| `--blue-400 #5DA2F7` | 8.0 | 7.1 | 6.1 |
| `--gold-2 #D2A970` | 9.7 | 8.6 | 7.3 |
| severity CRITICAL / HIGH / MEDIUM / LOW / INFO | 6.5 / 9.0 / 12.9 / 6.6 / 6.9 | 5.8 / 8.0 / 11.5 / 5.9 / 6.1 | 4.9 / 6.8 / 9.8 / 5.0 / 5.2 |

White on the primary gradient: 5.4:1 at the top, 6.7:1 in the middle, 9.7:1 at the bottom. Dark text on the light button: 14.7:1.
`--blue-500 #1A57BB` is 2.8:1 as text and is used only as a fill. `ui.test.tsx` ("contrast tokens") fails if any text token drops
below 4.5:1 on any background or surface.

Type: **Outfit** (sans) and **JetBrains Mono** (numbers, addresses, fingerprints), both OFL-1.1, self-hosted from
`@fontsource-variable/*` (approved 2026-11-19). Display 40–84 px light caps (landing only), section 30–44 px light, page titles 26 px
light, body 14 px, UI labels 12.5 px caps with 0.04em tracking, eyebrow 11 px caps with 0.08em tracking and a blue diamond.

Shape: parallelogram buttons and tabs (`clip-path`, 10 px inset, 6 px at small sizes), 4–6 px card radius, corner "+" marks,
viewfinder brackets. Motion: 200 ms hovers, 500 ms entrances, everything off under `prefers-reduced-motion`.

## Departures from Cyntra, and why

| Departure | Reason |
|---|---|
| Body text `#A3A3A6` instead of the measured `#9C9C9C` | accessibility margin: 6.3:1 instead of 5.8:1 on hover surfaces |
| Captions `#8E8E93`; the reference's card descriptions are `#4F4F4F` | accessibility: `#4F4F4F` is 2.3:1, far below AA 4.5:1 |
| Primary gradient starts at `#2A66CC`; the bright `#5DA2F7` appears only as a 1 px top highlight | accessibility: white text on the reference's bright top band would be ~4.1:1 |
| Primary blue never used for text; links and active states use `#5DA2F7` | accessibility: `#1A57BB` is 2.8:1 as text |
| Focus on skewed buttons/tabs is an inner white ring plus an outer bracket | accessibility: `clip-path` cuts off a normal outline |
| Severity badges add a distinct shape (triangle, diamond, square, circle, ring) | accessibility: colour is never the only signal |
| Our own mark (prism diamond) and terrain/beam/signal-field SVGs instead of the photo and cube logo | rule 4: their assets are theirs. **The mark is new branding: needs the owner's approval** |
| No partner logos, case studies, stats or "Book a demo"; the logo-strip tiles become the capability strip | rule 2: honest copy only |
| Glow limited to one focal element per screen; tables, forms and lists stay flat with no blur behind text | density and legibility in an analyst tool |
| Console page titles are 26 px sentence case; caps display type only on landing, login and empty-state headings | density |
| Score meter always prints the threshold and "unusual for this network, not proof" | rule 2 |

## Step 3: shell and global behaviour (2026-11-19)

* `src/shell/Shell.tsx`: sidebar (skewed items, current page with the active-tab look, "restricted" for sections that need
  `investigate`, "planned" for Hosts, an Experimental group marked "simulated"), collapsible on desktop (remembered as a UI
  preference), a menu drawer below 860 px; top bar with page title, global search (`GET /api/search`, results in a drawer), capture
  state, live-events state (live / reconnecting / offline, each as text), model state, user + role chip, sign out; skip link.
* `src/lib/api.ts`: non-401 errors are `ApiError` (status + Retry-After), unreachable server is `NetworkError`; both still carry the
  message existing pages show. The client signals `spectra:storage` / `spectra:offline` / `spectra:online`; `useConnection` turns
  them into banners.
* Global banners: "Cannot reach the Spectra server"; "Storage temporarily unavailable, retrying in N s" (one countdown per outage,
  then a refresh); "No trained model" on every page with "Train a baseline" only for `model:manage`; capture error.
* 401 mid-session → sign-in with "Your session ended", then back to the page the analyst was on. A deep link while signed out →
  sign-in, then that page. (Sign-in itself is restyled in step 4; 429 countdown there.)
* Existing pages render inside the shell and pick up the new palette through a variable bridge in `shell.css`; each is fully
  restyled in steps 5–7. Hosts is a "planned" page; Account shows the profile until step 5.
* Mock: the switcher is now bottom-left, with a "Demo data, no trained model" scenario.

## Step 4: landing and login (2026-11-19)

* `src/components/Landing.tsx`: framed panel on the blue backdrop; header with the wordmark, skewed nav (Overview, How it works,
  Modules, Limitations, Docs) and Sign in; hero with the dot-grid sky, mist, terrain, the mark in viewfinder brackets and the flow
  beam, the light caps headline "See the flow. / Never the payload. / Act on **evidence**." (gold on the last word), right-aligned copy
  and "⚡ Sign in" / "How it works ↗"; capability strip; four numbered crosshair cards; "What it never does" with the signal field;
  an honest detector-status card citing evaluation report §14 and §20; footer.
* The landing makes **no API calls** (every route but `/api/health` needs a session). The capability strip reads only module title
  and maturity from the generated contract export at build time; those are fixed in backend `capabilities.py` and the contract
  drift check fails CI if they change without a re-export.
* `src/components/LoginPanel.tsx`: glass card inside viewfinder brackets over the hero backdrop; username, password with reveal,
  optional authenticator/recovery code; a 429 disables the form and counts down from `Retry-After`; "Your session ended" and "Sign in
  to continue" notices come from the shell's 401/deep-link handling.
* Docs and Limitations links point at the GitHub repository; if the repository is private, signed-out visitors cannot open them.

Additional departures in this step:

| Departure | Reason |
|---|---|
| The beam fades out behind the headline instead of running through it as the reference waterfall does | accessibility: white text on the beam's light blue would be about 1.9:1 |
| The glow pool sits where the beam meets the terrain, above the copy, not under the text | accessibility: no text on a glow |
| Headline sentence: our own copy ("See the flow. Never the payload. Act on evidence.") | rule 2/4: Cyntra's copy is theirs |
| Capability strip shows module name + REAL/LOCAL/SIMULATED/EXPERIMENTAL instead of partner logos | rule 2: real facts only |

## Not done yet / known gaps

* **`THIRD_PARTY_NOTICES.md`** is not regenerated: the generator resolves Python packages for the Linux container (it needs
  `uvloop`), so it cannot run correctly on Windows. Until it is run on Linux or in CI, `gen_third_party_notices.py --check` will fail
  because the two font packages are new production dependencies. The font CSS is also not in the built bundle yet, because nothing in
  the production app imports the UI kit until step 3.
* **CSP check** of the built, backend-served bundle happens at checkpoint C3; the dev server sends no CSP.
* Hover/focus/active are shown as forced states in the styleguide; live behaviour checked by keyboard and mouse at 1280 px; 390 px
  checked inside a 390 px frame (no horizontal page overflow) because phone emulation does not apply while the browser pane is hidden.
