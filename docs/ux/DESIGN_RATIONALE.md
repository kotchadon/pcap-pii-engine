# TRACE experience redesign: rationale

This note explains why the TRACE dashboard is structured the way it is. It is a
working record for reviewers, not marketing copy.

## 1. What was wrong with the previous experience

| Problem | Effect on a person using TRACE |
|---|---|
| Every engine concept was a first-class screen: flows, BiLSTM coverage, synthetic probes, packet provenance. | A first-time user met TCP and model terminology before learning whether anything was found. |
| Results opened as a statistics dashboard: packets, flows, frame bytes. | The answer ("what may be exposed, and how sure is TRACE?") was buried. |
| Inspect stacked details under a long table (main) or below the table at laptop widths (PR #34). | The VP's complaint: click Inspect, scroll to find the result, scroll back to choose the next one. |
| Three competing inspectors: the legacy Evidence Inspector, PR #33's HTTP conversation page and PR #34's exchange viewer. | The same finding looked different depending on where it was opened. |
| Upload, options and results shared one long page. | Hard to tell whether a scan was running, finished or showing an older capture. |
| Decorative Unicode glyphs, all-caps labels, many coloured chips. | Read as a lab prototype rather than a product. |

## 2. Research: what was studied and what was taken from it

**Apple Human Interface Guidelines** (Split views, Sidebars, Sheets, Layout and
Accessibility; read from Apple's documentation JSON on 2026-10-25):

- *Split views:* "persistently highlight the current selection in each pane
  that leads to the detail view"; "prefer using a split view in a regular — not
  a compact — environment"; "account for narrow, compact, and intermediate
  window widths"; "to display supplementary information, prefer a split view
  instead of a new window"; "automatically display the most relevant detail
  view"; set sensible minimum and maximum pane sizes, and let people resize.
- *Sidebars:* show no more than two levels of hierarchy; use succinct labels and
  familiar symbols; let people hide the sidebar when space is short.
- *Sheets:* use for a focused task that returns to the parent view; display only
  one sheet at a time; always give a clear way to close.
- *Layout:* order content by importance; align and group related items; "use
  progressive disclosure to make layouts cleaner"; differentiate controls from
  content; adapt to window size.
- *Accessibility:* support text enlargement to 200%; WCAG AA contrast (4.5:1
  for body text); never rely on colour alone.

**Linear: peek preview** (linear.app/docs/peek). Space opens a preview of the
focused list item. J/K or the arrow keys move through the list while the
preview follows. The list never moves away.

**Figma and Xcode: inspectors.** A persistent properties panel on the trailing
edge that always describes the current selection, with an empty state when
nothing is selected.

**Stripe Dashboard and Vercel.** Calm, light, typographic data tables. A short
answer above the detail, and technical data one step away.

**WAI-ARIA dialog pattern** (from established practice; w3.org was unreachable
from the build sandbox). Modal panels need `role="dialog"`, `aria-modal`, a
label, focus moved inside on open, Tab contained, Escape to close, and focus
returned to the invoking control.

## 3. Patterns selected

1. **One universal inspector with a navigation stack.** Findings, conversations
   and connections all open the same inspector. Opening the HTTP message behind
   a finding pushes a view onto the stack. "Back" returns to the finding, and
   the list behind never changes.
2. **Adaptive presentation of the same component.** It appears as a persistent
   right pane on wide windows (≥ 1180 px), a modal drawer on laptops and
   tablets, and a full-height sheet on phones. It never stacks below the list.
3. **Answer first, then evidence, then technical detail.** The inspector's first
   screen covers: what was found, where it appeared, why TRACE flagged it and
   what supports it. Byte ranges, streams and diagnostics sit under *Technical
   details*.
4. **A dedicated start screen.** It offers one obvious action (choose a capture),
   one clearly labelled alternative (the sample capture), and states plainly
   that analysis starts when a file is chosen. Detection method stays visible
   because it changes what is claimed. Resource profiles live behind a
   disclosure.
5. **Summary that leads with the answer.** It shows the count of potential
   findings, what kinds of information may be exposed, and how complete the
   examination was. Statistics move into a disclosure.
6. **Keyboard-first list navigation (from Linear).** ↑/↓ or J/K move the
   selection and the pane follows. Enter opens the drawer at narrow widths.
   Escape closes it.
7. **A light, adaptive palette.** Quiet paper-white surfaces, graphite text and
   one deep teal accent for selection and primary actions, with a matching dark
   appearance via `prefers-color-scheme`. Status colours appear only for
   states, always with text or a shape as well.

## 4. Patterns considered and rejected

| Rejected | Why |
|---|---|
| Dark "security console" theme | Long reading sessions favour light surfaces. It is also the cliché the VP called gimmicky. Dark remains available automatically. |
| Separate full pages for finding and message detail | Breaks the user's place in the list, which was the original complaint. |
| Accordions expanding inline in the table | Rows jump, and long evidence pushes the next item away (the same failure in another form). |
| Rendering captured HTML in a sandboxed iframe preview | Adds attack surface for little investigative value. The CSP has no frame source. Inert text is the honest view. |
| Charts for category counts | A ranked list with counts answers the question faster and stays accessible. Bars stay as a quiet proportional cue. |
| Migrating to React and Vite | See below. |

## 5. Technology decision

TRACE stays on dependency-free browser JavaScript, served as static files by
the Python dashboard.

- **Deployment.** The Python package installs and runs offline with no Node
  toolchain. A framework build step would add a release-time dependency and
  compiled artefacts to keep in sync with the CSP (`script-src 'self'`).
- **Security reviewability.** Text-only rendering (`textContent`, no
  `innerHTML`) is enforced by existing tests that read these files directly.
  JSX would hide those guarantees behind a compiler.
- **Size.** About 2,500 lines of UI code. Discipline comes from modules with
  single responsibilities and one source of truth for inspector state, not from
  a framework.

The code is organised as follows:

- `app.js` handles the session, scan lifecycle, paged findings and flows,
  summary and export (existing tested contracts).
- `inspector.js` holds the universal inspector: its state and navigation stack,
  responsive presentation, focus management, conversation list, message,
  connection and evidence views, and the opt-in source viewer. It replaces PR
  #33's `investigation.js` and PR #34's exchange viewer, which do the same job.
- `lab.js` holds the Model laboratory (unchanged semantics).

## 6. How the new experience differs

| Before | After |
|---|---|
| Options form, drop zone and results on one page | Start screen, then progress, then Summary. The current capture and its completeness are always visible in the sidebar. |
| "PII findings" table with an inspector below | Findings list with the inspector beside it (pane, drawer or sheet) |
| Network flows and HTTP conversations as separate modules | One *Traffic* view with Conversations and Connections, using the same inspector |
| Technical metrics first | The answer first. Technical detail one click away and never hidden when it qualifies a result (incomplete analysis, partial model coverage). |
