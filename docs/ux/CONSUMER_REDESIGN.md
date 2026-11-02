# TRACE consumer redesign (Issue #50)

Design direction, system and reasoning for the consumer-first TRACE interface.
This builds on the inspector architecture in `DESIGN_RATIONALE.md` and the
original-value work merged in #47–#49. It changes presentation, copy and icons
only: there are no ML, protocol, detection or API changes.

## The problems we fixed

1. **It read like a lab tool.** Rows led with `json_body.shipping.email`,
   `Rules 0.98` and monospace values. People look for *the value* and *what
   kind of thing it is*.
2. **Card stacks instead of hierarchy.** Almost every block was a bordered card
   of the same weight, so nothing told the eye where to start.
3. **Teal everywhere, no personality.** One colour did selection, buttons,
   bars and the brand. Nothing felt deliberate.
4. **Jargon in primary places.** "Traffic", "Model laboratory", "Reading
   packets", "HTTP response", "Rules + contextual model".
5. **Small, grey type.** 12–13 px metadata in mid-grey carried important
   meaning.
6. **The inspector buried its answer.** The value was in monospace, and packet
   chips sat above the fold, next to the main action.
7. **Generic or arbitrary icons.** Checklist glyphs for findings, a beaker for
   the AI, and no category icons at all.

## References studied, and what we took

| Product | Pattern taken | Not taken |
|---|---|---|
| macOS System Settings | Sidebar with plain names. Grouped, inset lists with one icon tile per row. Explanations directly under a control | Coloured icon tiles per row (arbitrary colours) |
| Finder / Files | Sidebar → content → inspector. The selection persists. Keyboard movement through lists. Inspect without losing your place | Column view, toolbar clutter |
| Apple Photos | Content first. Categories as navigable rows with counts. Compact info panel for the selected item | Imagery and full-bleed media |
| Apple Wallet | Typographic confidence: one large, legible value with a small label above it | Literal cards, gradients, glass |
| Gmail / Google Photos | High-volume lists with search, filter and fixed paging. Two-line rows: primary value, secondary context | Dense icon toolbars |
| Apple HIG, Design principles and Layout | Hierarchy through size and weight, not boxes. Progressive disclosure. Generous, consistent spacing | — |
| GOV.UK Details component | Plain-language disclosure for optional detail ("What is a recording?") | — |
| Lucide accessibility guide | Decorative icons are `aria-hidden`; every icon-only button has a label | — |

## Direction: calm neutrals, one confident blue

We considered three directions:

- **Refine the existing graphite and teal.** Rejected: the VP called out the
  teal, and it carried the technical feeling.
- **Warm paper with a saffron or coral accent.** Distinctive, but warm accents
  read as *warning* in a privacy product, and saffron fails contrast on white.
- **Neutral greys with a single cobalt-blue accent (chosen).** Blue reads as
  calm and trustworthy, leaves amber, red and green free to mean warning,
  error and success, and works in both themes. TRACE's identity comes from
  type, its trace-line mark and value-first rows, not from extra colour.

## System

**Colour** (tokens in `app.css`, every pair checked by
`test_design_tokens_meet_wcag_aa_in_light_and_dark`):

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#f5f5f7` | `#111113` | Window canvas |
| `--surface` | `#ffffff` | `#1c1c1f` | Grouped lists, inspector |
| `--sidebar` | `#ececef` | `#18181b` | Navigation |
| `--text` / `--text-2` / `--text-3` | `#1c1c1e` / `#3a3a40` / `#616168` | `#f2f2f4` / `#c9c9ce` / `#9c9ca3` | Primary, secondary, tertiary text (all ≥ 4.5:1) |
| `--accent` | `#2457d6` | `#6f9dff` | Selection, primary action, icon tint |
| warn / error / ok | amber, red, green | lifted tints | Status only, always with text or shape |

**Type** (system UI font; numbers use tabular figures):

- Display: 34 / 40, weight 700
- Title: 26 / 32, weight 700
- Headline: 17 / 24, weight 600
- Body: 15 / 22
- Callout: 14 / 20
- Footnote: 13 / 18, used only for metadata, never for meaning

Monospace is used only for addresses, packet IDs and raw source.

**Space**: a 4/8-point rhythm. Hierarchy comes from spacing and one component,
the *grouped list* (white surface, 12 px radius, hairline separators inset
past the icon). There are no stacks of bordered cards.

**Icons**: Lucide (ISC licence), inlined in a local sprite, 2 px stroke,
drawn at 18–20 px inside 32–44 px tinted tiles. One metaphor per category:

| Category | Icon |
|---|---|
| Email | `mail` |
| Phone | `phone` |
| Name | `user-round` |
| Username | `at-sign` |
| Password or token | `key-round` (amber tile: the one sensitive category) |
| Card number | `credit-card` |
| Network address | `network` |
| Age | `cake` |
| Device or advertising ID | `smartphone` |
| Account ID | `id-card` |

Icons are decorative (`aria-hidden`), and every icon-only button is labelled.

**Motion**: 140–220 ms ease-out for hover, press, selection and the inspector
slide. Nothing waits on an animation. `prefers-reduced-motion` removes it.

## Words

- Speak human first; precise terms live one disclosure away.
- **Navigation:** New scan, Summary, Findings, Web conversations, AI details,
  How TRACE works.
- **Field names:** "TRACE noticed this because the field was labelled *Full
  name*", not "the rules detector classified `json_body.full_name`".
- **Partial results:** say plainly when results are partial ("The AI checked
  about half of the fields it could read"). The exact counts stay in *What did
  TRACE check?*.
- **No overclaiming:** a finding is a candidate. No safety score, no
  calibrated-probability language, no claims of theft.

## Accessibility notes

- Under `prefers-reduced-motion`, transitions are removed (`transition: none`),
  not just shortened. A near-zero duration still animates the inherited
  `visibility` of every child of the drawer for one frame, which stopped focus
  from reaching the inspector title.
- While the inspector is a drawer or sheet it is a modal dialog. The skip
  link, sidebar, top bar and main content are `inert`, focus starts on the
  inspector title, and Escape returns focus to the selected row.

## Screenshots

All screenshots use the built-in fictional sample (`*.example.test`
addresses, masked credentials). They contain no real or client data.

- `screenshots/before/`: `main` before this change.
- `screenshots/after/`: every view at 1440 px (light and dark) and on phone
  width (390 px).
- `screenshots/states/`: scanning, partial results (illustrative), protected
  credential, empty search, invalid file, and the findings list with the
  inspector at 1024, 768, 390 and 375 px.
