# TRACE usability session script (30 minutes)

Use this with one person who has never seen TRACE. It checks whether the
redesign works for people, not for the people who built it. One facilitator,
one participant, screen visible to both. Record observations, not opinions.

## Before the session

1. Start TRACE: `python -m packet_pii.dashboard --port 8765`
   (add `--retain-capture-for-inspection` for task 5).
2. Open `http://127.0.0.1:8765/` in a fresh browser window at laptop size
   (about 1280 × 800).
3. Have a capture file ready on the desktop. The sample capture inside TRACE
   is fine.
4. Say: *"We are testing the software, not you. Please think aloud. I can't
   help during the tasks, but I'll answer questions afterwards."*

## Tasks

Read each task aloud exactly as written. Do not point at the screen.

| # | Task (read aloud) | Success looks like | Note |
|---|---|---|---|
| 1 | "In your own words, what does this application do?" (10 seconds on the first screen) | Mentions network capture or traffic, plus personal information | Words they use |
| 2 | "Check this capture for personal information." | Chooses the file or the sample without help. Notices that analysis starts | Hesitation before choosing; whether they open Analysis options |
| 3 | "How much did TRACE find, and was the check complete?" | Reads the count and the completeness note on Summary | Do they trust "Complete"? Do they ask what it means? |
| 4 | "Find out where the second email address appeared and why TRACE flagged it." | Opens Findings, selects the row, reads *Where it appeared* and *Why TRACE flagged it* | **Any scrolling to find the details is a failure of the redesign.** Note it |
| 5 | "Show me the web request that carried it, then come back to the finding." | Opens the request, then uses Back | Did they lose their place in the list? |
| 6 | "Now look at a different finding." | Selects another row, or uses ↓ | Did the inspector update without them looking for it? |
| 7 | "Make the window narrow (like a tablet) and inspect a finding again." | Drawer opens over the list. Closes with × or Escape | Do they find the way back? |
| 8 | "Download the results." | Export report | — |
| 9 | (Expert participants only) "Show me the packets that support this finding, and the original response text." | Packets table. Source reveal after acknowledging | Do they understand the warning before revealing? |

## Afterwards (5 minutes)

- "What was the most confusing moment?"
- "Was there anything you expected to find but couldn't?"
- "How confident are you in what TRACE told you? Why?"
- Ask for a rating from 1 to 7 for "easy to use" and for "I trust the results".

## Scoring

- **Task success:** completed without help / with a hint / failed.
- **Critical incidents:** any time the participant scrolled to look for
  inspector details, misread a score as accuracy, or believed "no findings"
  meant "no personal data".
- **Decision rule:** two or more participants failing the same task, or one
  critical incident about accuracy or safety claims, means a design change is
  needed before release.

This script describes a test to run. Nothing in this repository claims it has
been run with real participants.
