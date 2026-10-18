# TRACE in plain language

*For executives and non-technical reviewers. Every example below is fictional. Technical details and evidence: `TECHNICAL_VALIDATION.md`.*

## What TRACE does
Think of a network recording (a "PCAP file") as a long tape of everything a set of computers said to each other.
TRACE plays the tape back, puts the broken-up pieces of each conversation back together, reads the web messages inside,
and highlights places where **personal information may have been sent in the clear** - for example an email address,
a card number or a person's name. It shows *where* each item was found (which conversation, which message, which field)
and hides most of the value on screen.

It works offline on your own computer. It does not send your data anywhere.

## Two helpers look at the same messages
| Helper | How it works | Good at | Weak at |
|---|---|---|---|
| **Checklist (rules)** | Fixed patterns: "this looks like an email", "this field is called `password`" | Emails, phone numbers, card numbers, passwords - very predictable | Names and usernames in fields it was not told about |
| **Pattern-spotting model (AI, "BiLSTM")** | A small trained model that guesses whether a piece of text is a person's name or a username from its surroundings | Names/usernames in unusual field names, other languages | Can guess wrong: sometimes flags a company, a city or a currency as a person |

**Rules-only mode** uses just the checklist. **Hybrid mode** adds the AI's guesses *next to* the checklist's findings, always labelled
as AI so nobody mistakes one for the other. Hybrid never removes or changes a checklist finding.

## A fictional example (the built-in 12-conversation demo)
In one message a form contains `recipient: "Priyanka Venkataraman"`, `email: ship@example.test`.
* The checklist flags the **email** (it knows what emails look like) but *not* the recipient - it has no rule for that field name.
* The AI flags **"Priyanka Venkataraman" as a person's name**. That is something the checklist could not do.
* In the same demo the AI also flags the word **"Madison"** (a city) and the currency code **"AUD"** as if they were people.
  Those are **mistakes**, and TRACE shows them rather than hiding them.
* It missed **"Alex Example"** in one message; the checklist caught it because the field was literally called `full_name`.

Measured on this demo: 95 packets, 12 conversations, 24 web messages; 19 checklist findings; 12 AI findings
(8 of the 9 names/usernames the demo author planted, plus 4 mistakes). Eight of nine is **not** an accuracy score: it is nine
hand-picked items.

## Why you may see "AI ready" but "0 AI findings"
"AI ready" only means the model file loaded. Zero findings can still be correct or expected, for different reasons:
1. The capture contains only things the checklist handles (passwords, emails, headers) - these are deliberately not given to the AI.
2. There was no readable web traffic (for example encrypted web traffic).
3. The AI looked at ordinary text and found no name.
4. The AI missed one (a real limitation).
**Zero findings never means "this file is clean".**

## How accurate is it?
* **For the file you are looking at: unknown (live-file accuracy is not measured).** Accuracy needs a human-made answer key for that file. TRACE has none, so the screen
  deliberately shows no accuracy number for a live scan.
* **On a fixed practice exam:** the AI was tested once on 1,058 invented (synthetic) fields that it was never trained on. It got roughly
  **82 out of 100** (an F1 of 0.818 on the offline challenge benchmark; between 79 and 84 allowing for chance) on spotting exactly the right piece of text. On the same practice exam
  the simple checklist research baseline scored about 32 and the checklist that is actually inside the app about 13, because
  it only knows a few field names. Those are **practice-exam scores on invented data, not performance on real traffic**, and
  our own target (88) was **not** reached.
* The AI's numbers next to each finding are **raw, uncalibrated scores, not probabilities** ("0.9" does not mean "90% likely right").

## What TRACE does *not* claim
* It does **not** prove that data was stolen, leaked or misused: a finding is not proof of anything. A finding means "personal-looking data was visible in this recording".
* It cannot read encrypted traffic (HTTPS), newer web protocols (HTTP/2, HTTP/3) or most non-web traffic.
* If the recording is damaged or has missing pieces, results can be incomplete - and in a few cases (a missing last piece) the
  tool does not yet say so. These are listed with owners in `TECHNICAL_VALIDATION.md`.
* The demo data is fictional and was written by the team, so it flatters nothing and proves nothing about real traffic.

## One-sentence summary you can safely say
"TRACE is a local research prototype that reads unencrypted web traffic from a recording, finds likely personal data with fixed rules and an
experimental AI, shows exactly where it found each item, and is honest that the AI is about 82% accurate on an invented practice test
and has not been measured on real traffic."
