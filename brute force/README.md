# 🔐 PIN Security Console (HTML / CSS / JS)

A single-page, browser-based version of the PIN Security Visualizer,
styled as a physical security-panel keypad with an LCD-style readout.
Runs entirely client-side — open `index.html` in any browser, no
server or build step required.

## What it does

- On-screen numeric keypad (also supports your physical keyboard: `0-9`,
  `Backspace`, `Esc` to clear, `Enter` to analyze).
- LCD-style digit readout with a show/hide toggle (digits are masked
  by default, like a real keypad).
- Detects common weak patterns:
  - All-same digits (`0000`, `1111`, ...)
  - Ascending/descending sequences (`1234`, `4321`, ...)
  - Repeating pair patterns (`1212`, `4848`, ...)
  - Well-known commonly-chosen PINs
  - PINs that look like a calendar year
- 0–100 educational strength score with a segmented LED-style meter
  (green / amber / red).
- A "search space" track showing where the PIN's numeric value sits
  within the fixed 0000–9999 range — a visual teaching aid, not a
  brute-force progress bar.
- A reference table of generic, publicly known guess-rate scenarios
  and how long exhausting the *entire* 10,000-PIN space would take at
  each rate — for illustration only.
- A plain-language recommendation (e.g. "Enable MFA").

## What it deliberately does NOT do

- It never guesses, cracks, or attempts to bypass any real PIN,
  device, or account.
- It makes no network requests with your PIN — everything happens
  in `script.js`, in memory, in your browser tab.
- The LED meter, search-space track, and time table are static,
  clearly-labeled educational visuals based on the fixed size of the
  PIN space (10,000) — not a live attack simulation.

## Project structure

```
pin-security-visualizer-web/
│── index.html   # Structure: keypad device + diagnostic readout panel
│── style.css    # Security-console visual design (LCD, keypad, LEDs)
│── script.js    # Local-only pattern analysis + UI wiring
│── README.md
```

## Running it

Just open `index.html` in a browser — double-click the file, or serve
the folder locally, e.g.:

```bash
python -m http.server 8000
# then visit http://localhost:8000
```

## Notes on the design

The look is meant to evoke an actual door/ATM keypad diagnostic panel
rather than a generic form: a recessed LCD digit readout, tactile
keypad buttons, and a segmented LED bar for the strength meter (green
= strong, amber = moderate, red = weak), instead of a plain gradient
progress bar.

## Extending it

- Add a 6-digit mode by changing `TOTAL_COMBINATIONS` and the regex
  in `analyzePin` (`/^\d{4}$/` → `/^\d{6}$/`), plus the keypad/LCD
  slot count in `index.html`.
- Swap `COMMONLY_USED_PINS` for a larger, licensed breach-frequency
  list if you have one.
- The analysis functions (`detectWeaknesses`, `scorePin`, etc.) are
  pure and framework-free, so they're easy to unit test or reuse.
