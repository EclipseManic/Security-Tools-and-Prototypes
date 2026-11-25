# Endpoint Behavior Monitor

An early Windows script that writes keystrokes and active-window switches to a
local text file. It exists to show, at the API level, how basic endpoint telemetry
is produced: `pynput` for key events, `pygetwindow` for the foreground window title.

This is a keystroke logger. It is the one script in this collection that should
only ever run on a machine you own or have written permission to monitor. There is
no stealth, no persistence, no encoding and no network code in it - it is a single
file of callbacks appending lines to `key_log.txt`.

## What it does

| Behaviour | Detail |
|---|---|
| Key capture | Every key press is appended to `key_log.txt` |
| Window context | A separator line is written whenever the foreground window changes |
| Special keys | Mapped to readable tokens: `[ENTER]`, `[TAB]`, `[BACKSPACE]`, `[SHIFT]`, `[CTRL]`, `[ALT]`, `[CAPSLOCK]`, `[ESC]`, `[DEL]` |
| Lifetime | Runs until `Ctrl+C` in the terminal that started it |

## Running it

```text
pip install pynput pygetwindow
python endpoint_behavior_monitor.py
```

Output is appended to `key_log.txt` in the working directory.

## Limits and risks

- Windows only. `pygetwindow` reads foreground window titles through the Win32 API
  and returns nothing elsewhere.
- No rotation, no size cap, no redaction. Anything typed while it runs, including
  passwords, lands in plain text on disk.
- No tamper evidence. The output is an ordinary text file that anything can edit.
- No detection value. It produces the telemetry, it does not spot it. For the
  defensive side of endpoint work, see ServiceSentinel.
- Consent is not a technical control. On a shared or employer-owned machine,
  running this without explicit written permission is a policy and legal problem.

## Why it is still here

Written in 2025 while learning how Windows input and window-focus telemetry is
actually produced. It stayed because knowing what that telemetry looks like is what
makes the detection side readable. It is not presented as a tool.

## Licence

MIT. See `LICENSE`.
