# fwscan

A small command line tool that reads firewall logs and finds port scanning in them.

You give it a log where your firewall blocked connections. It tells you who was
scanning, what kind of scan it was, what it assumed about each source, and what
the log cannot tell you.

Plain Python, no dependencies, nothing to install. Needs Python 3.10 or newer.

```
python fwscan.py demo
```

## Why I made this

I had one day of firewall deny records and three questions to answer from them: what
kind of scan happened, what did I have to assume about where it came from, and what
can this log not tell me.

The tempting version of this tool is a script that groups by source, counts failed
attempts, and prints anything over twenty. That answers the first question badly and
skips the other two completely.

The problem is the third question. A deny log only records what got blocked, so the
interesting part is not the noise it contains, it is the silence. An attack that
worked on the first try leaves no line at all. A port that answered is missing from
the log. Build a detector without admitting that and you ship something that looks
confident and is blind.

So the tool is built backwards from that. Every finding shows the evidence behind it.
Every assumption about a source is printed next to the reason for it and the thing
that would prove it wrong. And the detection gap is not described in a paragraph, it
is measured: the same log goes through twelve threshold settings and the table shows
what each one catches and what it wrongly flags.

The other reason is practical. Real logs do not come with answer keys, so there was
no way to tell whether any of this worked. I wrote a generator that plants four
different attacks in a day of realistic noise and writes down exactly what it
planted. Now every claim in this README can be checked by running one command.

## What a port scan is, and why it matters

A port scan is someone trying lots of ports on a machine to see which ones are
open. The scan itself does no damage. Every attempt got blocked, and that is
exactly why it shows up in a deny log.

It matters because it is the step before the attack. Somebody is walking around
looking for the one door you forgot to lock.

So the useful question is not "was there a scan". It is "what kind was it, and
did any part of it get through".

## What it finds in the sample day

The repo includes one generated day of logs: 2,812 blocked connections from one
firewall, 50 sources. Four attacks are planted in it, and the tool finds all four.

**One machine, a thousand ports, nine minutes.** `203.0.113.45` tried ports 1 to
1024 on a single host. Score 0.97, high. The obvious one, and the easy one.

**Three ports across 252 machines, eleven minutes.** `198.51.100.77` tried the
same three service ports on every host in the subnet. Score 0.81, high. Same
intent as the first, completely different shape, so it needs its own rule.

**Six sources, one port, all day.** Six addresses from `192.0.2.11` to `.16`
each made a handful of attempts. Alone, none of them is worth looking at. Together
they all hit port 22 on the same four machines. Score 0.63, medium. Nothing that
looks at one source at a time can see this.

**One port every thirty-three minutes.** `203.0.113.90` tried 40 ports over 21
hours. Any 15 minute window contains at most one port, so a normal short-window
check never fires. Score 0.60, medium. This is the one that matters, and the
reason the tool has a second kind of rule.

There is also a backup job that looks a lot like the second attack and is not,
and a human who mistyped SSH ports five times. Neither gets flagged. They are in
the sample on purpose.

## How it works

### Reading the log

Each line is one blocked connection: when, from where, to where, and which port.
The parser accepts ISO timestamps or normal syslog timestamps, and several
spellings of the source, destination and port fields, because every firewall
vendor writes them differently.

Any line it cannot read is counted and shown, never quietly dropped. A parser
that silently skips half your file is worse than no parser, because every number
after it is wrong and you have no way to know.

### The rules

Everything is grouped by source address, and then four shapes are checked.

Many ports on one machine, fast. That is a normal scan, enumerating services.

Same few ports across many machines, fast. That is hunting one service across a
whole network.

Both at once. A full sweep.

Then the two hard ones. A source that is slow: small in every window, but large
over the whole day. And a group of sources that are each doing almost nothing,
but all aiming at the same port.

### The slow one is a different problem, not a stricter setting

You cannot catch the slow scanner by lowering the threshold. Lower it enough to
see one port every half hour and you also flag the backup job, which knocks on
six machines every ten minutes and is doing nothing wrong. Meanwhile the next
slow scanner just goes slower.

So that rule asks a different question. Not "how many ports in this window", but
"is this source small in every window yet large in total". That combination is
the definition of a paced scanner, and it cannot be tuned away.

### The port that is not in the log

The log only records blocked attempts. So if a scanner walked ports 1 to 1024 and
there is no line for 443, that is because 443 was not blocked. It answered, and
the scanner got in.

The tool looks for single numbers missing from the middle of a long unbroken run,
and reports them as probably open. Probably, not definitely, because a machine
that simply did not respond leaves the exact same gap. This log cannot tell those
two cases apart, so the report says so instead of picking the exciting one.

In the sample day it finds port 443 missing from the thousand-port scan, and two
hosts missing from the subnet sweep.

### The score

The score is how strong the evidence is, not how dangerous the attack is. It is
built from things that are hard to fake by accident: how wide the scan got, how
many of the ports came in order, and how evenly spaced the attempts were. A script
walks ports in order at a steady pace. A person and a retry storm do not.

0.80 and above is high, 0.55 and above is medium. 0.63 means "probably real, less
evidence than the 0.97 one", not "63 percent dangerous".

## About reputation

There is no list of known bad addresses in this tool, on purpose. Such a list is
out of date within a week, and worse, it quietly makes the decision for you.

Instead the tool looks at two honest things: where the address sits, and what it
actually did. Then it prints the four assumptions it is making, and how each one
could be wrong.

The one worth reading is the third: it treats internal addresses as less
suspicious, because most noise from inside a network is a broken job and not a
break-in. That is usually right, and it is also exactly how you miss a machine
inside your network that is already infected and quietly scanning around. So a
high-scoring internal source is something to go and check, not noise.

Every finding says `feed_consulted=false`, so nobody can mistake this for a
threat-intel lookup.

## The gap, measured instead of claimed

Anyone can write "this detector has gaps" in a report. It is true and useless.

So the tool argues with itself. It runs the same log through twelve different
threshold settings and counts two things for each: how many of the planted attacks
it caught, and how many innocent sources it flagged by mistake.

From `examples/sweep.txt`:

```
 WIN  PORTS  HOSTS  BASELINE  FLAG  CAUGHT  RECALL  FP  MISSED / FALSE POSITIVES
   5     20     15       off     8       3     75%   0  missed=D fp=-
  15     20     15       off     8       3     75%   0  missed=D fp=-
  15     20     15        on     9       4    100%   0  missed=-
  15     20      6        on    10       4    100%   1  missed=- fp=10.0.4.50
```

Read the rows, not the best one. Switch the long-window rule off and the slow
scanner disappears from every single row. Loosen the host threshold to catch more
and the backup job appears as a false positive. There is no setting that catches
everything and invents nothing, and now you can see the trade instead of guessing
at it.

The report also lists seven specific things this kind of log cannot tell you.
Each one comes with what was actually seen, why it matters, and what to change to
close it. They are not disclaimers, they are a to-do list for whoever owns the
firewall.

## Commands

Four commands. `demo` is the tour, the other three are the real ones. Every command
takes `--help`.

### demo

```
python fwscan.py demo
```

Generates a day of sample logs, analyses it, and prints the sweep. Nothing to prepare
first. With the same seed it writes the same day back, so running it twice does not
change the repo.

`--dir` where the sample files go, default `data`. `--seed` which day, default 7.
`--year` the year used for syslog timestamps.

### generate

```
python fwscan.py generate --out data/deny.log --truth data/truth.json
```

Writes a sample log and the answer key that says what was planted in it.

`--out` where the log goes, default `data/deny.log`. `--truth` where the answer key
goes, default `data/truth.json`; pass `--truth ""` if you do not want one. `--seed`
picks the day. `--no-attacks` writes only the innocent traffic, which is the honest
way to check for false positives, because a good run on that log finds nothing.

### analyze

The main command.

```
python fwscan.py analyze --log your.log
python fwscan.py analyze --log data/deny.log --truth data/truth.json
python fwscan.py analyze --log your.log --format json --out report.json
```

| flag | default | what it does |
|---|---|---|
| `--log` | required | the deny log to read |
| `--truth` | none | answer key. Only meaningful on generated data, where it adds a scoring block |
| `--format` | `text` | `text`, `json` or `markdown` |
| `--out` | screen | write the report here instead of printing it |
| `--window` | `15` | how many minutes count as "at once" |
| `--min-ports` | `20` | distinct ports inside one window that trigger a scan finding |
| `--min-hosts` | `15` | distinct hosts inside one window that trigger a sweep finding |
| `--no-long-baseline` | off | turns the slow-scanner rule off. Run it once to watch the fourth campaign disappear |
| `--fail-on-findings` | off | exit with code 3 if any high severity finding exists |
| `--year` | `2025` | the year to assume when a syslog line has no year in it |

### sweep

```
python fwscan.py sweep --log your.log
python fwscan.py sweep --log data/deny.log --truth data/truth.json
```

Runs the same log through twelve settings and prints what each one caught and what it
flagged by mistake. It varies the window (5, 15 and 60 minutes), the host threshold
(6 and 15) and the slow rule (on and off). The port threshold stays at 20, because
changing it moved nothing on this data and a table row that never changes is worse
than no row at all.

Takes the same `--log`, `--truth`, `--format`, `--out` and `--year` as `analyze`.
Without a `--truth` file it still runs, it just cannot tell you which findings were
real attacks, so the recall column stays empty. On a real log the useful columns are
`FLAG` and `FP`.

### Exit codes

`0` ran and finished. `2` the log was missing or had no usable records, so nothing
was analysed. `3` a high severity finding exists and you passed `--fail-on-findings`,
which is how you put this in a script or a scheduled job.

`python fwscan.py --version` prints the version.

### Reading the report

Five sections, in the order the questions were asked. One, a summary of what was read
and what was found. Two, each finding in detail with its evidence, its reason and its
reputation view. Three, the four assumptions with what breaks each one. Four, the
seven gaps, each with what was seen, why it matters and what to change. Five, what to
do next.

If you passed `--truth`, a scoring block is appended saying which planted campaigns
were detected and which were missed. That block is labelled synthetic, because it is.

You can read both without running anything. `examples/report.txt` and
`examples/sweep.txt` are real output from the sample log in this repo.

## Using it on your own log

Three steps, in this order.

**Check that it can read your log.** Run `analyze` and look at the skipped count
in the header. If a large share of lines were skipped, your format is not being
understood and everything after that is nonsense.

```
python fwscan.py analyze --log your.log
```

**Then run the sweep before trusting any threshold.** The defaults are set for a
small lab network. On a bigger one they mean nothing.

```
python fwscan.py sweep --log your.log
```

**Then read the gaps.** That is where the value is. When it shows you a port
missing from a scan, go and check your allow records. That is where a failed
attempt turns into a real one.

Do not block the source address on the strength of this alone. It might be a
shared address for a whole office, a proxy, or a cloud range, and you would be
blocking everyone behind it.

Every flag is listed under Commands above. The one worth trying first is
`--no-long-baseline`, because watching the fourth campaign vanish from the sweep
explains the whole point of the tool faster than reading about it.

## What it can't do

The sample data is generated by this repo, so finding all four planted attacks
proves the rules fire on the shapes they claim to detect. It does not prove
anything about your network. The recall numbers are a property of the generator.

It reads one log from one firewall. Traffic blocked somewhere else, or permitted
somewhere else, is invisible to it.

It only sees blocked traffic, so an attack that succeeds on its first attempt
never appears at all. That is not a bug, it is the limit of the data source, and
the fix is to ship allow records alongside denies.

It loads the whole file into memory and sorts it. Fine for a day of one firewall,
not built for a multi-gigabyte export.

## Project layout

```
fwscan.py              entry point, run this
fwlog/parser.py        reads log lines, counts what it cannot read
fwlog/generator.py     makes the sample log and the four attacks
fwlog/analyzer.py      the rules, the gap finding, the scoring, the sweep
fwlog/reputation.py    address classification and the stated assumptions
fwlog/report.py        text, markdown and json output
tests/test_fwscan.py   22 tests
data/deny.log          sample log, one day
data/truth.json        what was planted, used only for scoring
examples/              real output from the sample log
```

## Tests

```
python -m unittest discover -s tests -v
```

The tests cover the parser on ISO and syslog timestamps and on lines it should
reject, each of the detection rules, the missing-port and missing-host logic, the
benign lookalikes not being flagged, the reputation labels, all seven gap ids, and
the sweep's trade-off. Two of them exist because of real bugs: one where port
counting used event counts instead of distinct ports, and one where a distributed
finding named six sources but was counted as a single unknown address, so the
campaign scored as missed while the report showed it as found.

## License

MIT. See `LICENSE`.
