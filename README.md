# web

An interactive terminal UI for assembling pentest tool command lines. The screen
is split into three bordered panels:

- **Project picker** (top-left, 1/3 height) — define the target you're hunting:
  its in-scope URLs/hosts and the things to keep out of scope.
- **Tool picker / configurator** (bottom-left, 2/3 height) — pick a tool and
  toggle its flags while the command builds live.
- **Output** (right half) — streams the command's output when you run it.

Select a project first; its in-scope targets then auto-fill the tool's URL/host
flag (and the out-of-scope list blocks any command that would touch it).
**Nothing is executed unless you explicitly press `ctrl+r`.**

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea).

## Tools included

Curated toward **bug bounty** — tools that find leads on their own and
complement a proxy like Caido/Burp rather than duplicating it. Grouped by
workflow stage (filter with `/` by stage name, e.g. `recon`):

- **recon** — `subfinder` · `amass` · `dnsx`
- **probe** — `httpx` · `naabu` · `gowitness`
- **crawl** — `katana` · `gau` · `waybackurls`
- **content discovery** — `ffuf` · `arjun` · `gobuster`
- **vuln scan** — `nuclei` · `dalfox` · `subzy` · `sqlmap` · `nikto`
- **shells** — GTFOBins reverse / bind / spawn shells (`bash`, `nc`, `socat`,
  `python`, `perl`, `php`, `ruby`, `openssl`, `telnet`, `lua`, `node`, `gawk`,
  `busybox`, `zsh`) for post-exploitation on hosts you're authorized to test
- **payloads** — a `PayloadsAllTheThings`-style cheat sheet of canonical
  detection probes (XSS, SQLi, SSTI, SSRF, path traversal, XXE, command
  injection, open redirect, NoSQL/LDAP/CRLF, JWT). Filter with `/payload`,
  fill the `{MARKER}`/`{HOST}`/`{FILE}`/`{CMD}` placeholder, then `ctrl+y` to
  copy the probe into Caido/Burp. See [Payloads](#payloads) below.

Each exposes a curated set of flags with sensible defaults, descriptions, and
required-field hints.

The **shells** branch is lifted from [GTFOBins](https://gtfobins.github.io).
Entries are named `<binary> · <technique>`; pick one, fill the `{LHOST}` /
`{LPORT}` placeholders (which are substituted straight into the payload), then
`ctrl+y` to copy or `ctrl+r` to run. The plain `· shell` spawns take no
parameters.

A typical chain: `subfinder` → `httpx` → `katana`/`gau` → `ffuf`/`arjun` →
`nuclei`, then pivot into Caido for manual testing. The sibling
[`pentest-learning`](../pentest-learning) project explains this whole workflow.

## Wordlists

A curated slice of [SecLists](https://github.com/danielmiessler/SecLists) ships
in `wordlists/` so the fuzzing tools run out of the box — no system install
needed:

| Dir | Lists | Used by |
|-----|-------|---------|
| `web-content/` | `common.txt`, `raft-medium-directories.txt`, `raft-medium-files.txt`, `big.txt`, `quickhits.txt`, `DirBuster-2007_directory-list-2.3-medium.txt`, `raft-large-directories.txt`, `raft-large-files.txt` | `ffuf`, `gobuster` |
| `dns/` | `subdomains-top1million-{5000,20000,110000}.txt`, `bitquark-subdomains-top100000.txt` | subdomain brute / vhost fuzzing |
| `usernames/` | `top-usernames-shortlist.txt`, `cirt-default-usernames.txt` | auth fuzzing |
| `passwords/` | `darkweb2017_top-1000.txt`, `probable-v2_top-{1575,12000}.txt`, `Pwdb_top-100000.txt`, `top-passwords-shortlist.txt` | auth fuzzing |

`ffuf` and `gobuster` default their `-w` flag to a bundled list (editable in the
UI). Paths resolve to an absolute location next to the binary, so a command
copied or run from the TUI works from any directory. To use a different
collection, set `PENTEST_TUI_WORDLISTS` to a directory that mirrors the same
`web-content/`, `dns/`, … sub-layout, and the defaults follow it; otherwise just
edit the `-w` path in the UI.

## Payloads

A curated, **detection-first** payload library ships in `payloads.go`, modelled
on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
and the [PortSwigger Web Security Academy](https://portswigger.net/web-security)
cheat sheets. Each entry is a well-known *probe* — the minimal input that
confirms whether a sink is reachable and how your input is treated — not a
weaponised exploit. They live in the same picker as the tools (filter with
`/payload`), grouped by class:

| Class | Example probes |
|-------|----------------|
| `xss` | script canary, img/svg handlers, attribute breakout, `javascript:` URI, polyglot, DOM hashprobe |
| `sqli` | quote probe, auth-bypass tautology, UNION column count/select, boolean & time-blind (MySQL/Postgres/MSSQL) |
| `ssti` | `${7*7}{{7*7}}` math detector, Jinja2 & Freemarker markers |
| `path-traversal` | `../`, URL- & double-encoded, PHP `filter` wrapper |
| `ssrf` | localhost, cloud metadata (`169.254.169.254`), decimal-IP bypass, OOB canary |
| `cmd-injection` | separators, command substitution, blind OOB |
| `xxe` | external-entity file read, OOB exfil |
| `open-redirect`, `nosqli`, `ldapi`, `crlf`, `host-header`, `jwt` | the usual one-liners |

Placeholders are substituted straight into the copied string (same mechanism as
the GTFOBins shells):

| Token | Meaning |
|-------|---------|
| `{MARKER}` | a unique canary you grep responses for to see where input lands |
| `{HOST}` | your out-of-band host (Interactsh / Burp Collaborator) for blind detection |
| `{FILE}` | a file path target for traversal / LFI probes |
| `{CMD}` | a benign command (a timed `sleep`) to prove execution |

Workflow: pick a probe → fill the placeholder → `ctrl+y` to copy → paste into
your proxy and fire the request against a target **you are authorized to test**.
The payloads are wrapped in `printf '%s'`, so they stay literal whether you copy
them or print them on quit.

## Build & run

Go 1.27+ is required. This repo was set up with Go installed to `~/go-sdk/go`,
so either run `source ~/.bashrc` (adds it to PATH) or call it directly:

```bash
cd ~/Desktop/bug-bounty-tool
go build -o bug-bounty-tool .
./bug-bounty-tool
```

Or just `./run.sh`.

## Projects & scope

A project is a hunting target: a name, a list of **in-scope** URLs/hosts, and a
list of **out-of-scope** entries. Projects persist between runs in
`$XDG_CONFIG_HOME/bug-bounty-tool/projects.json` (usually
`~/.config/bug-bounty-tool/projects.json`).

- Press `ctrl+p` from anywhere to jump to the project panel.
- `n` creates a project, `s` edits its scope, `enter` makes it the active one.
- When a project is active, choosing a tool pre-fills its URL/host flag with the
  first in-scope target; `ctrl+n` in the configurator cycles through the rest.
- `ctrl+r` **refuses** to run any command that contains an out-of-scope entry.

## Keys

### Project picker (top-left)
| Key | Action |
|-----|--------|
| `↑/↓` | move between projects |
| `enter` | select the active project (scope in effect) |
| `n` | new project (type a name, `enter` to save) |
| `s` | edit scope → `ctrl+t` toggles in/out, `enter` adds, `↑/↓`+`ctrl+x` deletes, `esc` done |
| `d` | delete the highlighted project |
| `tab` | switch focus down to the tool picker |

### Tool list (bottom-left)
| Key | Action |
|-----|--------|
| `↑/↓` | move |
| `/` | filter |
| `enter` | configure selected tool |
| `ctrl+p` | jump to the project panel |
| `q` / `ctrl+c` | quit |

### Flag configurator (bottom-left)
| Key | Action |
|-----|--------|
| `↑/↓` or `tab` | move between flags |
| `space` | toggle a boolean flag |
| `←/→` | cycle a choice flag |
| *(type)* | edit the selected text/number flag |
| `ctrl+n` | fill the selected flag with the next in-scope target |
| `ctrl+y` | copy the command to the clipboard |
| `ctrl+o` | print the command and quit |
| `ctrl+r` | **run** the command — output streams into the right panel |
| `ctrl+p` | jump to the project panel |
| `ctrl+c` | cancel a running command (or quit when idle) |
| `pgup/pgdn`, `home/end`, mouse wheel | scroll the output panel |
| `esc` | back to the tool list |

The command runs inside the TUI via `sh -c`, so compound binaries
(e.g. `gobuster dir`) and the shell quoting behave exactly as shown. Output
(stdout and stderr) streams live into the right panel and the exit status is
appended when it finishes. The last assembled command is also printed to stdout
when you quit (via `ctrl+o`, `ctrl+r`, or after a `ctrl+y` copy), so it survives
leaving the TUI.

## Adding a tool

Edit `catalog.go` and append a `Tool` to the `catalog` slice. Each `Flag` has a
`Kind` (`KindBool`, `KindString`, `KindInt`, `KindChoice`), an optional default
(`Value` / `Enabled`), a `Desc`, and flags like `Required` or `Positional`.
Positional flags (targets, URLs with no switch) are emitted at the end of the
command.

## Files

| File | Purpose |
|------|---------|
| `tool.go` | `Tool`/`Flag` types + command assembly and shell quoting |
| `catalog.go` | the built-in tool definitions |
| `payloads.go` | the detection-probe payload library (appended into the catalog) |
| `model.go` | Bubble Tea model, update loop, and three-panel rendering |
| `project.go` | project/scope picker: state, persistence, and scope wiring |
| `run.go` | streams a running command's output into the right panel |
| `wordlists.go` | resolves the bundled SecLists paths |
| `main.go` | entrypoint; prints the last assembled command on quit |

## Safety

This tool builds commands and, only when you press `ctrl+r`, runs them in the
output panel. Run them only against systems you are authorized to test.
