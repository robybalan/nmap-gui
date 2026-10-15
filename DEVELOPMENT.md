# Implementation and validation record

Development proceeded through working checkpoints with separate Git commits. Complete source files are in `src/nmap_gui/`; tests are in `tests/`. The commits preserve the full code at each stage rather than leaving partial snippets or a single large application script.

## Incremental checkpoints

| Stage | Created or changed files | Decision and verification |
| --- | --- | --- |
| 1. Repository | `.gitignore`, `LICENSE`, `README.md`, `requirements.txt`, `pyproject.toml`, `src/nmap_gui/__init__.py` | Isolated `nmap-gui/` repository, `src` layout and editable installation. Committed as `Initial project structure`. |
| 2–3. Builder and validation | `command_builder.py`, `validators.py`, `models.py`, `test_command_builder.py`, `test_validators.py` | argv lists, strict target/port allowlists, compatible scan options, IPv6 detection. **88 tests passed** before scanner work. |
| 4. Execution | `scanner.py`, `test_scanner.py`, `conftest.py` | QThread with subprocess/selectors, independent streaming pipes, exit/duration and process group cancellation. **93 passed, 1 skipped** before GUI work. |
| 5–6. GUI and streaming | `gui.py`, `main.py`, `askpass.py`, `test_gui.py`, packaging entry points | Live command preview, explicit privileges, separate sudo helper, output/copy/save/stop. **96 passed, 1 skipped**, including a synthetic GUI streaming/stop run. |
| 7. XML parser | `parser.py`, `test_parser.py` | ElementTree into dataclasses; entity rejection, missing fields and completed-host recovery for interrupted XML. **9 parser tests passed** before table integration. |
| 8. Tables | `gui.py`, `test_gui.py` | Results and discovered hosts; raw output survives parse errors. **106 passed, 1 skipped**. |
| 9. History | `database.py`, `models.py`, `gui.py`, `main.py`, `test_database.py`, `test_gui.py`, `conftest.py` | SQLite, mode-0600 database, JSON argv/options, validated rerun and state isolation in tests. **111 passed, 1 skipped**. |
| 10–12. Release preparation | README, this file, contributing guide, screenshots, sample fixture, screenshot script, manifest, GitHub Actions | Complete installation/usage/security/architecture guide, public repository preparation and distribution verification. See final validation below. |

Run all tests with:

```bash
source .venv/bin/activate
python -m pytest -q
```

Run a focused checkpoint with, for example:

```bash
python -m pytest -q tests/test_command_builder.py tests/test_validators.py
python -m pytest -q tests/test_scanner.py
python -m pytest -q tests/test_parser.py
python -m pytest -q tests/test_database.py tests/test_gui.py
```

## Environment observations

The implementation environment provided Python 3.14.6 and Nmap 7.99. Its PySide6 package was incomplete (QtCore/QtWidgets were absent). PyQt6 was already working, so the implementation uses the alternative allowed by the project requirements. Qt runtime: 6.10.2.

PyPI DNS/network access was unavailable. A local `.venv` with `--system-site-packages` was used for verification, followed by `pip install --no-build-isolation --no-deps -e .`. The regular README installation remains the recommended setup on a connected Kali machine. A clean installation that downloads dependencies from PyPI could not be verified here. The system Python has unrelated pre-existing dependency conflicts; the project did not change those system packages.

The execution sandbox disallowed creating AF_INET sockets, including loopback. The ephemeral-listener Nmap integration test was therefore skipped with an explicit reason. A real `nmap -sL -n -oX … 127.0.0.1` invocation succeeded and its generated XML was read by the scanner. Synthetic subprocess tests verified live stdout/stderr, cancellation, failures and complete GUI/history workflows without sending probes.

sudo reported a `no new privileges` restriction in this environment. Real password authentication, raw scans and privileged signal forwarding require the manual Kali checks below; they are not represented as verified here.

## Final validation

Final suite: **115 passed, 1 skipped**. Additional checks verified bytecode compilation, module/console entry points, offscreen Qt launch, real rendered screenshots, sdist/wheel contents and installation from the built wheel into a temporary environment outside the source tree. Both installed entry points were present; the installed GUI opened and closed through the Qt event loop.

The system's `build` package also lacked its runnable module, so distribution files were produced through the configured setuptools backend directly, without network access:

```bash
python -c 'from setuptools.build_meta import build_sdist, build_wheel; print(build_sdist("dist")); print(build_wheel("dist"))'
```

Produced artifacts: `dist/nmap_edu_gui-0.1.0.tar.gz` and `dist/nmap_edu_gui-0.1.0-py3-none-any.whl`. These generated artifacts are ignored by Git. Wheel verification reused the existing system Qt libraries; it does not claim a clean PyPI dependency download. The final cancellation test also confirmed SIGKILL escalation for a synthetic process that ignored both SIGINT and SIGTERM. Authentication helper tests used synthetic responses and did not invoke sudo or real credentials.

Screenshots were generated by `scripts/capture_screenshots.py` from a clearly labelled XML fixture and visually inspected. This script never starts Nmap or sends network traffic.

### Readability correction

The initial stylesheet left several text colors to the desktop theme and gave the disabled Run button white text on a gray background. `theme.py` now sets a complete light palette plus explicit foreground/background pairs for inputs, buttons, disabled controls, table rows/selections, headers, tabs, dropdowns, tooltips and dialogs. The sudo helper uses the same theme. Text defaults to at least 10 points; the output console also uses a minimum 10-point monospace font.

Verification began with an intentionally dark application palette, then opened the actual widgets. Measured foreground/background contrast ratios were 6.15 for disabled controls, 7.45 for the primary action and active/inactive table selections, 14.55 for inputs/dropdowns/password fields, and 14.38 for the console. Rendered screenshots of disabled controls, selected rows, dropdowns and a dummy password dialog were visually inspected. No scan or authentication was performed. Documentation screenshots were refreshed; the existing suite still reports **115 passed, 1 skipped**.

## Manual acceptance on an authorized Kali desktop

1. Follow the README's clean virtualenv installation. Run `nmap --version` and `python -m nmap_gui.main` as an ordinary desktop user.
2. Enter `127.0.0.1`, choose TCP Connect, custom ports `22,80,443`, T3, and optionally version detection. Verify the preview exactly matches the process shown in a process viewer, including `-oX`.
3. Run the scan. Confirm the window remains interactive, output arrives during execution and the final tables reflect actual local services. A closed/filtered port is a valid result.
4. Choose SYN or OS detection. Confirm the privilege notice and disabled Run button until Use sudo is selected. Run, authenticate in the separate dialog, and verify only Nmap is privileged. Also test cancelling the password dialog.
5. Start a scan of an authorized lab subnet with a slow timing profile, then Stop. Verify no Nmap process remains. Repeat with sudo and while the authentication dialog is visible. Close the app during a scan and verify it exits after cancellation.
6. Choose Host Discovery / Ping Scan on an owned VM subnet. Verify no port options remain in the command, and Discovered Hosts shows reachable IPs. MAC/vendor fields may be blank when unavailable.
7. Reopen the app. Open the latest history row, compare raw/structured results, copy its original command and rerun. Verify the same scan options and a fresh temporary XML path.
8. Save Results and compare the text file with the scan output. Clear the visible console and confirm saved completed results/history remain available.
9. Try invalid ports and targets with shell operators, substitutions, newlines or option syntax. Confirm validation prevents execution. Temporarily launch with Nmap absent from PATH and confirm the dependency message.
10. Test an authorized IPv6 loopback/lab target and IPv6 DNS. Verify automatic `-6` for literal IPv6 targets and manual IPv6 DNS selection for hostnames.

## Publishing

The repository uses `main` and contains logical local commits. No GitHub remote or public repository is created implicitly. Replace the placeholder repository owner in the README, create the empty public repository, then use the documented `git remote add` / `git push` commands. Local development commits use an explicit automation author (`Codex <codex@localhost>`), without modifying the user's global Git identity.
