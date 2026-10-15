# Contributing

Contributions should improve authorized lab discovery, enumeration and analysis. Automatic exploitation, password attacks and unreviewed offensive workflows are outside this project's scope.

1. Create a branch for a focused change.
2. Install the project and development tools with `pip install -e '.[dev]'`.
3. Keep Qt code out of the builder, validators, parser, models and database.
4. Keep all process execution in `scanner.py`, always using argv lists and `shell=False`.
5. Add meaningful tests for behavior changes, especially validation, privileges, cancellation and parsing.
6. Run `python -m pytest -q` and `python -m build` before proposing the change.
7. Update the README for user-facing changes and describe relevant validation in the pull request.

Tests may only use fixtures, local synthetic subprocesses or loopback. They must not scan external hosts or request sudo credentials. Label sample screenshots and fixtures clearly. Do not upload real network inventory, databases or credentials.

If reporting an issue, include Python/Qt/Nmap versions and the smallest reproducible input. Remove private target addresses, hostnames and service details from shared output.
