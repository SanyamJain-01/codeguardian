# Coding Standards

## CS-01: Parameterised SQL only
Never build SQL text with %, +, f-strings or .format(). Pass values as parameters to execute(): `execute("SELECT * FROM users WHERE name = ?", (name,))`. Applies to every query, select, insert, update and delete.

## CS-02: No print in application code
Use the logging module (`log.info(...)`) instead of print(). print output is lost in production and cannot be filtered by level.

## CS-03: No bare except
Catch specific exceptions. Never write `except:` or `except Exception: pass`, which hide real errors.

## CS-04: No hard-coded configuration
URLs, hosts, ports, passwords, tokens and API keys come from environment variables (os.environ), never literals in code.

## CS-05: Subprocess takes argument lists
Call subprocess.run / subprocess.call with a list of arguments, for example `subprocess.run(["ls", path])`. Never shell=True and never a single command string.

## CS-06: Public functions have docstrings
Every def whose name does not start with an underscore has a one-line docstring saying what the function returns or does.

## CS-07: Timeouts on network calls
Every requests or httpx call (get, post, request) passes timeout=.

## CS-08: No eval or exec
Never call eval() or exec() on any input.
