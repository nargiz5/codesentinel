# Real-world results

**In short:**

- **Four mature Flask apps** (CTFd, FlaskBB, pgAdmin, Redash): CodeSentinel raises 10 alerts, against 40 for CodeQL, 165 for Semgrep and 689 for Bandit. I reviewed every alert of the basic analysis (28) by hand. None is a confirmed vulnerability: 24 are code that already checks its input, and 4 point to a policy question in pgAdmin (its URL check allows any port on localhost). Recognizing the projects' own checks ("guards") brings 28 down to 10.
- **RealVuln, an independent benchmark** (26 vulnerable apps, labels written by others): 87% of CodeSentinel's alerts are real, against 65% for Semgrep in the same classes. CodeSentinel finds fewer vulnerabilities (21% of those in its classes, Semgrep 29%), so it trades coverage for precision.
- **A small local language model** can recognize about half of the false alarms, but only when the question is asked neutrally. When told "a scanner reported this", it agreed with the scanner almost every time.

My labeled benchmark covers patterns I wrote myself. This page shows how CodeSentinel behaves on code written by others:

1. [Four open-source Flask applications](#four-open-source-flask-applications), every alert reviewed by hand, compared with Bandit, Semgrep and CodeQL.
2. [What guards and record lookups do](#what-guards-and-record-lookups-do), measured on those four and seven more applications.
3. [RealVuln](#an-external-benchmark-realvuln), an independent benchmark with ground truth written by others.
4. [Whether a local language model can filter the false alarms](#can-a-local-language-model-filter-these-false-alarms).

## Four open-source Flask applications

### Setup

| Project | Python files scanned |
|---|--:|
| [CTFd](https://github.com/CTFd/CTFd) (`CTFd/`) | 357 |
| [FlaskBB](https://github.com/flaskbb/flaskbb) (`flaskbb/`) | 242 |
| [pgAdmin 4](https://github.com/pgadmin-org/pgadmin4) (`web/pgadmin/`) | 1323 |
| [Redash](https://github.com/getredash/redash) (`redash/`) | 309 |

Each project was scanned at the commit listed in [`benchmark/real_world/alerts.json`](../benchmark/real_world/alerts.json). Bandit 1.9.4 and Semgrep 1.186.0 (the `python/` rules of [semgrep-rules](https://github.com/semgrep/semgrep-rules) at `a5ad171`) were run on the same directories, and so was CodeQL 2.27.6 with its `python-security-extended` query suite. Counts include only the vulnerability classes CodeSentinel covers (SQL, command and code injection, deserialization, path traversal, XSS, SSRF, template injection, open redirect).

### Alerts

| Project | Bandit | Semgrep | CodeQL | CodeSentinel, core analysis (reviewed) | CodeSentinel |
|---|--:|--:|--:|--:|--:|
| CTFd | 5 | 21 | 4 | 4 | 0 |
| FlaskBB | 45 | 17 | 3 | 2 | 0 |
| pgAdmin 4 | 629 | 93 | 27 | 16 | 10 |
| Redash | 10 | 34 | 6 | 6 | 0 |
| **Total** | **689** | **165** | **40** | **28** | **10** |

"Core analysis" counts the alerts of the taint analysis alone, without [guards](#what-guards-and-record-lookups-do), record lookups or the class-based-view sources; these 28 are the ones I reviewed by hand. The last column is CodeSentinel as it is. Low-confidence alerts (environment variables and command-line arguments, hidden by default) are not included.

The counts are not a ranking. Bandit reports every risky API call by design, so that a person looks at it; CodeSentinel only reports where it can trace user data. What matters is what each alert means.

CodeQL, which also follows data across functions and files, reports 27 of the 28 places (same file, within 2 lines). So these false alarms are not specific to CodeSentinel: a mature taint engine does not recognize these projects' own checks either. I reviewed the 13 alerts only CodeQL raises: all are false alarms too, mostly in pgAdmin's own path-hardening code (`O_NOFOLLOW` opens relative to a checked directory, `os.path.isfile` tests on validated paths). Where CodeQL does find something CodeSentinel misses is on known CVEs: see [Known CVEs](CVE_VALIDATION.md). All 40 are in [`benchmark/real_world/codeql.json`](../benchmark/real_world/codeql.json).

I also sampled about 30 of Bandit's and Semgrep's alerts (SQL, redirect and deserialization in CTFd and FlaskBB). All were false alarms, for the same reasons and a few others: SQL built from internal table names, `pickle` in database migrations, redirects to `url_for(...)`. I did not review all 854.

### Every alert, by cause

I reviewed all 28 alerts of the core analysis:

| Cause | Core analysis | CodeSentinel | What is left |
|---|--:|--:|---|
| Redirect target checked by the project's own function | 14 | 2 | pgAdmin `mfa/views.py:289`, where the check is combined with a second condition that is tested again later; `:380`, a URL built by the project's `login_url()` |
| File path or program checked by the project's own validators | 8 | 8 | pgAdmin's validators raise an exception instead of returning a result, and its binary-path check is a deny-list, not a guard |
| Allow-list check | 2 | 0 | `if plugin in config_html_plugins: open(...)` (CTFd) |
| Needs a product decision | 4 | 0 | see below |
| **Confirmed vulnerabilities** | **0** | **0** | |
| **Total** | **28** | **10** | |

24 of the 28 are code that already defends itself: the check happens in an `if` before the sink (`if is_safe_url(next): return redirect(next)` in CTFd), or inside a function only the project knows (`get_next_path()` in Redash, `_is_safe_redirect_url()` in pgAdmin). That is the clearest result of this review, and it is what [guards](DETAILS.md#guards) are for.

**A guard can hide a policy problem.** The 4 alerts that need a product decision are in pgAdmin's LLM settings, which fetch a model list from a URL the logged-in user enters. pgAdmin checks it with `validate_api_url()`, a real check, so CodeSentinel trusts it. But its default allow-list lets the server contact any port on localhost. A guard says that a check happened, not that the check's policy is right, so this kind of issue is out of reach of the analyzer.

## What guards and record lookups do

**Guards.** A check in a condition makes a value safe on that path: inside `if is_safe_url(x):`, or after `if not is_safe_url(x): abort()`, the value is safe for that check's context. A project's own check functions are recognized by what they do (parse the URL and compare or reject its host; normalize the path and compare it to a root), not by their name, so `return True`, a scheme-only URL check, or a function that only returns the host is not trusted. Details in [DETAILS](DETAILS.md#guards).

**Records loaded by key.** An id chooses a record; it does not become the record's content. So reads by key return stored data, as `table[key]` does: ORM lookups (`session.get(Model, key)`, `Model.query....first()`, `Model.objects.get(...)`, `get_object_or_404`) and `.get(key)` on a subscripted mapping. Raw SQL inside such a call is still reported. On the four apps this matters for FlaskBB's `MethodView` handlers, which load a forum by the id in the URL (`db.session.get(Forum, forum_id)`) and redirect to its stored link.

**On seven more applications** (ArchiveBox, OctoPrint, calibre-web, changedetection.io, healthchecks, PowerDNS-Admin, SearXNG; alert counts only, not every alert reviewed) CodeSentinel raises 62 alerts. Guards hide 5, and each is behind a real check: Django's `url_has_allowed_host_and_scheme`, OctoPrint's `validate_local_redirect`, changedetection.io's `is_safe_url`, healthchecks' `_allow_redirect` and PowerDNS-Admin's `_safe_relay_state`. Record lookups hide 5 more, among them 2 in ArchiveBox and 2 in changedetection.io. Neither rule hides a finding on the [known CVEs](CVE_VALIDATION.md), on RealVuln or on the labeled benchmark.

**Which data was used for tuning.** The four apps were used to develop both rules, and FlaskBB and changedetection.io pointed to the record-lookup rule. The five other apps among the seven, and the known CVEs, were not used for tuning.

## An external benchmark: RealVuln

My own benchmark tests patterns I chose. [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark) is an independent, open benchmark whose ground truth was written by other people. Its 26 hand-written vulnerable Python applications (PyGoat, DjanGoat, VAmPI, DVPWA and others, benchmark commit `71a680a`) contain 700 labeled vulnerabilities and a set of false-positive traps. I scored CodeSentinel and RealVuln's own published Semgrep results with the same rules (same file, an acceptable CWE, line within ±10 of the labeled range), using [`benchmark/realvuln/score_realvuln.py`](../benchmark/realvuln/score_realvuln.py):

| Tool | Alerts | Correct alerts (precision) | Vulnerabilities found, all 700 | Found, in the 252 that belong to classes CodeSentinel covers |
|---|--:|--:|--:|--:|
| CodeSentinel | 61 | 53 (**87%**, 95% interval 76–93%) | 52 (7%) | 52 (21%) |
| Semgrep, alerts in the same classes | 200 | 130 (65%, 58–71%) | | 72 (**29%**) |
| Semgrep, all alerts | 615 | 193 (31%) | 126 (**18%**) | 72 (**29%**) |

Semgrep's overall precision includes classes CodeSentinel does not cover; restricted to alerts whose CWE is in a covered class (as in the last column), it is 65%. Intervals are Wilson 95% intervals; with 61 alerts, CodeSentinel's precision is known only to within about ±9 points.

This is the same trade-off as everywhere else, measured on data I did not write: when CodeSentinel reports something it is usually right; its coverage is narrower by design. Part of the gap is scope: most of the 700 are authentication, access-control and configuration problems that no taint analysis looks for. Part of it is support. Request data has to come from a framework CodeSentinel knows; class-based views (Flask `MethodView`, Flask-RESTful and RESTX resources, Django and DRF views), Flask-RESTful's `reqparse`, aiohttp, Tornado handlers and Python's own `http.server` are supported, and without them 11 of the 52 vulnerabilities would be missed. Those frameworks were chosen by looking at which RealVuln applications produced no alerts. 6 applications still produce none: GraphQL resolvers (graphene), Connexion handlers whose parameters come from an OpenAPI file, FastAPI code that renders templates with a Jinja2 `Environment`, a Tornado app written in Python 2, which CodeSentinel cannot parse, and OWASP Web Playground. Per-application numbers are in [`benchmark/realvuln/results.json`](../benchmark/realvuln/results.json).

## Can a local language model filter these false alarms?

I gave the 28 alerts of the core analysis, with the code of the function around each one, to `qwen2.5-coder:7b` running locally ([`benchmark/evaluate_ai_real_world.py`](../benchmark/evaluate_ai_real_world.py), my labels and reasons in [`benchmark/real_world/alerts.json`](../benchmark/real_world/alerts.json)), with two prompts:

- **report:** "A taint analyzer reported this finding: ... Decide whether untrusted data can really reach the sink."
- **neutral:** "Line N calls `flask.redirect`. This is dangerous only if attacker-controlled data reaches it. 1. Where does the value come from? 2. List every check it must pass before line N. 3. Decide."

| My review | Prompt | Model: real | Model: false alarm | Model: uncertain |
|---|---|--:|--:|--:|
| False alarm (24) | report | 23 | 1 | 0 |
| False alarm (24) | **neutral** | 2 | **12** | 10 |
| Needs review (4) | report | 4 | 0 | 0 |
| Needs review (4) | neutral | 3 | 0 | 1 |

On the labeled samples (24 real alerts and 1 false alarm), both prompts dismissed no real vulnerability (report: 23 real, 1 uncertain; neutral: 22 real, 2 uncertain, both of them flows that leave the function the model was shown). On the one false alarm, the report prompt said "real" and the neutral prompt said "uncertain", the same pattern as on the real projects below.

**With the report prompt the model agreed with the scanner.** It answered "real" with confidence 1.00 for 23 of 24 false alarms, and its explanations were often wrong about the code in front of it: for `CTFd/auth.py:402` it wrote that `next` "is not validated or sanitized", while the redirect sits inside `if request.args.get("next") and validators.is_safe_url(request.args.get("next")):`.

**With the neutral prompt it looked for the checks first, and found them:** `validators.is_safe_url` in CTFd, `get_next_path()` in Redash, `_is_safe_redirect_url()` in pgAdmin, the plugin allow-list in CTFd. Where the check is in another function it cannot see (pgAdmin's path validators, FlaskBB's `redirect_url()`), it mostly said "uncertain", which is the honest answer. It also pointed out `validate_api_url()` in pgAdmin's LLM code.

The verdict is an annotation that never hides a finding. Each of the 5 times it answered "real", its explanation described a check and called the code safe: twice on false alarms (pgAdmin `mfa/views.py:118` and `289`) and three times on the 4 alerts that need review (pgAdmin `llm/__init__.py:800`, `875` and `1001`). Read by its explanations, it would have recognized 14 of the 24 false alarms instead of 12. So the neutral prompt is the default. Full answers: [report](../benchmark/AI_REAL_WORLD.md), [neutral](../benchmark/AI_REAL_WORLD_NEUTRAL.md).

This is one small model (7B parameters). Larger models may do better with either prompt; measuring that is the obvious next experiment.

## Patterns that look dangerous but are not

Reviewing alerts on real code showed several patterns where a simple taint analysis raises an alarm for safe code. CodeSentinel handles them as follows:

| Pattern | Example | How CodeSentinel treats it |
|---|---|---|
| A user value picks a stored value | `pickle.loads(session["gridData"][trans_id])` | The result carries the taint of the container, not of the key: the user chooses *which* value, not its content |
| Allow-list dictionary | `{"name": "name", "age": "age"}.get(sort, "name")` | Same rule: the result is one of the dictionary's own values |
| Environment variables and command-line arguments | `subprocess.Popen(os.environ["WORKER_CMD"], shell=True)` | Set by whoever runs the program, not by a remote user: reported as low confidence, hidden unless `--include-low-confidence` |
| SQLAlchemy statements | `db.session.execute(sa.select(Topic).where(Topic.id.in_(ids)))` | Values become bound parameters, so the statement is safe; `text()` and `literal_column()` are still raw SQL and still reported |
| `.execute()` on objects that are not databases | `pipeline.execute(context)` | Treated as SQL only when the receiver looks like a database (`cursor`, `conn`, `session`, `db`, ...) or is a call such as `conn.cursor()` |
| Redirects built by the router | `redirect(url_for("login", next=path))` | `url_for` and Django's `reverse` produce internal URLs, so they are sanitizers for redirects |
| Code that runs a user's SQL on purpose | pgAdmin's query tool | Not an analyzer question; a project would silence it with `# codesentinel: ignore` |

Each of these has tests that check both sides: the safe form is not reported, and the dangerous form next to it still is.

## The CVE behind the cross-module claim

pgAdmin 8.4 had a remote code execution bug in its "validate binary path" API ([CVE-2024-3116](https://nvd.nist.gov/vuln/detail/cve-2024-3116), fixed in 8.5). The source (`request.data` in `pgadmin/misc/__init__.py`) and the sink (`subprocess.run` in `pgadmin/utils/__init__.py`) are in different modules, so the flow is only visible to an analysis that follows calls across files; CodeQL reports it too. On the scanned pgAdmin commit the same sink is still reported (`utils/__init__.py:982`): pgAdmin's fix is a set of path checks the analyzer cannot verify, so that alert is one of the 8 "project's own validators" above. This and four more CVEs are in [Known CVEs](CVE_VALIDATION.md).

## Reproduce

```bash
# Each project at the commit pinned in benchmark/real_world/alerts.json, e.g. FlaskBB:
git init flaskbb && cd flaskbb
git fetch --depth 1 https://github.com/flaskbb/flaskbb 63afaa41d6e012a917aa615efcda55531577c3b6
git checkout FETCH_HEAD
codesentinel flaskbb --json
codesentinel flaskbb --include-low-confidence
cd ..

# The CVE-2024-3116 version

git clone --depth 1 --branch REL-8_4 https://github.com/pgadmin-org/pgadmin4 pgadmin4-8.4
cd pgadmin4-8.4/web && codesentinel pgadmin

# CodeQL (bundle 2.27.6), the same way for each project directory
codeql database create db --language=python --source-root pgadmin
codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=codeql.sarif
```

## Next

1. Checks that raise instead of returning a result (pgAdmin's path validators), and facts that depend on two conditions together.
2. GraphQL resolvers and Connexion handlers as sources, the largest remaining recall gap on RealVuln.
3. More known CVEs, vulnerable and fixed versions, for CodeSentinel and CodeQL.
4. The same false-alarm test with larger models.
5. Smaller, less-reviewed projects, where real vulnerabilities are more likely.
