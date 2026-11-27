# Known CVEs: vulnerable and fixed versions

**In short:** on five published vulnerabilities in real Python web apps, CodeSentinel finds 3, CodeQL finds 3 (a different set) and Semgrep's taint rules find 1. One CVE, in calibre-web, is found only by CodeSentinel. The two misses are explained below: one needs method calls on stored objects, which CodeSentinel does not follow yet; the other uses a source and sink it does not know.

A tool that works on real code should report a known vulnerability in the vulnerable version, point to the right source and sink, and stop reporting it once the bug is fixed. I checked this on five published CVEs in open-source Python web applications, all in vulnerability classes CodeSentinel covers. I ran CodeQL 2.27.6 (`python-security-extended`) and Semgrep CE 1.187.0 (the `python/` rules of [semgrep-rules](https://github.com/semgrep/semgrep-rules) at `a5ad171`, audit rules included) on the same versions for comparison.

## Results

| CVE | Project, versions | Class | CodeSentinel | CodeQL | Semgrep CE |
|---|---|---|---|---|---|
| [CVE-2024-3116](https://nvd.nist.gov/vuln/detail/CVE-2024-3116) | pgAdmin 8.4 → 8.5 | Command injection | **Found** across two modules | **Found** across two modules | Audit rule only |
| [CVE-2024-2044](https://nvd.nist.gov/vuln/detail/CVE-2024-2044) | pgAdmin 8.3 → 8.4 | Path traversal → deserialization | Missed | **Found** (the path traversal) | Audit rule only |
| [CVE-2022-0339](https://nvd.nist.gov/vuln/detail/CVE-2022-0339) | calibre-web 0.6.15 → 0.6.16 | SSRF | **Found** across two modules | Missed | Missed |
| [CVE-2024-32651](https://nvd.nist.gov/vuln/detail/CVE-2024-32651) | changedetection.io 0.45.20 → 0.45.21 | Template injection | Missed | Missed | Audit rule only |
| [CVE-2025-57633](https://nvd.nist.gov/vuln/detail/CVE-2025-57633) | FTP-Flask-python `5173b68` (no fix) | Command injection | **Found** | **Found** | **Found** |

CodeSentinel and CodeQL each find 3 of the 5, and not the same 3; together they find 4. Semgrep's taint rules find 1. Its audit rules flag the dangerous API at three more of them (`subprocess` with a non-literal argument, every use of `pickle`, a Jinja2 `Environment` without autoescape), but an audit rule fires wherever the API is used, with no source: in these same versions they also produce most of Semgrep's 277 alerts on pgAdmin and 145 on calibre-web, and two of them still fire after the fix.

**CVE-2022-0339 is found only by CodeSentinel.** The cover URL is read from `request.form` in `editbooks.py` and passed to `helper.save_cover_from_url()`, which calls `requests.get(url)`. CodeSentinel reports it with that source and sink. CodeQL with its extended security queries and Semgrep with its Python rules, audit rules included, report nothing on that line. For Semgrep this is expected: the free edition's taint analysis stays inside one function, and here the source and the sink are in different modules. Semgrep's paid edition analyzes across files; I did not test it.

**After the fix.** Only one alert disappears in a fixed version: CodeQL's alerts for CVE-2024-2044. For CVE-2024-3116 both tools still report the sink in pgAdmin 8.5, and CodeSentinel still reports calibre-web 0.6.16. In both cases the fix is a check that does not make the value safe in general, so the alert staying is defensible: pgAdmin 8.5 only refuses programs inside the storage directory (a deny-list, and choosing any other program is still allowed by design), and calibre-web 0.6.16 compares the resolved address with a few localhost prefixes, a fix that was bypassed several times afterwards ([CVE-2022-0766](https://nvd.nist.gov/vuln/detail/CVE-2022-0766), [CVE-2022-0767](https://nvd.nist.gov/vuln/detail/CVE-2022-0767), [CVE-2022-0939](https://nvd.nist.gov/vuln/detail/CVE-2022-0939)). Recognizing [guards](DETAILS.md#guards) did not change any result on this page.

## Why CodeSentinel missed two

- **CVE-2024-2044.** The session id comes from a cookie and reaches `open()` and `pickle.load()` through method calls on a session-manager object (`self.manager.get(sid, ...)`). CodeSentinel does not resolve method calls on instances, a limitation listed in [Details](DETAILS.md#known-gaps-and-next-steps).
- **CVE-2024-32651.** The template is taken from a WTForms field (`field.data`) and rendered with `Environment(...).from_string(...)`. CodeSentinel knows neither the source nor this sink. CodeQL misses it too.

## How the CVEs were chosen

The CVEs had to be in Flask or Django code, in classes CodeSentinel covers, with a known vulnerable version and, where one exists, a fixed version (CVE-2025-57633 has no fix yet). The results show what each tool does on these cases. Every result, with file and line, is in [`benchmark/cves/cves.json`](../benchmark/cves/cves.json).

## Reproduce

```bash
git clone --depth 1 --branch REL-8_4 https://github.com/pgadmin-org/pgadmin4 pg-8.4
codesentinel pg-8.4/web/pgadmin

# CodeQL, the same way for each version
codeql database create db --language=python --source-root pg-8.4/web
codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=codeql.sarif
```

The versions and scan directories for all five CVEs are listed in `cves.json`.
