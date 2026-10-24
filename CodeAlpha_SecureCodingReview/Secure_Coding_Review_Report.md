# Secure Coding Review: Vulnerable-Flask-App

**Author:** Hamsa | **Programme:** CodeAlpha Cyber Security Internship, Task 3
**Application audited:** [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App), an intentionally vulnerable Flask application built for security demos. All credit for the original code goes to its authors. Nothing in this repository is a claim of authorship of the original application.

## 1. Scope and method

| Item | Detail |
|---|---|
| Language / framework | Python 3, Flask, SQLAlchemy, PyJWT, Tornado |
| Files reviewed | `app/app.py` (main application, about 340 lines) and `tests/e2e_zap.py` |
| Automated tool | Bandit 1.9.4 (static analysis for Python) |
| Manual review | Line-by-line reading of `app.py` against an OWASP-style checklist: injection, authentication, session/JWT handling, sensitive data, access control, file upload, error handling, logging, cryptography |
| Verification | Remediated file re-scanned with Bandit; compiled with `py_compile` |

Limitation: the application was reviewed statically. It was not run or exploited, because the pinned dependencies are old. Findings marked "needs dynamic testing" are flagged as such.

## 2. Summary

Bandit reported **18 issues** across the project (5 High, 6 Medium, 7 Low). 9 of them were in `app.py`. Manual review found **16 distinct findings**, including several that Bandit cannot detect (broken JWT verification, template injection, access control, sensitive data exposure, logging of credentials).

Bandit's severity is not always the real risk. For example, the SQL injection was rated only "Medium, low confidence" by the tool, but it lets an attacker read or alter the whole database, so it is rated **High** here.

| ID | Finding | Location | CWE | Severity | Found by |
|---|---|---|---|---|---|
| F1 | SQL injection in customer search | `app.py:261` | CWE-89 | High | Bandit + manual |
| F2 | Unsafe YAML deserialization | `app.py:329` | CWE-502 | High | Bandit + manual |
| F3 | JWT signature not verified on `/get/<id>` | `insecure_verify()` | CWE-347 | Critical | Manual |
| F4 | Template injection / reflected XSS in error pages | `pnf()`, `/search` error handler | CWE-1336, CWE-79 | High | Manual |
| F5 | Hardcoded secrets, including the JWT signing key `secret` | `app.py:26-28` | CWE-798 | High | Bandit + manual |
| F6 | Passwords stored as plaintext or unsalted MD5 | `app.py:141`, `/login` | CWE-327, CWE-256 | High | Bandit + manual |
| F7 | Hardcoded default admin credentials | `app.py:62-63` | CWE-798 | Medium | Bandit + manual |
| F8 | Full credit card numbers stored in plaintext and returned by the API | `Customer.ccn`, `/get`, `/fetch/customer` | CWE-312 | High | Manual |
| F9 | Broken access control: no ownership or role checks, open registration | `/get/<id>`, `/fetch/customer`, `/register/*` | CWE-639, CWE-862 | Medium | Manual |
| F10 | Credentials and tokens written to logs | `login()`, `insecure_verify()` | CWE-532 | Medium | Manual |
| F11 | Unrestricted file upload (no type or size limit) | `/xxe_uploader`, `/yaml_hammer` | CWE-434 | Medium | Manual |
| F12 | Verbose errors returned to the client | `str(e)` in responses | CWE-209 | Low | Manual |
| F13 | Weak random numbers for uploaded file names | `app.py:295, 319` | CWE-330 | Low | Bandit |
| F14 | No brute-force protection, 4-hour token lifetime | `/login`, `get_exp_date()` | CWE-307 | Low | Manual |
| F15 | Code-quality bugs and deprecated APIs | several | n/a | Low | Manual |
| F16 | Test script disables TLS verification, has no timeouts, hardcoded login | `tests/e2e_zap.py` | CWE-295 | Low | Bandit |

## 3. Detailed findings and fixes

### F1: SQL injection (High)
**Evidence:** `str_query = "SELECT ... WHERE username = '%s';" % search_term` and `db.engine.execute(str_query)`.
**Risk:** the search term goes straight into the SQL text. An input such as `' OR '1'='1` returns every customer. UNION-based input can read other tables.
**Fix:** use the ORM so values are bound as parameters.
```python
rows = (Customer.query.filter_by(username=term)
        .with_entities(Customer.first_name, Customer.last_name, Customer.username).all())
```

### F2: Unsafe YAML load (High)
**Evidence:** `ydata = yaml.load(y)` on an uploaded file.
**Risk:** the default loader can build arbitrary Python objects, which can lead to code execution.
**Fix:** `ydata = yaml.safe_load(yfile)`.

### F3: JWT signature not verified (Critical)
**Evidence:** `insecure_verify()` calls `jwt.decode(token, verify=False)` and always returns `True`. It protects `/get/<cust_id>`.
**Risk:** anyone can send a forged or unsigned token and read customer records, including card data. This is a full authentication bypass.
**Fix:** remove `insecure_verify()`. Every protected route uses `verify_jwt()`, which checks signature, algorithm, issuer and expiry.

### F4: Template injection and reflected XSS (High)
**Evidence:** the 404 handler builds an HTML string with `% request.url` and passes it to `render_template_string`. The `/search` handler does the same with `str(e)`.
**Risk:** user-controlled text is evaluated as a template (server-side template injection), which can expose application data or run code. It is also reflected into HTML without escaping.
**Fix:** do not pass user input to `render_template_string`. Return HTML-escaped text: `... % escape(request.url)`.

### F5: Hardcoded secrets (High)
**Evidence:** `SECRET_KEY_HMAC = 'secret'`, `SECRET_KEY_HMAC_2 = 'am0r3C0mpl3xK3y'`, and a literal `app.secret_key`.
**Risk:** anyone with the source can sign valid JWTs or forge session cookies. A short word like `secret` is also easy to brute-force. Bandit rated this "Low", but the impact is high because it breaks all authentication.
**Fix:** read secrets from environment variables (`os.environ["SECRET_KEY_HMAC"]`) and generate long random values, for example with `secrets.token_urlsafe(32)`.

### F6: Weak password storage (High)
**Evidence:** `hashlib.md5(password).hexdigest()` at registration. `/login` compares the submitted password directly with the stored value, so the default admin password is stored in plaintext.
**Risk:** MD5 is fast and unsalted, so leaked hashes can be cracked quickly. Plaintext storage exposes all passwords at once.
**Fix:** `generate_password_hash()` on write and `check_password_hash()` on login (salted, slow hashing from Werkzeug). Argon2 or bcrypt are also good choices.

### F7: Default admin credentials (Medium)
**Evidence:** `user.username = 'admin'`, `user.password = 'admin123'`.
**Fix:** read the initial admin password from an environment variable, store it hashed, and force a change on first login.

### F8: Sensitive data exposure (High)
**Evidence:** `Customer.ccn` holds the full card number and the API returns it as `cc_num`.
**Risk:** a database leak or any access-control bug exposes complete card numbers, which also breaks PCI-DSS rules.
**Fix:** do not store full card numbers. Keep only the last 4 digits (or a payment-provider token) and mask the rest in responses.

### F9: Broken access control (Medium)
**Evidence:** any valid token can read any customer by ID. `/register/user` and `/register/customer` need no authentication, and there are no roles.
**Fix:** add roles and ownership checks (a customer reads only their own record), rate-limit registration, and use non-guessable identifiers. The remediated file still has a single role, so this item is only partly addressed (see section 6).

### F10: Sensitive data in logs (Medium)
**Evidence:** `print(content)` in `login()` prints usernames and passwords. `insecure_verify()` prints decoded tokens.
**Fix:** remove these prints. Use the `logging` module and never log credentials, tokens or card data.

### F11: Unrestricted file upload (Medium)
**Evidence:** uploads are saved without an extension check, size limit or authentication. `secure_filename` is used, which is good.
**Risk:** storage exhaustion and a larger attack surface for the document and YAML parsers. Whether the document parser is open to XXE **needs dynamic testing**; it was not confirmed here.
**Fix:** extension allow-list, `MAX_CONTENT_LENGTH`, random stored names, and (in a real application) authentication on upload routes.

### F12 to F16 (Low)
- **F12:** return a generic message to clients and log the detail on the server.
- **F13:** `random.randint` is predictable. File names now use `uuid.uuid4().hex`; use `secrets` for anything security related.
- **F14:** add login rate limiting (for example Flask-Limiter) and lockout. Token lifetime was reduced from 240 to 30 minutes.
- **F15:** `e.message` does not exist in Python 3, `hashlib.md5(str)` fails, `User(username, hash_pass)` does not match the model, and `before_first_request`, `db.engine.execute` and `jwt.decode(verify=...)` are deprecated or removed in current libraries. These bugs also hide real error handling. The dependency versions in `requirements.txt` were not audited here; run `pip-audit` on them.
- **F16:** `verify=False` disables TLS certificate checks, requests have no timeout, and the login is hardcoded. Acceptable only for a local test script.

## 4. Verification of the fixes

| Scan | `app.py` issues |
|---|---|
| Original `app/app.py` | 9 (High 1, Medium 2, Low 6) |
| Remediated `fixed/app_fixed.py` | **0** |

The remediated file also compiles cleanly. Raw output is in `scans/bandit_report_fixed.txt`. Note that a clean Bandit scan does not prove the code is secure: logic issues such as F9 are invisible to it.

## 5. Secure coding best practices

1. Never build SQL, HTML or templates by concatenating user input. Use parameters and escaping.
2. Keep secrets out of source code. Use environment variables or a secrets manager.
3. Hash passwords with a slow, salted algorithm (Argon2, bcrypt, scrypt).
4. Verify JWT signatures, algorithm, issuer and expiry on every request.
5. Enforce authorization on every route, not only authentication.
6. Do not store data you do not need (card numbers); minimise and mask what you keep.
7. Use `safe_load` for YAML and avoid `pickle` on untrusted data.
8. Validate uploads by type and size, and store them with random names.
9. Return generic errors to users, and keep detailed errors in protected logs without secrets.
10. Run SAST (Bandit, Semgrep) and dependency scanning (`pip-audit`) in CI, and always add manual review.

## 6. Limitations and conclusion

This was a static review of one small application. The remediated code was compiled and scanned but not run against the full application, because the original dependencies are outdated and the templates were not part of this review. Access control (F9) still needs a proper role model, and the upload parsers need dynamic testing.

The review shows that automated tools find fewer than half of the real problems: of the 16 findings, 7 came from Bandit and 9 needed manual reading, and Bandit under-rated two of the most serious ones (SQL injection and hardcoded secrets). Combining a static scan with manual review gives a much more accurate picture.
