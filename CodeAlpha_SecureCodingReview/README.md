# CodeAlpha_SecureCodingReview

Secure code review of the intentionally vulnerable open-source app [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App).
By Hamsa, CodeAlpha Cyber Security Internship, Task 3.

## Contents
- `Secure_Coding_Review_Report.md`: full report (16 findings, severity, CWE, fixes)
- `fixed/app_fixed.py`: remediated version of the main application file
- `scans/bandit_report.txt`: Bandit scan of the original code
- `scans/bandit_report_fixed.txt`: Bandit scan of the fixed code (0 issues)

## Tools
Bandit 1.9.4 plus manual code review.

## Run the fixed file (optional)
Set `SECRET_KEY_HMAC`, `FLASK_SECRET_KEY` and `ADMIN_PASSWORD` as environment variables first. The original repository's templates and dependencies are needed to run the full app.

The original application belongs to its authors; only the review and the modified file are in this folder.
