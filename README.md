# BLACKSITE — Security HQ

An authenticated cybersecurity workspace for Security Engineering, VAPT, Web Application Security and Cloud Security.

## Architecture
- Frontend: this standalone public GitHub repository (static site source).
- Backend: dedicated Supabase project `fnoteezrxjauzbnwrwah` in Mumbai (`ap-south-1`).
- Authentication: Supabase Auth (email + password).
- Database: Postgres `public.workspace_items` with Row Level Security (RLS).
- Evidence storage: private Supabase Storage bucket `security-evidence`; access is scoped to the authenticated user's UUID folder.
- Browser client uses only the Supabase publishable key in `supabase-config.js`. Never put a service-role/secret key in browser code.

## Features
- Domain checklists for security engineering, VAPT, web/API testing and cloud posture.
- Projects, findings and learning records saved to the private cloud database.
- Checklist completion and activity history synchronized through Supabase.
- Per-user RLS policies on every workspace record.
- Private evidence bucket with per-user folder policies, 20 MB file limit and allowlisted MIME types.
- JSON export for backups.
- Curated primary-source references for OWASP, NIST, MITRE, CISA, cloud security and vulnerability advisories.

## Run locally
From this directory, serve the static app over HTTP (not by opening the file directly):
```bash
python -m http.server 8080
```
Open `http://localhost:8080`.

## First login
1. Open the app from a trusted HTTPS host or localhost.
2. Choose **Create your account** and register your email/password.
3. If email confirmation is enabled in Supabase Auth, confirm the message before signing in.
4. Once authenticated, your records sync to the BLACKSITE Supabase project.

The project is separate from Keshav Trades. Do not reuse its database, credentials, storage or environment configuration.

## Hosting note
Supabase hosts the database, authentication and private file storage; it is not a general-purpose static website host. Keep this repository private. To publish the frontend behind HTTPS, connect this directory to a private deployment on a static hosting provider and set the same Supabase URL and publishable key there. Do not enable public GitHub Pages for this repository.

## Security boundaries
- RLS ensures authenticated users can access only rows whose `user_id` matches their Supabase Auth user ID.
- Storage access is private and limited to paths beginning with the signed-in user's UUID.
- The publishable key is intended for browser use; database RLS is the security boundary. Never expose service-role keys.
- Do not store passwords, API tokens, client secrets, personal data, unredacted evidence or confidential client reports. Use redacted, authorized evidence only.
- Only assess systems you own or have explicit permission to test. Record written scope and rules of engagement first.
- Supabase free-tier quotas and retention/backup features can change; monitor usage in the dashboard.

## References
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST CSF: https://www.nist.gov/cyberframework
- MITRE ATT&CK: https://attack.mitre.org/
- Supabase RLS: https://supabase.com/docs/guides/database/postgres/row-level-security
- Supabase Storage access control: https://supabase.com/docs/guides/storage/security/access-control
