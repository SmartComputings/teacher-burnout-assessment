# Backend - Teacher Burnout Survey MVP

Stack:
- Node.js (18/20)
- Express
- better-sqlite3 (lightweight file DB for MVP)
- JWT (jsonwebtoken) for admin auth
- bcryptjs for password hashing
- csv-stringify for CSV export

Important files:
- `index.js` - main server
- `survey_definition.json` - the survey (28 questions, domain mapping)
- `init_db.js` - initialize SQLite DB and create demo admin
- `compute_sample_scores.js` - helper to compute domain scores for demo
- `data.db` - created by `npm run init-db`

Endpoints:
- `GET /survey` - returns survey JSON (questions + domains)
- `POST /survey/submit` - anonymous submit; stores answers and domain scores
- `POST /admin/login` - returns JWT for admin user
- `GET /admin/aggregates` - returns aggregated domain averages and overall score (admin auth)
- `GET /admin/export` - CSV export of responses (admin auth)

Security / anonymity:
- Responses are stored without emails or identifiers; only a UUID is stored per response.
- Admins must login to see aggregated stats; no raw respondent PII is stored or exported.

Notes for production:
- Replace SQLite with Postgres (or managed DB like Amazon RDS).
- Use HTTPS and strong JWT secret stored in environment variables.
- Add role-based access for district vs principal views (per-school aggregation).
