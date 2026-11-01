# CyberGuard AI — Living Specification

## MVP purpose
CyberGuard AI is a safe, simulated Security Operations Center for the academic project “Threat Detection & Enhanced Cybersecurity Using Agentic AI”. It ingests synthetic events, classifies them with a deterministic local ML baseline, passes them through five auditable agents, applies a deterministic decision policy, records simulated responses, and exposes the result in a real-time dashboard.

## Data model
MongoDB collections: `users`, `security_events`, `threat_detections`, `agent_executions`, `incidents`, `response_actions`, `audit_logs`, `system_settings`, `datasets`, and `url_checks`. All application IDs are strings. `SAFE_MODE=true` is the default and no real system action is performed.

## Key flows
1. Existing users enter through `/login`; new users enter the separate `/signin` page and receive a VIEWER-only account. Admin signs in through `/api/auth/login` using `admin`, or the supported email alias `admin@cyberguard.local`, and receives an httpOnly JWT session cookie.
2. Dashboard reads backend KPIs and subscribes to `/api/ws/security-events`.
3. Start Simulation creates labeled synthetic events and runs Monitoring → Detection → Analysis → Decision → Response.
4. Threats with risk ≥ 51 open incidents; every response is stored as a completed simulated action and audit record.
5. Threat details show concise structured explanation and agent timeline; reports export CSV/PDF.
6. The main Dashboard includes an inline Analyze Event panel. It persists the submitted event through the same five-agent pipeline and clearly returns `THREAT PRESENT` or `NO THREAT` with confidence, risk, severity, and explanation.
7. Dataset Management accepts NSL-KDD-style CSV/TXT uploads, infers headers/features/classes, summarizes missing values/categorical columns/duplicates, stores a preview, and records the dataset for future training.
8. Dashboard and URL Checks accept an authorized public HTTP/HTTPS URL, perform one bounded passive fetch plus DNS/TLS/header/redirect/structure checks, persist the risk result through the SOC workflow, and explicitly state that the result is not proof of compromise or safety.
9. Security events, detections, agent executions, incidents, responses, URL checks, datasets, dashboards, analytics, exports, and audit reads are scoped to the authenticated username. Legacy unowned records are visible only to the seeded Admin. WebSocket events are delivered only to sockets owned by the same user.
10. Threat Detection includes a confirmed Delete History action that removes only the current account's detections and related workflow records while retaining a deletion audit entry.

## Roles
`ADMIN` can use all MVP controls, including model evaluation, settings, and incident updates. `ANALYST` can investigate and update incidents. `VIEWER` is read-only. The home page separates LOGIN for existing users from SIGN IN, which creates VIEWER-only accounts. A development admin account is seeded on first start (see README).

## ML and agent boundary
The local classifier answers “what activity pattern is this?” using deterministic rules over synthetic event features. The agents answer “what should happen next?” using deterministic policy thresholds. Metrics are computed on the labeled synthetic demonstration set and are explicitly not production or NSL-KDD benchmarks.

## Safety and limitations
No malware, exploit, credential theft, external scanning, firewall change, account lock, or endpoint isolation is implemented. Response labels such as `SIMULATED_BLOCK_IP` are records and UI demonstrations only. Uploaded dataset profiling is a preprocessing preview; it does not automatically promote a model or claim NSL-KDD benchmark performance. Feedback labeling, candidate retraining approval, and enterprise integrations remain future work.