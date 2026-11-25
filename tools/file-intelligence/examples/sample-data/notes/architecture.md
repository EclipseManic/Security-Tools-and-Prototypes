# Demo architecture

The demo service consists of three components:

1. A web front end on `app.example.com`.
2. An API process that connects to `postgresql://demo:demo@db.internal.example:5432/demo`.
3. A nightly export job that writes CSV files to `s3://demo-exports/`.

Internal monitoring uses `http://10.20.30.40:9090/metrics`.

This document is synthetic. It is included to give the scanner a realistic mix
of URLs, connection strings, and prose.
