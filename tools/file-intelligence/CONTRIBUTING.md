# Contributing

Thanks for taking a look at File Intelligence Platform.

## Development setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt

cd frontend
npm ci
cd ..
```

Run the development servers:

```bash
python run.py --dev
```

Or run the API only:

```bash
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Before opening a pull request

```bash
cd backend
python -m pytest -q
ruff check app tests

cd ../frontend
npm run build
```

- Keep the default bind on loopback. Do not add an option that exposes the
  scanner by default.
- Add a test for a new detector pattern or analyzer behaviour.
- Do not commit `.env`, `backend/data/`, generated reports, or real scan
  output. Use the synthetic data in `examples/sample-data` instead.
- Keep user-facing text and error messages specific and free of personal paths.

## Detector patterns

Patterns live in `backend/app/services/detector/patterns.py` as
`(name, severity, category, regex)` tuples. Add the narrowest expression that
matches the real format, include a synthetic example in the test suite, and
explain the severity choice in the pull request.

## Reporting a security issue

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
