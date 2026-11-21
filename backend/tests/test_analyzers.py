from __future__ import annotations

import os
import tempfile

import pytest

from app.services.analyzer.orchestrator import AnalysisOrchestrator


@pytest.fixture
def orchestrator():
    return AnalysisOrchestrator()


@pytest.mark.asyncio
async def test_text_analyzer(orchestrator):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("Hello, this is a test document.\nIt has multiple lines.\nLine three.")
        f.flush()
        fpath = f.name

    try:
        result = await orchestrator.analyze_file(fpath)
        assert result["analyzer_type"] == "text"
        assert result["extracted_text"] is not None
        assert "Hello" in result["extracted_text"]
        assert result["metadata"] is not None
        assert result["metadata"]["line_count"] == 3
        assert result["error"] is None
    finally:
        os.unlink(fpath)


@pytest.mark.asyncio
async def test_code_analyzer(orchestrator):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("""import os
import sys

def greet(name):
    print(f"Hello, {name}")

class MyClass:
    pass
""")
        f.flush()
        fpath = f.name

    try:
        result = await orchestrator.analyze_file(fpath)
        assert result["analyzer_type"] == "code"
        assert result["analysis_details"] is not None
        assert result["analysis_details"]["language"] == "Python"
        assert len(result["analysis_details"]["imports"]) >= 2
        assert "greet" in str(result["analysis_details"]["functions"])
        assert "MyClass" in str(result["analysis_details"]["classes"])
    finally:
        os.unlink(fpath)


@pytest.mark.asyncio
async def test_pdf_analyzer(orchestrator):
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        fpath = f.name

    try:
        import fitz
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 50), "Hello from FIP PDF test")
        doc.save(fpath)
        doc.close()

        result = await orchestrator.analyze_file(fpath)
        assert result["analyzer_type"] == "pdf"
        assert result["metadata"] is not None
        assert result["metadata"]["page_count"] >= 1
        assert result["error"] is None

    finally:
        os.unlink(fpath)


@pytest.mark.asyncio
async def test_image_analyzer(orchestrator):
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        fpath = f.name

    try:
        from PIL import Image
        img = Image.new("RGB", (100, 100), color="red")
        img.save(fpath)

        result = await orchestrator.analyze_file(fpath)
        assert result["analyzer_type"] == "image"
        assert result["metadata"] is not None
        assert result["metadata"]["width"] == 100
        assert result["metadata"]["height"] == 100
        assert result["error"] is None

    finally:
        os.unlink(fpath)


@pytest.mark.asyncio
async def test_unsupported_file(orchestrator):
    with tempfile.NamedTemporaryFile(suffix=".xyz", delete=False) as f:
        fpath = f.name

    try:
        result = await orchestrator.analyze_file(fpath)
        assert result["analyzer_type"] == "none"
    finally:
        os.unlink(fpath)


@pytest.mark.asyncio
async def test_zip_analyzer(orchestrator):
    import zipfile

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        fpath = f.name

    try:
        with zipfile.ZipFile(fpath, "w") as zf:
            zf.writestr("test.txt", "hello world")
            zf.writestr("data.csv", "a,b,c\n1,2,3")

        result = await orchestrator.analyze_file(fpath)
        assert result["analyzer_type"] == "archive"
        assert result["metadata"] is not None
        assert result["metadata"]["entry_count"] == 2
        assert result["error"] is None

    finally:
        os.unlink(fpath)
