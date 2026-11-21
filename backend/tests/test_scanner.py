from __future__ import annotations

import os
import tempfile

import pytest

from app.services.scanner.directory_scanner import DirectoryScanner


@pytest.mark.asyncio
async def test_directory_scanner_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        file1 = os.path.join(tmpdir, "test1.txt")
        file2 = os.path.join(tmpdir, "test2.txt")
        subdir = os.path.join(tmpdir, "sub")
        os.makedirs(subdir)
        file3 = os.path.join(subdir, "test3.txt")

        for f in [file1, file2]:
            with open(f, "w") as fh:
                fh.write("hello world")

        with open(file3, "w") as fh:
            fh.write("nested file content")

        scanner = DirectoryScanner(path=tmpdir, thread_count=2, batch_size=10)
        results = await scanner.scan()

        assert len(results) == 3
        paths = {r["path"] for r in results}
        assert file1 in paths
        assert file2 in paths
        assert file3 in paths

        for r in results:
            assert r["size"] > 0
            assert r["name"] is not None
            assert r["extension"] is not None


@pytest.mark.asyncio
async def test_directory_scanner_exclusions():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "Windows"))
        os.makedirs(os.path.join(tmpdir, "data"))

        with open(os.path.join(tmpdir, "Windows", "system.dll"), "w") as f:
            f.write("dll content")

        with open(os.path.join(tmpdir, "data", "doc.txt"), "w") as f:
            f.write("doc content")

        scanner = DirectoryScanner(
            path=tmpdir,
            exclude_dirs=["Windows"],
        )
        results = await scanner.scan()

        assert len(results) == 1
        assert "doc.txt" in results[0]["name"]


@pytest.mark.asyncio
async def test_scanner_metadata():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "test_metadata.bin")
        data = b"\x00" * 100 + b"\xff" * 100 + b"\xAB" * 100
        with open(filepath, "wb") as f:
            f.write(data)

        scanner = DirectoryScanner(path=tmpdir)
        results = await scanner.scan()

        assert len(results) == 1
        r = results[0]
        assert r["name"] == "test_metadata.bin"
        assert r["extension"] == ".bin"
        assert r["size"] == 300
        assert r["entropy"] is not None
        assert r["permissions"] is not None
        assert r["volume"] is not None
