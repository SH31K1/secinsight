import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_backend.db")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient

from app.main import app

SAMPLE_NMAP = os.path.join(os.path.dirname(__file__), "..", "..", "core", "tests", "fixtures", "nmap_sample.xml")


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_list_tools(client):
    r = client.get("/api/scans/tools")
    assert r.status_code == 200
    assert "nmap" in r.json()["tools"]


def test_upload_and_analyze(client):
    with open(SAMPLE_NMAP, "rb") as f:
        r = client.post("/api/scans", files={"file": ("nmap.xml", f, "text/xml")})
    assert r.status_code == 200
    body = r.json()
    assert body["tool"] == "nmap"
    assert 0 <= body["score"] <= 100
    assert len(body["findings"]) > 0


def test_get_scan_and_score(client):
    with open(SAMPLE_NMAP, "rb") as f:
        r = client.post("/api/scans", files={"file": ("nmap.xml", f, "text/xml")})
    scan_id = r.json()["id"]

    r2 = client.get(f"/api/scans/{scan_id}")
    assert r2.status_code == 200

    r3 = client.get(f"/api/scans/{scan_id}/score")
    assert r3.status_code == 200
    assert "summary" in r3.json()


def test_scan_not_found(client):
    r = client.get("/api/scans/does-not-exist")
    assert r.status_code == 404


def test_dashboard_overview(client):
    with open(SAMPLE_NMAP, "rb") as f:
        client.post("/api/scans", files={"file": ("nmap.xml", f, "text/xml")})
    r = client.get("/api/scans/dashboard/overview")
    assert r.status_code == 200
    assert r.json()["total_scans"] >= 1


def test_generate_and_download_report(client):
    with open(SAMPLE_NMAP, "rb") as f:
        r = client.post("/api/scans", files={"file": ("nmap.xml", f, "text/xml")})
    scan_id = r.json()["id"]

    r2 = client.post(f"/api/reports/{scan_id}/generate?format=html&mode=student")
    assert r2.status_code == 200
    download_url = r2.json()["download_url"]

    r3 = client.get(download_url)
    assert r3.status_code == 200
    assert b"SecInsight" in r3.content


def test_compare_endpoint(client):
    with open(SAMPLE_NMAP, "rb") as f:
        r1 = client.post("/api/scans", files={"file": ("nmap.xml", f, "text/xml")})
    with open(SAMPLE_NMAP, "rb") as f:
        r2 = client.post("/api/scans", files={"file": ("nmap.xml", f, "text/xml")})
    id1, id2 = r1.json()["id"], r2.json()["id"]

    r3 = client.get(f"/api/compare/{id1}/{id2}")
    assert r3.status_code == 200
    assert "summary" in r3.json()


def test_bad_file_upload(client, tmp_path):
    bad_file = tmp_path / "bad.xml"
    bad_file.write_text("this is not a valid scan file at all")
    with open(bad_file, "rb") as f:
        r = client.post("/api/scans", files={"file": ("bad.xml", f, "text/xml")})
    assert r.status_code == 422
