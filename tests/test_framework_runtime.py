"""Runtime contracts for FastAPI form parsing and multipart bounds."""

from typing import Annotated

import pytest
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    app = FastAPI()

    @app.post("/upload")
    async def upload(
        file: Annotated[UploadFile, File()],
        note: Annotated[str, Form()] = "example",
    ):
        return {
            "filename": file.filename,
            "content": (await file.read()).decode(),
            "note_size": len(note),
        }

    @app.post("/bounded-form")
    async def bounded_form(request: Request):
        async with request.form(max_files=1, max_fields=1) as form:
            return {"parts": len(form)}

    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("note_size, status", [(1024 * 1024, 200), (1024 * 1024 + 1, 400)])
def test_upload_enforces_default_field_size(client, note_size, status):
    response = client.post(
        "/upload",
        files={"file": ("example.txt", b"example", "text/plain")},
        data={"note": "a" * note_size},
    )
    assert response.status_code == status
    if status == 200:
        assert response.json() == {
            "filename": "example.txt",
            "content": "example",
            "note_size": note_size,
        }
    else:
        assert response.json() == {"detail": "Part exceeded maximum size of 1024KB."}


@pytest.mark.parametrize(
    "parts, detail",
    [
        ([('first', ('example.txt', b'one')), ('second', ('example.txt', b'two'))],
         "Too many files. Maximum number of files is 1."),
        ([('first', (None, 'one')), ('second', (None, 'two'))],
         "Too many fields. Maximum number of fields is 1."),
    ],
    ids=["file-count", "field-count"],
)
def test_form_enforces_explicit_part_counts(client, parts, detail):
    response = client.post("/bounded-form", files=parts)
    assert response.status_code == 400
    assert response.json() == {"detail": detail}


@pytest.mark.parametrize(
    "extra_headers",
    [b"X-Example: " + b"a" * (64 * 1024) + b"\r\n", b"X-Example: a\r\n" * 129],
    ids=["header-size", "header-count"],
)
def test_upload_rejects_headers_over_default_bounds(client, extra_headers):
    body = (
        b'--example\r\nContent-Disposition: form-data; name="file"; filename="example.txt"\r\n'
        + extra_headers
        + b"\r\nexample\r\n--example--\r\n"
    )
    response = client.post(
        "/upload", content=body,
        headers={"Content-Type": "multipart/form-data; boundary=example"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid multipart data."}


def test_upload_rejects_missing_disposition_name(client):
    response = client.post(
        "/upload",
        content=b'--example\r\nContent-Disposition: form-data; filename="example.txt"\r\n\r\nexample\r\n--example--\r\n',
        headers={"Content-Type": "multipart/form-data; boundary=example"},
    )
    assert response.status_code == 400
    assert response.json() == {
        "detail": 'The Content-Disposition header field "name" must be provided.'
    }
