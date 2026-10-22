"""Run container runtime checks with: python tests/check_container.py IMAGE."""
import json
import subprocess
import sys
import time


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, stderr=subprocess.PIPE, timeout=30,
    ).strip()


def check(image):
    runtime = docker("run", "--rm", "--entrypoint", "python", image, "-c", """
import os
import shutil
from io import BytesIO
from pathlib import Path
from xhtml2pdf import pisa
assert os.getuid() != 0
assert shutil.which('node') is None
assert shutil.which('cc') is None
probe = Path('data/example-runtime-check')
probe.write_text('example')
probe.unlink()
pdf = BytesIO()
assert pisa.CreatePDF('<html><body>Example</body></html>', dest=pdf).err == 0
assert pdf.getvalue().startswith(b'%PDF')
print('non-root runtime, writable data, PDF rendering, no build tools')
""")
    print(runtime)
    container = docker(
        "run", "--detach", "--env", "VERVET_DEMO_MODE=true",
        "--env", "VERVET_API_KEY=example-api-key", image,
    )
    try:
        for attempt in range(30):
            try:
                result = docker("exec", container, "python", "-c", """
import http.client
import json
import socket
connection = http.client.HTTPConnection(socket.gethostname(), 8000, timeout=2)
api_headers = {'X-API-Key': 'example-api-key', 'Content-Type': 'application/json'}
for path in ['/health', '/api/v1/analysis/threats']:
    connection.request('GET', path, headers=api_headers if path.startswith('/api/') else {})
    response = connection.getresponse()
    assert response.status == 200, (path, response.status)
    data = json.loads(response.read())
    if path == '/health':
        assert data == {'status': 'healthy'}
    else:
        assert data['total'] > 0, data
connection.request('PUT', '/api/v1/settings', body=json.dumps({'display': {'page_size': 25}}),
                   headers=api_headers)
response = connection.getresponse()
assert response.status == 200, ('settings write', response.status)
assert json.loads(response.read()) == {'status': 'saved'}
connection.request('GET', '/api/v1/settings', headers=api_headers)
response = connection.getresponse()
assert response.status == 200
assert json.loads(response.read())['display']['page_size'] == 25
connection.request('GET', '/api/v1/scoring/weights', headers=api_headers)
response = connection.getresponse()
assert response.status == 200
weights = json.loads(response.read())['weights']
connection.request('PUT', '/api/v1/scoring/weights', body=json.dumps(weights),
                   headers=api_headers)
response = connection.getresponse()
assert response.status == 200, ('weights write', response.status)
response.read()
connection.request('GET', '/')
response = connection.getresponse()
assert response.status == 200
assert b'<html' in response.read()
connection.request('GET', '/api/status')
response = connection.getresponse()
assert response.status == 401
response.read()
print(json.dumps({'health': 200, 'threats': 200, 'demo_hosts': data['total']}))
""")
                print(json.dumps(json.loads(result), sort_keys=True))
                return
            except subprocess.CalledProcessError as exc:
                if attempt == 29:
                    raise RuntimeError(exc.stderr.strip()) from exc
                time.sleep(1)
    finally:
        docker("rm", "--force", container)


if __name__ == "__main__":
    check(sys.argv[1])
