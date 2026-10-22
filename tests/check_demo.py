"""Check a running demo container with: python tests/check_demo.py IMAGE."""
import subprocess
import sys
import time


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], text=True, stderr=subprocess.PIPE, timeout=30,
    ).strip()


def check(image):
    container = docker("run", "--detach", "--env", "VERVET_DEMO_MODE=true", image)
    try:
        for attempt in range(30):
            try:
                result = docker("exec", container, "python", "-c", """
import http.client
import json
import socket
connection = http.client.HTTPConnection(socket.gethostname(), 8000, timeout=2)
for path in ['/health', '/api/v1/analysis/threats']:
    connection.request('GET', path)
    response = connection.getresponse()
    assert response.status == 200, (path, response.status)
    data = json.loads(response.read())
    if path == '/health':
        assert data == {'status': 'healthy'}
    else:
        assert data['total'] > 0, data
print(json.dumps({'health': 200, 'threats': 200, 'demo_hosts': data['total']}))
""")
                print(result)
                return
            except subprocess.CalledProcessError as exc:
                if attempt == 29:
                    raise RuntimeError(exc.stderr.strip()) from exc
                time.sleep(1)
    finally:
        docker("rm", "--force", container)


if __name__ == "__main__":
    check(sys.argv[1])
