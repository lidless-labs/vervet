#!/usr/bin/env python3
"""
Performance test for beacon detection.
Tests that analyzer can handle 100k+ connections in under 5 seconds.
"""
import time
from datetime import datetime, timedelta
import random

# Mock minimal dependencies for standalone test
class Connection:
    def __init__(self, src_ip, dst_ip, dst_port, timestamp):
        self.uid = f"{random.randint(1000000, 9999999)}"
        self.src_ip = src_ip
        self.src_port = random.randint(50000, 60000)
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.proto = "tcp"
        self.service = "http"
        self.duration = 1.0
        self.bytes_sent = random.randint(100, 5000)
        self.bytes_recv = random.randint(100, 5000)
        self.timestamp = timestamp
        self.tags = []
        self.source = "test"
        self.conn_state = "SF"
        self.pkts_sent = 10
        self.pkts_recv = 10


def generate_test_data(num_connections=100000, num_beacons=5):
    """Generate test data with mix of beacon and normal traffic."""
    print(f"Generating {num_connections} connections with {num_beacons} beacons...")

    connections = []
    base_time = datetime(2024, 1, 1, 0, 0, 0)

    # Generate beacons (regular intervals)
    connections_per_beacon = 50
    for beacon_id in range(num_beacons):
        src_ip = f"192.0.2.{100 + beacon_id}"
        dst_ip = f"203.0.113.{50 + beacon_id}"
        dst_port = 443
        interval = 60.0  # 60 second intervals

        for i in range(connections_per_beacon):
            timestamp = base_time + timedelta(seconds=i * interval)
            conn = Connection(src_ip, dst_ip, dst_port, timestamp)
            connections.append(conn)

    # Generate normal traffic (random)
    num_normal = num_connections - (num_beacons * connections_per_beacon)

    src_ips = [f"198.18.{i}.{j}" for i in range(1, 20) for j in range(1, 20)]
    dst_ips = [f"198.19.{i}.{j * 10 + k}" for i in range(1, 10) for j in range(1, 10) for k in range(1, 10)]

    for i in range(num_normal):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        dst_port = random.choice([80, 443, 8080, 8443, 3000, 3306, 5432])

        # Random timestamp within 24 hour window
        offset = random.uniform(0, 86400)
        timestamp = base_time + timedelta(seconds=offset)

        conn = Connection(src_ip, dst_ip, dst_port, timestamp)
        connections.append(conn)

    print(f"Generated {len(connections)} total connections")
    return connections


def test_performance():
    """Test beacon detection performance."""
    print("\n=== Beacon Detection Performance Test ===\n")

    # Generate test data
    connections = generate_test_data(num_connections=100000, num_beacons=5)

    # Import analyzer (will fail if dependencies not installed)
    try:
        from api.services.beacon_analyzer import BeaconAnalyzer
        from api.config.allowlists import BeaconAllowlist
    except ImportError as e:
        print(f"ERROR: Cannot import beacon analyzer: {e}")
        print("This test requires dependencies to be installed.")
        print("Run from environment with: pip install -r requirements.txt")
        return False

    # Initialize analyzer
    analyzer = BeaconAnalyzer(
        min_connections=10,
        max_jitter_pct=20.0,
        min_time_span_hours=1.0,
        score_threshold=70.0,
    )

    # Run analysis and time it
    print(f"Analyzing {len(connections)} connections...")
    start_time = time.time()

    beacons = analyzer.analyze_connections(connections)

    elapsed_time = time.time() - start_time

    # Results
    print(f"\n--- Results ---")
    print(f"Connections analyzed: {len(connections):,}")
    print(f"Beacons detected: {len(beacons)}")
    print(f"Analysis time: {elapsed_time:.2f} seconds")
    print(f"Throughput: {len(connections) / elapsed_time:,.0f} connections/second")

    # Check performance requirement
    if elapsed_time < 5.0:
        print(f"\n✓ PASS: Analysis completed in {elapsed_time:.2f}s (< 5s requirement)")
        success = True
    else:
        print(f"\n✗ FAIL: Analysis took {elapsed_time:.2f}s (> 5s requirement)")
        success = False

    # Show detected beacons
    if beacons:
        print(f"\n--- Top 5 Detected Beacons ---")
        for i, beacon in enumerate(beacons[:5], 1):
            print(f"{i}. {beacon.src_ip} -> {beacon.dst_ip}:{beacon.dst_port}")
            print(f"   Score: {beacon.beacon_score:.1f}, Jitter: {beacon.jitter_pct:.1f}%, Connections: {beacon.connection_count}")

    return success


if __name__ == "__main__":
    try:
        success = test_performance()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
