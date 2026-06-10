"""Tests for tshark PCAP converter."""

from api.parsers.pcap_converter import convert_tshark_json


def test_convert_tshark_json_maps_connection_and_dns():
    tshark_output = [
        {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.number": "1",
                        "frame.time_epoch": "1739617200.123",
                        "frame.len": "128",
                    },
                    "ip": {"ip.src": "198.19.11.5", "ip.dst": "8.8.8.8"},
                    "udp": {"udp.srcport": "51515", "udp.dstport": "53"},
                    "dns": {
                        "dns.qry.name": "example.com",
                        "dns.qry.type": "1",
                        "dns.flags.rcode": "0",
                        "dns.a": ["93.184.216.34"],
                    },
                }
            }
        }
    ]

    connections, dns_queries, alerts = convert_tshark_json(tshark_output)

    assert len(connections) == 1
    assert connections[0].src_ip == "198.19.11.5"
    assert connections[0].dst_ip == "8.8.8.8"
    assert connections[0].service == "dns"

    assert len(dns_queries) == 1
    assert dns_queries[0].query == "example.com"
    assert dns_queries[0].answers == ["93.184.216.34"]

    assert alerts == []


def test_convert_tshark_json_handles_missing_layers_gracefully():
    tshark_output = [
        {"_source": {"layers": {"frame": {"frame.time_epoch": "1739617200.1"}}}},
        {
            "_source": {
                "layers": {
                    "frame": {"frame.time_epoch": "1739617200.2", "frame.len": "60"},
                    "ip": {"ip.src": "192.0.2.10", "ip.dst": "1.1.1.1"},
                    "tcp": {"tcp.srcport": "50123", "tcp.dstport": "443", "tcp.flags.str": "0x00000018"},
                }
            }
        },
    ]

    connections, dns_queries, alerts = convert_tshark_json(tshark_output)

    assert len(connections) == 1
    assert connections[0].proto == "tcp"
    assert connections[0].dst_port == 443
    assert connections[0].conn_state == "0x00000018"
    assert dns_queries == []
    assert alerts == []
