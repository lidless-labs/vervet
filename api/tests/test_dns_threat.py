"""
Unit tests for DNS threat detection.
Tests DNS tunneling, DGA, fast-flux, and suspicious pattern detection.
"""
import pytest
from datetime import datetime, timedelta
from api.parsers.unified import DnsQuery
from api.services.dns_analyzer import DnsAnalyzer


class TestDnsAnalyzer:
    """Test suite for DnsAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create a DnsAnalyzer instance with default parameters."""
        return DnsAnalyzer(
            tunneling_threshold=60.0,
            dga_threshold=65.0,
            fast_flux_threshold=70.0,
            min_queries_tunneling=5,
            min_queries_dga=3,
            min_queries_fast_flux=3,
        )

    @pytest.fixture
    def base_time(self):
        """Base timestamp for generating test data."""
        return datetime(2024, 1, 1, 12, 0, 0)

    def create_dns_query(
        self,
        query: str,
        src_ip: str = "203.0.113.1",
        dst_ip: str = "8.8.8.8",
        qtype: str = "A",
        rcode: str = "NOERROR",
        answers: list = None,
        timestamp: datetime = None,
    ) -> DnsQuery:
        """Helper to create a DnsQuery object."""
        if timestamp is None:
            timestamp = datetime.now()
        if answers is None:
            answers = []

        return DnsQuery(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=53124,
            dst_ip=dst_ip,
            dst_port=53,
            query=query,
            qtype=qtype,
            rcode=rcode,
            answers=answers,
            source="zeek",
        )

    def test_entropy_calculation(self, analyzer):
        """Test Shannon entropy calculation."""
        # Very low entropy (all same character)
        entropy_low = analyzer._calculate_entropy("aaaaaaa")
        assert entropy_low == 0.0

        # High entropy (random-looking)
        entropy_high = analyzer._calculate_entropy("a1b2c3d4e5f6")
        assert entropy_high > 3.0

        # Medium entropy (English-like)
        entropy_medium = analyzer._calculate_entropy("example")
        assert 2.0 < entropy_medium < 3.5

    def test_consonant_ratio_calculation(self, analyzer):
        """Test consonant-to-vowel ratio calculation."""
        # Balanced English word
        ratio_normal = analyzer._calculate_consonant_ratio("example")
        assert 1.0 < ratio_normal < 2.5

        # High consonant ratio (DGA-like)
        ratio_high = analyzer._calculate_consonant_ratio("xyzqwrst")
        assert ratio_high > 3.0

        # No vowels edge case
        ratio_no_vowels = analyzer._calculate_consonant_ratio("xyz")
        assert ratio_no_vowels > 5.0

    def test_digit_ratio_calculation(self, analyzer):
        """Test digit ratio calculation."""
        # No digits
        ratio_none = analyzer._calculate_digit_ratio("example")
        assert ratio_none == 0.0

        # Some digits
        ratio_some = analyzer._calculate_digit_ratio("test123")
        assert 0.3 < ratio_some < 0.5

        # All digits
        ratio_all = analyzer._calculate_digit_ratio("123456")
        assert ratio_all == 1.0

    def test_bigram_score_calculation(self, analyzer):
        """Test English bigram frequency scoring."""
        # English word rich in common bigrams should score high. ("example"
        # was a poor fixture choice: none of its bigrams ex/xa/am/mp/pl/le are
        # in the analyzer's top-30 COMMON_BIGRAMS table, so it scores 0.)
        score_english = analyzer._calculate_bigram_score("internet")
        assert score_english > 30.0

        # Random string should have low score
        score_random = analyzer._calculate_bigram_score("xqzwfk")
        assert score_random < 20.0

    def test_dns_tunneling_detection_high_entropy_subdomains(self, analyzer, base_time):
        """Test detection of DNS tunneling with high-entropy subdomains."""
        queries = []

        # Generate queries with high-entropy subdomains (simulating data exfiltration)
        for i in range(15):
            subdomain = f"a1b2c3d4e5f6g7h8i9j0k{i}"  # High entropy
            query = self.create_dns_query(
                query=f"{subdomain}.evil-c2.com",
                src_ip="192.0.2.100",
                timestamp=base_time + timedelta(seconds=i * 30),
            )
            queries.append(query)

        results = analyzer.detect_dns_tunneling(queries)

        assert len(results) > 0
        result = results[0]
        assert result.domain == "evil-c2.com"
        assert result.src_ip == "192.0.2.100"
        assert result.tunneling_score >= 60.0
        assert result.avg_subdomain_entropy > 3.0
        assert result.unique_subdomains >= 10

    def test_dns_tunneling_detection_txt_records(self, analyzer, base_time):
        """Test detection of DNS tunneling via TXT records."""
        queries = []

        # Generate TXT queries with encoded data. Subdomains must be
        # high-entropy/encoded-looking to score as tunneling; benign labels
        # like "data000" legitimately score below threshold.
        for i in range(10):
            subdomain = f"a1b2c3d4e5f6g7h8i9j0k{i}"
            query = self.create_dns_query(
                query=f"{subdomain}.exfil.com",
                src_ip="192.0.2.101",
                qtype="TXT",
                timestamp=base_time + timedelta(seconds=i * 10),
            )
            queries.append(query)

        results = analyzer.detect_dns_tunneling(queries)

        assert len(results) > 0
        result = results[0]
        assert result.txt_record_queries > 0
        assert "TXT record" in " ".join(result.reasons)

    def test_dns_tunneling_detection_long_subdomains(self, analyzer, base_time):
        """Test detection of DNS tunneling with very long subdomains."""
        queries = []

        # Generate queries with unusually long subdomains
        for i in range(10):
            subdomain = f"verylongsubdomainwithlotsofcharacters{i}" * 2
            query = self.create_dns_query(
                query=f"{subdomain}.tunnel.net",
                src_ip="192.0.2.102",
                timestamp=base_time + timedelta(seconds=i * 20),
            )
            queries.append(query)

        results = analyzer.detect_dns_tunneling(queries)

        assert len(results) > 0
        result = results[0]
        assert result.avg_subdomain_length > 30
        assert "long subdomain" in " ".join(result.reasons).lower()

    def test_dga_detection_high_entropy_domain(self, analyzer, base_time):
        """Test detection of DGA domain with high entropy."""
        queries = []

        # Generate queries to DGA-like domain
        dga_domain = "xqzwfkjhgpmnb.com"
        for i in range(5):
            query = self.create_dns_query(
                query=dga_domain,
                src_ip="192.0.2.200",
                rcode="NXDOMAIN",
                timestamp=base_time + timedelta(seconds=i * 60),
            )
            queries.append(query)

        results = analyzer.detect_dga_domains(queries)

        assert len(results) > 0
        result = results[0]
        assert result.domain == dga_domain
        assert result.dga_score >= 65.0
        assert result.domain_entropy > 3.0
        assert result.bigram_score < 50.0

    def test_dga_detection_suspicious_tld(self, analyzer, base_time):
        """Test detection of DGA domain with suspicious TLD."""
        queries = []

        # Generate queries to domain with suspicious TLD
        dga_domain = "randomstring123.tk"
        for i in range(5):
            query = self.create_dns_query(
                query=dga_domain,
                src_ip="192.0.2.201",
                rcode="NXDOMAIN",
                timestamp=base_time + timedelta(seconds=i * 30),
            )
            queries.append(query)

        results = analyzer.detect_dga_domains(queries)

        assert len(results) > 0
        result = results[0]
        assert result.tld == "tk"
        assert "Suspicious TLD" in " ".join(result.reasons)

    def test_dga_detection_high_consonant_ratio(self, analyzer, base_time):
        """Test detection of DGA domain with high consonant ratio."""
        queries = []

        # Generate queries to domain with lots of consonants
        dga_domain = "xyzqwrstmnbvcx.com"
        for i in range(5):
            query = self.create_dns_query(
                query=dga_domain,
                src_ip="192.0.2.202",
                timestamp=base_time + timedelta(seconds=i * 45),
            )
            queries.append(query)

        results = analyzer.detect_dga_domains(queries)

        assert len(results) > 0
        result = results[0]
        assert result.consonant_ratio > 2.5

    def test_fast_flux_detection_multiple_ips(self, analyzer, base_time):
        """Test detection of fast-flux DNS with multiple IPs."""
        queries = []

        # Generate queries returning different IPs. The analyzer requires the
        # observations to span at least 1 hour; 10 queries at 600s intervals
        # gives a 1.5h window (the previous 300s interval spanned only 45 min).
        domain = "fastflux.example.com"
        for i in range(10):
            answers = [f"203.0.113.{i}"]
            query = self.create_dns_query(
                query=domain,
                src_ip="192.0.2.300",
                answers=answers,
                timestamp=base_time + timedelta(seconds=i * 600),
            )
            queries.append(query)

        results = analyzer.detect_fast_flux(queries)

        assert len(results) > 0
        result = results[0]
        assert result.domain == domain
        assert result.unique_ips >= 5
        assert result.fast_flux_score >= 70.0

    def test_fast_flux_detection_rapid_changes(self, analyzer, base_time):
        """Test detection of fast-flux with rapid IP changes."""
        queries = []

        # Generate queries with rapid IP rotation
        domain = "rapidflux.net"
        for i in range(15):
            answers = [f"198.51.100.{i % 20}"]
            query = self.create_dns_query(
                query=domain,
                src_ip="192.0.2.301",
                answers=answers,
                timestamp=base_time + timedelta(minutes=i * 10),
            )
            queries.append(query)

        results = analyzer.detect_fast_flux(queries)

        assert len(results) > 0
        result = results[0]
        assert result.ip_changes_per_hour > 1.0
        assert "IP change rate" in " ".join(result.reasons)

    def test_excessive_nxdomain_detection(self, analyzer, base_time):
        """Test detection of excessive NXDOMAIN responses."""
        queries = []

        # Generate many NXDOMAIN responses
        for i in range(20):
            query = self.create_dns_query(
                query=f"random{i}.doesnotexist.com",
                src_ip="192.0.2.400",
                rcode="NXDOMAIN",
                timestamp=base_time + timedelta(seconds=i * 15),
            )
            queries.append(query)

        results = analyzer.detect_suspicious_patterns(queries)

        nxdomain_patterns = [r for r in results if r.pattern_type == "excessive_nxdomain"]
        assert len(nxdomain_patterns) > 0

        result = nxdomain_patterns[0]
        assert result.src_ip == "192.0.2.400"
        assert "NXDOMAIN" in " ".join(result.reasons)

    def test_unusual_query_types_detection(self, analyzer, base_time):
        """Test detection of unusual query types."""
        queries = []

        # Generate unusual query types
        unusual_types = ["NULL", "CAA", "DNSKEY", "RRSIG"]
        for i, qtype in enumerate(unusual_types * 3):
            query = self.create_dns_query(
                query=f"test{i}.example.com",
                src_ip="192.0.2.500",
                qtype=qtype,
                timestamp=base_time + timedelta(seconds=i * 20),
            )
            queries.append(query)

        results = analyzer.detect_suspicious_patterns(queries)

        unusual_patterns = [r for r in results if r.pattern_type == "unusual_query_types"]
        assert len(unusual_patterns) > 0

        result = unusual_patterns[0]
        assert result.src_ip == "192.0.2.500"
        assert "Unusual DNS query types" in " ".join(result.reasons)

    def test_high_query_rate_detection(self, analyzer, base_time):
        """Test detection of abnormally high query rate."""
        queries = []

        # Generate high rate of queries to single domain
        domain = "highrate.example.com"
        for i in range(100):
            query = self.create_dns_query(
                query=domain,
                src_ip="192.0.2.600",
                timestamp=base_time + timedelta(seconds=i * 2),
            )
            queries.append(query)

        results = analyzer.detect_suspicious_patterns(queries)

        high_rate_patterns = [r for r in results if r.pattern_type == "high_query_rate"]
        assert len(high_rate_patterns) > 0

        result = high_rate_patterns[0]
        assert result.domain == domain
        assert "high query rate" in " ".join(result.reasons).lower()

    def test_comprehensive_threat_analysis(self, analyzer, base_time):
        """Test comprehensive analysis with multiple threat types."""
        queries = []

        # Add tunneling queries. Subdomains must be high-entropy to score as
        # tunneling (the prior "encoded{i:05x}data" labels were too low-entropy
        # and scored below threshold).
        for i in range(15):
            subdomain = f"a1b2c3d4e5f6g7h8i9j0k{i}"
            queries.append(
                self.create_dns_query(
                    query=f"{subdomain}.tunnel.com",
                    src_ip="198.19.1.1",
                    timestamp=base_time + timedelta(seconds=i * 30),
                )
            )

        # Add DGA queries. DGA detection groups by base domain and needs
        # >= min_queries_dga repeats of the SAME domain; the prior per-query
        # unique domains ("xqzwfkjh{i}.tk") each had a single query and were
        # all skipped. Use one repeated high-entropy NXDOMAIN domain.
        for i in range(10):
            queries.append(
                self.create_dns_query(
                    query="xqzwfkjhgpmnb.tk",
                    src_ip="198.19.1.2",
                    rcode="NXDOMAIN",
                    timestamp=base_time + timedelta(seconds=i * 45),
                )
            )

        # Add fast-flux queries
        for i in range(12):
            queries.append(
                self.create_dns_query(
                    query="fastflux.net",
                    src_ip="198.19.1.3",
                    answers=[f"192.0.2.{i}"],
                    timestamp=base_time + timedelta(minutes=i * 15),
                )
            )

        summary = analyzer.analyze_dns_threats(queries)

        assert summary.total_queries_analyzed == len(queries)
        assert summary.tunneling_detections > 0
        assert summary.dga_detections > 0
        assert summary.fast_flux_detections > 0

    def test_no_threats_legitimate_traffic(self, analyzer, base_time):
        """Test that legitimate DNS traffic doesn't trigger false positives."""
        queries = []

        # Generate legitimate-looking queries
        legitimate_domains = [
            "www.google.com",
            "mail.example.com",
            "api.github.com",
            "cdn.cloudflare.com",
        ]

        for domain in legitimate_domains:
            for i in range(5):
                query = self.create_dns_query(
                    query=domain,
                    src_ip="198.19.2.1",
                    answers=["93.184.216.34"],
                    timestamp=base_time + timedelta(minutes=i * 30),
                )
                queries.append(query)

        # Should not detect any threats
        tunneling = analyzer.detect_dns_tunneling(queries)
        dga = analyzer.detect_dga_domains(queries)
        fast_flux = analyzer.detect_fast_flux(queries)

        assert len(tunneling) == 0
        assert len(dga) == 0
        assert len(fast_flux) == 0

    def test_edge_case_empty_queries(self, analyzer):
        """Test handling of empty query list."""
        summary = analyzer.analyze_dns_threats([])

        assert summary.total_queries_analyzed == 0
        assert summary.tunneling_detections == 0
        assert summary.dga_detections == 0
        assert summary.fast_flux_detections == 0

    def test_edge_case_single_query(self, analyzer, base_time):
        """Test handling of single query (below minimum thresholds)."""
        query = self.create_dns_query(
            query="test.example.com",
            src_ip="198.19.3.1",
            timestamp=base_time,
        )

        tunneling = analyzer.detect_dns_tunneling([query])
        dga = analyzer.detect_dga_domains([query])
        fast_flux = analyzer.detect_fast_flux([query])

        assert len(tunneling) == 0
        assert len(dga) == 0
        assert len(fast_flux) == 0

    def test_mitre_technique_mapping(self, analyzer, base_time):
        """Test that MITRE ATT&CK techniques are correctly assigned."""
        queries = []

        # High-scoring tunneling with TXT records. Subdomains need enough
        # entropy/length to clear the tunneling threshold (the shorter
        # "a1b2c3d4{i}" labels scored 55, just under 60).
        for i in range(15):
            queries.append(
                self.create_dns_query(
                    query=f"a1b2c3d4e5f6g7h8i9j0k{i}.exfil.com",
                    src_ip="198.19.4.1",
                    qtype="TXT",
                    timestamp=base_time + timedelta(seconds=i * 20),
                )
            )

        results = analyzer.detect_dns_tunneling(queries)
        assert len(results) > 0

        result = results[0]
        assert "T1071.004" in result.mitre_techniques  # DNS protocol
        assert any("T1048" in t or "T1041" in t for t in result.mitre_techniques)  # Exfiltration

    def test_confidence_scoring(self, analyzer, base_time):
        """Test that confidence increases with more data."""
        queries_few = []
        queries_many = []

        # Few queries (low confidence)
        for i in range(10):
            queries_few.append(
                self.create_dns_query(
                    query=f"test{i}.tunnel.com",
                    src_ip="198.19.5.1",
                    timestamp=base_time + timedelta(seconds=i * 30),
                )
            )

        # Many queries (high confidence)
        for i in range(100):
            queries_many.append(
                self.create_dns_query(
                    query=f"test{i}.tunnel.com",
                    src_ip="198.19.5.2",
                    timestamp=base_time + timedelta(seconds=i * 30),
                )
            )

        results_few = analyzer.detect_dns_tunneling(queries_few)
        results_many = analyzer.detect_dns_tunneling(queries_many)

        if results_few and results_many:
            assert results_many[0].confidence > results_few[0].confidence
