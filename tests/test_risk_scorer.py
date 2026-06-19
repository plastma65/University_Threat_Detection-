"""Unit tests for the risk scoring engine."""

from src.risk_scorer.scorer import RiskScorer


# ---------------------------------------------------------------------------
# calculate — end-to-end weighted formula
# ---------------------------------------------------------------------------


def test_calculate_bruteforce_from_firewall_high_anomaly():
    """raw=0.8 (norm=80) + bruteforce(100) + firewall(100) → 80*0.6+100*0.3+100*0.1 = 88."""
    assert RiskScorer().calculate(0.8, "firewall", "bruteforce", 1.0) == 88


def test_calculate_anomaly_from_db_medium_anomaly():
    """raw=0.5 (norm=50) + anomaly(40) + db(20) → 50*0.6+40*0.3+20*0.1 = 44."""
    assert RiskScorer().calculate(0.5, "db", "anomaly", 1.0) == 44


# ---------------------------------------------------------------------------
# should_alert — threshold gate at 70
# ---------------------------------------------------------------------------


def test_should_alert_above_threshold():
    assert RiskScorer().should_alert(88) is True


def test_should_alert_below_threshold():
    assert RiskScorer().should_alert(44) is False


# ---------------------------------------------------------------------------
# get_source_weight — table + default fallback
# ---------------------------------------------------------------------------


def test_get_source_weight_firewall():
    assert RiskScorer().get_source_weight("firewall") == 100


def test_get_source_weight_unknown_defaults_to_30():
    """Unknown source must fall back to 30, not raise."""
    assert RiskScorer().get_source_weight("xyz_unknown") == 30


# ---------------------------------------------------------------------------
# get_severity_weight — table lookup with aliases
# ---------------------------------------------------------------------------


def test_get_severity_weight_bruteforce():
    assert RiskScorer().get_severity_weight("bruteforce") == 100


def test_get_severity_weight_port_scan_alias():
    """port_scan is a recon alias and should weight 75."""
    assert RiskScorer().get_severity_weight("port_scan") == 75


# ---------------------------------------------------------------------------
# normalize_anomaly_score — degenerate batch
# ---------------------------------------------------------------------------


def test_normalize_anomaly_score_zero_max_returns_zero():
    """score_max <= 0 must return 0.0 instead of raising ZeroDivisionError."""
    assert RiskScorer().normalize_anomaly_score(0.5, score_max=0) == 0.0
