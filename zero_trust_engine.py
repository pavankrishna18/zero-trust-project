"""
zero_trust_engine.py
=====================
Phase 7 — Continuous Zero Trust Verification.

Implements the 8-factor verification model on every authenticated request:

    Identity + Device + Location + Risk + Behavior + Time + Resource + Session

Design goal: a successful login is only the FIRST checkpoint. This module is
called from app.py's before_request hook on every subsequent request and
re-scores trust continuously. If composite risk crosses a threshold, the
session is stepped-up (forced re-auth) or terminated — login success alone
never grants standing trust.

This module is intentionally additive: it composes the existing
RiskScoringEngine, DeviceTrustService, GeoLocationService and resource
helpers rather than re-implementing them, so behavior you already validated
(e.g. risk_scoring.py's location/time/device/velocity checks) is reused
as the "Risk" factor instead of duplicated.
"""

from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger(__name__)

# Composite score bands (0-100, higher = riskier)
SCORE_ALLOW = 39          # <= this: continue silently
SCORE_STEP_UP = 69        # <= this: allow but require re-authentication
# > SCORE_STEP_UP: block / terminate session

# How often (seconds) we re-run the full composite evaluation for a given
# session. Cheap factors (resource/session) still run every request; the
# heavier ones (geo lookups) are throttled via this interval.
REEVALUATION_INTERVAL_SECONDS = 60


class VerificationResult:
    """Outcome of one continuous-verification pass."""

    __slots__ = ("decision", "score", "factors", "reasons")

    def __init__(self, decision, score, factors, reasons):
        self.decision = decision          # 'allow' | 'step_up' | 'block'
        self.score = score                # 0-100 composite risk score
        self.factors = factors            # dict of per-factor scores/notes
        self.reasons = reasons            # list[str] human-readable reasons

    def to_dict(self):
        return {
            "decision": self.decision,
            "score": self.score,
            "factors": self.factors,
            "reasons": self.reasons,
        }


def _factor_identity(user):
    """Identity: is the authenticated principal still valid/active?"""
    if not user.is_active or user.is_locked:
        return 100, "Account is inactive or locked"
    return 0, None


def _factor_device(user, device):
    """Device: trust posture of the device making the request."""
    if device is None:
        return 60, "Unrecognized/unregistered device"
    if getattr(device, "is_compromised", False):
        return 100, "Device flagged as compromised"
    if not device.is_trusted:
        return 45, "Device not yet trusted/approved"
    security_score = getattr(device, "security_score", 100) or 100
    return max(0, 100 - security_score), None


def _factor_location(risk_components):
    val = risk_components.get("location_risk", 0)
    return val, ("Location risk elevated" if val >= 30 else None)


def _factor_behavior(user, client_ip, risk_components):
    """Behavior: deviation from established usage patterns (velocity,
    failed-attempt clustering). Reuses RiskScoringEngine sub-scores."""
    velocity = risk_components.get("velocity_risk", 0)
    failed = risk_components.get("failed_attempts_risk", 0)
    score = max(velocity, failed)
    reason = "Unusual request velocity or recent failed attempts" if score >= 30 else None
    return score, reason


def _factor_time(risk_components):
    val = risk_components.get("time_risk", 0)
    return val, ("Access outside the user's normal hours" if val >= 30 else None)


def _factor_resource(user, resource_id):
    """Resource: does the user's role/permission set actually cover the
    resource being requested? Delegates to resources.validate_resource_access
    so policy stays in one place."""
    if not resource_id:
        return 0, None
    try:
        from resources import validate_resource_access
        allowed, _msg = validate_resource_access(user, resource_id)
        return (0, None) if allowed else (100, f"Not authorized for resource '{resource_id}'")
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("resource factor check skipped: %s", e)
        return 0, None


def _factor_session(session_record):
    """Session: age/integrity of the session token itself."""
    if session_record is None:
        return 20, "No tracked session record"
    if not session_record.is_active:
        return 100, "Session has been terminated server-side"
    return 0, None


def evaluate(user, client_ip, user_agent, device=None, session_record=None,
             resource_id=None):
    """
    Run the full 8-factor continuous verification pass.

    Returns a VerificationResult. Cheap to call on every request; the
    expensive sub-checks already live in RiskScoringEngine and are reused,
    not recomputed twice.
    """
    from risk_scoring import RiskScoringEngine

    base_risk = RiskScoringEngine.calculate_risk_score(user, client_ip, user_agent, device)
    components = base_risk.get("components", base_risk) if isinstance(base_risk, dict) else {}

    factors = {}
    reasons = []

    for name, (score, reason) in {
        "identity": _factor_identity(user),
        "device": _factor_device(user, device),
        "location": _factor_location(components),
        "risk": (components.get("overall_risk", base_risk.get("score", 0) if isinstance(base_risk, dict) else 0), None),
        "behavior": _factor_behavior(user, client_ip, components),
        "time": _factor_time(components),
        "resource": _factor_resource(user, resource_id),
        "session": _factor_session(session_record),
    }.items():
        factors[name] = score
        if reason:
            reasons.append(reason)

    # Weighted composite — identity/session/resource are binary trust
    # boundaries so they dominate; risk/device/behavior are gradients.
    weights = {
        "identity": 1.0, "device": 0.8, "location": 0.6, "risk": 1.0,
        "behavior": 0.8, "time": 0.4, "resource": 1.0, "session": 1.0,
    }
    weighted_sum = sum(factors[k] * weights[k] for k in factors)
    total_weight = sum(weights.values())
    composite = round(weighted_sum / total_weight, 1)

    # A hard fail on identity/resource/session always blocks regardless
    # of the blended average — those are trust boundaries, not gradients.
    hard_block = factors["identity"] >= 100 or factors["resource"] >= 100 or factors["session"] >= 100

    if hard_block:
        decision = "block"
    elif composite > SCORE_STEP_UP:
        decision = "block"
    elif composite > SCORE_ALLOW:
        decision = "step_up"
    else:
        decision = "allow"

    return VerificationResult(decision, composite, factors, reasons)


def should_reevaluate(session_record):
    """Throttle: only re-run the full composite check periodically per
    session, to avoid hammering geo/risk lookups on every single request."""
    if session_record is None:
        return True
    last = getattr(session_record, "last_zt_check", None)
    if last is None:
        return True
    now = datetime.now(timezone.utc)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) >= timedelta(seconds=REEVALUATION_INTERVAL_SECONDS)
