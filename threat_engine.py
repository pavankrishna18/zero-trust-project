"""
threat_engine.py
=================
Phase 8 — Threat Prevention Engine.

Wires the previously disconnected pieces (ThreatIntelligence, RiskScoringEngine,
AIExplainService, MonitoringService) into a single explicit pipeline:

    Detect -> AI Analysis -> Risk Score -> Policy Engine -> Decision
        -> Auto Block -> Alert -> SOC Dashboard -> Admin Review

Previously app.py only did Detect -> Log (a ThreatEvent row was written and
nothing else happened automatically). This module is the single place that
decides what happens to a detected threat, so that logic isn't duplicated
across routes.

Usage from app.py:

    from threat_engine import ThreatPreventionEngine

    result = ThreatPreventionEngine.process(
        threat_type='brute_force',
        severity='high',
        description='Brute-force attack detected',
        source_ip=client_ip,
        user=current_user,
    )
"""

import logging
from datetime import datetime, timezone, timedelta

from models import db, ThreatEvent, ActivityLog

logger = logging.getLogger(__name__)

# Policy thresholds (0-100 composite risk -> action)
POLICY_AUTO_BLOCK_THRESHOLD = 75
POLICY_ALERT_ONLY_THRESHOLD = 40


class ThreatPreventionEngine:
    """Detect -> AI Analysis -> Risk Score -> Policy -> Decision pipeline."""

    @staticmethod
    def process(threat_type, severity, description, source_ip, user=None,
                socketio=None, auto_block_fn=None):
        """
        Run one detected event through the full pipeline and return a dict
        describing what was decided. `auto_block_fn` is injected (rather than
        imported directly) so this module doesn't have to import app.py's
        IP-blocking call and create a circular import; pass
        ThreatIntelligence.auto_block_malicious_ip from the caller.
        """
        from threat_intelligence import ThreatIntelligence
        from risk_scoring import RiskScoringEngine
        from ai_explain import AIExplainService

        pipeline_trace = ["detect"]

        # ---- 1. AI Analysis ---------------------------------------------
        ai_result = None
        try:
            ip_entry = ThreatIntelligence.check_ip_reputation(source_ip)
            ai_result = AIExplainService.explain_ip(ip_entry) if ip_entry else None
            pipeline_trace.append("ai_analysis")
        except Exception as e:
            logger.warning("AI analysis stage failed, continuing with rule-based score: %s", e)

        # ---- 2. Risk Score -------------------------------------------------
        risk_score = 50  # neutral default if we can't compute a real one
        if user is not None:
            try:
                risk_data = RiskScoringEngine.calculate_risk_score(
                    user, source_ip, user_agent="unknown"
                )
                risk_score = risk_data.get("score", risk_score) if isinstance(risk_data, dict) else risk_score
            except Exception as e:
                logger.warning("Risk scoring stage failed: %s", e)
        if ai_result and isinstance(ai_result, dict) and "risk_score" in ai_result:
            # blend rule-based risk with AI-derived risk, AI weighted higher
            risk_score = round(0.4 * risk_score + 0.6 * ai_result["risk_score"], 1)
        pipeline_trace.append("risk_score")

        # ---- 3. Policy Engine -> Decision -----------------------------------
        if risk_score >= POLICY_AUTO_BLOCK_THRESHOLD or severity == "critical":
            decision = "auto_block"
        elif risk_score >= POLICY_ALERT_ONLY_THRESHOLD or severity in ("high", "medium"):
            decision = "alert"
        else:
            decision = "monitor"
        pipeline_trace.append("policy_engine")
        pipeline_trace.append("decision:" + decision)

        # ---- 4. Persist the threat event (always) ---------------------------
        threat = ThreatEvent(
            threat_type=threat_type,
            severity=severity,
            description=description,
            source_ip=source_ip,
            target_user_id=getattr(user, "id", None),
            target_username=getattr(user, "username", None),
            was_blocked=(decision == "auto_block"),
            auto_blocked=(decision == "auto_block"),
            admin_notified=(decision in ("auto_block", "alert")),
            response_action=decision,
        )
        db.session.add(threat)
        try:
            db.session.commit()
        except Exception as e:
            logger.error("Failed to persist threat event: %s", e)
            db.session.rollback()

        # ---- 5. Auto Block --------------------------------------------------
        if decision == "auto_block" and auto_block_fn is not None:
            try:
                auto_block_fn(source_ip, f"Auto-blocked by policy engine: {description}")
                pipeline_trace.append("auto_block")
            except Exception as e:
                logger.error("Auto-block stage failed: %s", e)

        # ---- 6. Alert (SOC + admins) ------------------------------------
        if decision in ("auto_block", "alert"):
            try:
                if user is not None:
                    ActivityLog.log_activity(
                        user.id, user.username, f"threat_{decision}",
                        "security_alert",
                        f"[{severity.upper()}] {threat_type}: {description} (risk={risk_score})",
                    )
                if socketio is not None:
                    socketio.emit("soc_alert", {
                        "threat_type": threat_type,
                        "severity": severity,
                        "description": description,
                        "source_ip": source_ip,
                        "risk_score": risk_score,
                        "decision": decision,
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }, room="admin_dashboard")
                pipeline_trace.append("alert")
            except Exception as e:
                logger.error("Alert stage failed: %s", e)

        # ---- 7/8. SOC Dashboard + Admin Review ------------------------------
        # No extra work needed here: the ThreatEvent row just written already
        # carries is_investigated / investigated_by / investigation_notes for
        # admin review, and get_soc_dashboard_data() (below) surfaces it.
        pipeline_trace.append("soc_dashboard")
        pipeline_trace.append("admin_review_pending")

        return {
            "decision": decision,
            "risk_score": risk_score,
            "ai_result": ai_result,
            "threat_event_id": threat.id,
            "pipeline": pipeline_trace,
        }

    @staticmethod
    def get_soc_dashboard_data(hours=24, limit=50):
        """Aggregate feed for the SOC dashboard: recent threats, breakdown by
        decision/severity, and the queue of items still awaiting admin review."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        recent = (
            ThreatEvent.query.filter(ThreatEvent.detected_at >= cutoff)
            .order_by(ThreatEvent.detected_at.desc())
            .limit(limit)
            .all()
        )

        severity_counts = {}
        decision_counts = {}
        for t in recent:
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
            action = t.response_action or "monitor"
            decision_counts[action] = decision_counts.get(action, 0) + 1

        pending_review = [t for t in recent if not t.is_investigated]

        return {
            "events": recent,
            "total": len(recent),
            "severity_counts": severity_counts,
            "decision_counts": decision_counts,
            "pending_review_count": len(pending_review),
            "pending_review": pending_review,
        }
