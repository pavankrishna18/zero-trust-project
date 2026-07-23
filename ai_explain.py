"""
AI Explanation Engine for Zero Trust
Rule-based engine that explains *why* a device or IP is blocked/pending,
using the same deterministic-heuristics approach as MonitoringService's
recommendation engine (see monitoring.py). Not an actual LLM call —
it reads live signals (LoginHistory, ActivityLog, ThreatEvent, RiskAssessment)
and turns them into a human-readable explanation, a risk score, a MITRE
ATT&CK mapping, and a recommended action.
"""

import logging
import json
from datetime import datetime, timezone, timedelta
from models import db, ActivityLog, LoginHistory, ThreatEvent, Device, IPWhitelist, AIThreatAnalysis
import llm_service

logger = logging.getLogger(__name__)

# How long a cached AI analysis is considered "fresh" before we re-run the pipeline.
CACHE_TTL_MINUTES = 15


class AIExplainService:
    """Generates explanations for blocked devices and blocked IPs."""

    # ---------- shared helpers ----------

    @staticmethod
    def _risk_level(score):
        if score >= 90:
            return 'CRITICAL'
        if score >= 70:
            return 'HIGH'
        if score >= 40:
            return 'MEDIUM'
        return 'LOW'

    @staticmethod
    def _dedupe_mitre(mitre):
        seen = {}
        for m in mitre:
            seen[m['id']] = m
        return list(seen.values())

    # ---------- devices ----------

    @staticmethod
    def explain_device(device):
        """
        Build an explanation for why a device is blocked/pending trust.
        Returns dict: risk_score, risk_level, reasons[], mitre[], recommendation, recommendation_label
        """
        try:
            reasons = []
            mitre = []
            score = 0

            if not device.is_trusted:
                reasons.append('Device has not completed identity verification by an administrator')
                score += 15

            if getattr(device, 'is_compromised', False):
                reasons.append('Device was flagged as compromised during a security scan')
                score += 35
                mitre.append({'id': 'T1586', 'name': 'Compromise Accounts'})

            if device.trust_score is not None and device.trust_score < 40:
                reasons.append(f'Trust score is {int(device.trust_score)}%, below the policy threshold of 40%')
                score += 15

            # Device fingerprint churn for this user
            sibling_count = Device.query.filter_by(user_id=device.user_id).count()
            if sibling_count >= 4:
                reasons.append(
                    f'User has {sibling_count} registered devices on file — frequent fingerprint '
                    f'changes are consistent with spoofing or device-farm activity'
                )
                score += 15
                mitre.append({'id': 'T1036', 'name': 'Masquerading'})

            user = device.user
            if user:
                cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
                failed = ActivityLog.query.filter(
                    ActivityLog.user_id == user.id,
                    ActivityLog.action == 'login',
                    ActivityLog.status == 'failed',
                    ActivityLog.timestamp >= cutoff_24h
                ).count()
                if failed >= 3:
                    reasons.append(f'{failed} failed login attempt(s) on this account in the last 24 hours')
                    score += 20
                    mitre.append({'id': 'T1110', 'name': 'Brute Force (Credential Access)'})

                recent_logins = LoginHistory.query.filter_by(user_id=user.id) \
                    .order_by(LoginHistory.timestamp.desc()).limit(10).all()
                countries = sorted({l.country_code for l in recent_logins if l.country_code})
                if len(countries) >= 2:
                    reasons.append(
                        f'Recent logins for this account originate from {len(countries)} different '
                        f'countries ({", ".join(countries)})'
                    )
                    score += 20
                    mitre.append({'id': 'T1078', 'name': 'Valid Accounts (Initial Access)'})

                if recent_logins:
                    last = recent_logins[0]
                    if last.is_blocked_country:
                        reasons.append(
                            f'Most recent login originated from a country on the blocked list '
                            f'({last.country or last.country_code})'
                        )
                        score += 25
                    if last.is_proxy or last.is_hosting:
                        reasons.append('Most recent login used a VPN, proxy, or hosting-provider IP')
                        score += 20
                        mitre.append({'id': 'T1090', 'name': 'Proxy (Command and Control)'})

            ip_entry = IPWhitelist.query.filter_by(ip_address=device.ip_address).first()
            if ip_entry and not ip_entry.is_active:
                detail = f' ({ip_entry.block_reason})' if ip_entry.block_reason else ''
                reasons.append(f'Device IP {device.ip_address} matches a blocked IP entry{detail}')
                score += 25
                mitre.append({'id': 'T1071', 'name': 'Application Layer Protocol (C2)'})

            if not reasons:
                reasons.append('No high-risk signals on file — device is simply awaiting manual approval')
                score = max(score, 10)

            score = min(score, 99)
            level = AIExplainService._risk_level(score)

            return {
                'risk_score': score,
                'risk_level': level,
                'reasons': reasons,
                'mitre': AIExplainService._dedupe_mitre(mitre),
                'recommendation': 'keep_blocked' if score >= 50 else 'reverify',
                'recommendation_label': 'Keep blocked' if score >= 50 else 'Reverify device',
            }
        except Exception as e:
            logger.error('Error explaining device %s: %s', getattr(device, 'id', '?'), str(e))
            return {
                'risk_score': 0, 'risk_level': 'LOW', 'mitre': [],
                'reasons': ['AI analysis unavailable right now — showing raw device status instead.'],
                'recommendation': 'reverify', 'recommendation_label': 'Reverify device',
            }

    # ---------- IPs ----------

    # ---------- Phase 6: real LLM pipeline ----------
    # Log -> Risk Engine (explain_device/explain_ip above) -> LLM -> Natural
    # Language Analysis -> Decision -> Store Explanation -> Display to User

    @staticmethod
    def _level_to_score(level):
        return {'LOW': 20, 'MEDIUM': 55, 'HIGH': 80, 'CRITICAL': 95}.get(level, 50)

    @staticmethod
    def _get_cached(target_type, target_id):
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=CACHE_TTL_MINUTES)
        row = AIThreatAnalysis.query.filter_by(target_type=target_type, target_id=target_id) \
            .filter(AIThreatAnalysis.created_at >= cutoff) \
            .order_by(AIThreatAnalysis.created_at.desc()).first()
        return row.to_dict() if row else None

    @staticmethod
    def _store(target_type, target_id, result):
        try:
            row = AIThreatAnalysis(
                target_type=target_type,
                target_id=target_id,
                risk_score=result['risk_score'],
                risk_level=result['risk_level'],
                reasons=json.dumps(result['reasons']),
                mitre_attack=json.dumps(result['mitre']),
                recommendation=result['recommendation'],
                recommendation_label=result['recommendation_label'],
                confidence=result.get('confidence', 60),
                source=result.get('source', 'rule_based'),
                is_llm_generated=result.get('is_llm_generated', False),
            )
            db.session.add(row)
            db.session.commit()
        except Exception as e:
            logger.error('Failed to store AI threat analysis: %s', str(e))
            db.session.rollback()

    @staticmethod
    def _device_facts(device, rule_result):
        user = device.user
        last_login = None
        if user:
            last_login = LoginHistory.query.filter_by(user_id=user.id) \
                .order_by(LoginHistory.timestamp.desc()).first()

        return {
            'device_fingerprint': (device.device_fingerprint or '')[:24] + '…',
            'ip_address': device.ip_address,
            'geo_location': f"{last_login.city}, {last_login.country}" if last_login and last_login.city else 'Unknown',
            'failed_login_count_24h': sum(1 for r in rule_result['reasons'] if 'failed login' in r.lower()) or 0,
            'threat_intelligence': '; '.join(rule_result['reasons']) or 'None on file',
            'trust_score_percent': device.trust_score,
            'is_currently_trusted': device.is_trusted,
            'is_flagged_compromised': bool(getattr(device, 'is_compromised', False)),
            'rule_engine_risk_score': rule_result['risk_score'],
            'rule_engine_risk_level': rule_result['risk_level'],
        }

    @staticmethod
    def _ip_facts(ip_entry, rule_result):
        geo = LoginHistory.query.filter_by(ip_address=ip_entry.ip_address) \
            .order_by(LoginHistory.timestamp.desc()).first()
        threats = ThreatEvent.query.filter_by(source_ip=ip_entry.ip_address).count()

        return {
            'ip_address': ip_entry.ip_address,
            'currently_active': ip_entry.is_active,
            'auto_blocked': ip_entry.is_auto_blocked,
            'block_reason_on_file': ip_entry.block_reason or 'None recorded',
            'geo_location': f"{geo.city}, {geo.country}" if geo and geo.city else 'Unknown',
            'is_proxy_or_vpn': bool(geo.is_proxy or geo.is_hosting) if geo else False,
            'threat_intelligence_event_count': threats,
            'rule_engine_risk_score': rule_result['risk_score'],
            'rule_engine_risk_level': rule_result['risk_level'],
        }

    @staticmethod
    def _merge_with_llm(rule_result, llm_result):
        """Combine the deterministic risk engine output with the LLM's natural-language verdict."""
        if not llm_result:
            return {
                **rule_result,
                'confidence': 70,
                'source': 'rule_based (no LLM provider configured)',
                'is_llm_generated': False,
            }

        combined_reasons = llm_result['reasons'] + [r for r in rule_result['reasons'] if r not in llm_result['reasons']]
        combined_mitre = rule_result['mitre'] + [m for m in llm_result['mitre'] if m['id'] not in {x['id'] for x in rule_result['mitre']}]

        # Trust the rule engine's grounded score, but never let the LLM under-call
        # something the deterministic signals flagged as worse.
        llm_score = AIExplainService._level_to_score(llm_result['risk_level'])
        final_score = max(rule_result['risk_score'], llm_score)
        final_level = AIExplainService._risk_level(final_score)

        return {
            'risk_score': final_score,
            'risk_level': final_level,
            'reasons': combined_reasons[:6],
            'mitre': combined_mitre,
            'recommendation': llm_result['recommendation'],
            'recommendation_label': llm_result['recommendation_label'],
            'confidence': llm_result['confidence'],
            'source': llm_result['source'],
            'is_llm_generated': True,
        }

    @staticmethod
    def analyze_device(device, force_refresh=False):
        """Full Phase 6 pipeline for a device: cache -> risk engine -> LLM -> store."""
        if not force_refresh:
            cached = AIExplainService._get_cached('device', device.id)
            if cached:
                return cached

        rule_result = AIExplainService.explain_device(device)
        try:
            facts = AIExplainService._device_facts(device, rule_result)
            llm_result = llm_service.analyze_with_llm(facts)
        except Exception as e:
            logger.warning('LLM analysis failed for device %s, using rule engine: %s', device.id, str(e))
            llm_result = None

        final = AIExplainService._merge_with_llm(rule_result, llm_result)
        AIExplainService._store('device', device.id, final)
        final['analyzed_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        return final

    @staticmethod
    def analyze_ip(ip_entry, force_refresh=False):
        """Full Phase 6 pipeline for an IP: cache -> risk engine -> LLM -> store."""
        if not force_refresh:
            cached = AIExplainService._get_cached('ip', ip_entry.id)
            if cached:
                return cached

        rule_result = AIExplainService.explain_ip(ip_entry)
        try:
            facts = AIExplainService._ip_facts(ip_entry, rule_result)
            llm_result = llm_service.analyze_with_llm(facts)
        except Exception as e:
            logger.warning('LLM analysis failed for IP %s, using rule engine: %s', ip_entry.ip_address, str(e))
            llm_result = None

        final = AIExplainService._merge_with_llm(rule_result, llm_result)
        AIExplainService._store('ip', ip_entry.id, final)
        final['analyzed_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        return final

    # ---------- IPs ----------

    @staticmethod
    def explain_ip(ip_entry):
        """
        Build an explanation for why an IP entry is blocked.
        Returns dict: risk_score, risk_level, reasons[], mitre[], recommendation, recommendation_label
        """
        try:
            reasons = []
            mitre = []
            score = 0

            if ip_entry.is_auto_blocked:
                reasons.append('IP was automatically blocked by the threat detection engine')
                score += 20

            if ip_entry.block_reason:
                reasons.append(ip_entry.block_reason)
                score += 10

            cutoff_5m = datetime.now(timezone.utc) - timedelta(minutes=5)
            attempts_5m = ActivityLog.query.filter(
                ActivityLog.ip_address == ip_entry.ip_address,
                ActivityLog.action == 'login',
                ActivityLog.timestamp >= cutoff_5m
            ).count()
            if attempts_5m >= 10:
                reasons.append(f'Detected {attempts_5m} login attempts within the last 5 minutes from this IP')
                score += 35
                mitre.append({'id': 'T1110', 'name': 'Brute Force (Credential Access)'})
            elif attempts_5m > 0:
                reasons.append(f'{attempts_5m} login attempt(s) from this IP in the last 5 minutes')
                score += 10

            cutoff_1h = datetime.now(timezone.utc) - timedelta(hours=1)
            failed_1h = ActivityLog.query.filter(
                ActivityLog.ip_address == ip_entry.ip_address,
                ActivityLog.action.in_(['login', 'access_denied']),
                ActivityLog.status == 'failed',
                ActivityLog.timestamp >= cutoff_1h
            ).count()
            if failed_1h >= 10:
                reasons.append(
                    f'{failed_1h} failed login/access attempts in the last hour — matches known '
                    f'brute-force behavior'
                )
                score += 30
                mitre.append({'id': 'T1110', 'name': 'Brute Force (Credential Access)'})

            threats = ThreatEvent.query.filter_by(source_ip=ip_entry.ip_address) \
                .order_by(ThreatEvent.detected_at.desc()).limit(5).all()
            if threats:
                types = sorted({t.threat_type for t in threats if t.threat_type})
                reasons.append(
                    f'Threat intelligence logged {len(threats)} related event(s)'
                    + (f': {", ".join(types)}' if types else '')
                )
                score += 20
                mitre.append({'id': 'T1595', 'name': 'Active Scanning (Reconnaissance)'})

            geo = LoginHistory.query.filter_by(ip_address=ip_entry.ip_address) \
                .order_by(LoginHistory.timestamp.desc()).first()
            if geo:
                if geo.is_proxy or geo.is_hosting:
                    reasons.append('GeoIP lookup flags this address as a VPN, proxy, or hosting/datacenter IP')
                    score += 15
                    mitre.append({'id': 'T1090', 'name': 'Proxy (Command and Control)'})
                if geo.is_blocked_country:
                    reasons.append(f'Address geolocates to a blocked country ({geo.country or geo.country_code})')
                    score += 20

            if not reasons:
                reasons.append('No additional automated signals on file — this entry was blocked manually')
                score = max(score, 10)

            score = min(score, 99)
            level = AIExplainService._risk_level(score)

            return {
                'risk_score': score,
                'risk_level': level,
                'reasons': reasons,
                'mitre': AIExplainService._dedupe_mitre(mitre),
                'recommendation': 'keep_blocked' if score >= 50 else 'unblock',
                'recommendation_label': 'Keep blocked' if score >= 50 else 'Consider unblocking',
            }
        except Exception as e:
            logger.error('Error explaining IP %s: %s', getattr(ip_entry, 'ip_address', '?'), str(e))
            return {
                'risk_score': 0, 'risk_level': 'LOW', 'mitre': [],
                'reasons': ['AI analysis unavailable right now — showing raw IP status instead.'],
                'recommendation': 'keep_blocked', 'recommendation_label': 'Keep blocked',
            }
