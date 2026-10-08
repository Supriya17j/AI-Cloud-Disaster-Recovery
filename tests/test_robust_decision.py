import unittest

from modules.robust_decision import decide, trust_state


def trust(execution=90, selection=90):
    names = ("Monitoring Agent", "Threat Detection Agent", "Recovery Assessment Agent",
             "Recovery Point Selection Agent", "Recovery Execution Agent", "Recovery Verification Agent")
    values = {name: 90.0 for name in names}
    values["Recovery Execution Agent"] = float(execution)
    values["Recovery Point Selection Agent"] = float(selection)
    return {name: {"score": score, "state": trust_state(score), "authority": "ALLOWED" if score >= 60 else "REVOKED"} for name, score in values.items()}


def live(risk=10, security="NORMAL"):
    return {"risk_score": risk, "security_state": security, "cloudwatch_alarm": "NOT_CONFIGURED", "system_status": "HEALTHY", "telemetry": {"source": "local-psutil"}}


def gate(decision="SAFE TO RECOVER", recommended="RP-1"):
    return {"decision": decision, "recommended": recommended, "assessments": [{"backup_id": recommended, "integrity": True, "decision": "SELECTED"}]}


def ready(score=90):
    return {"score": score, "status": "READY" if score >= 80 else "NOT_READY", "blocking_factors": [] if score >= 80 else ["dependencies"]}


class RobustDecisionTests(unittest.TestCase):
    def test_low_risk_trusted_agent_is_safe(self):
        result = decide(live(), gate(), trust(), ready(), [{"recovery_point": "RP-1", "decision": "SELECTED"}])
        self.assertEqual(result["decision"], "SAFE_TO_RECOVER")

    def test_high_risk_trusted_agent_uses_trusted_path(self):
        result = decide(live(90, "HIGH"), gate(), trust(), ready(), [{"recovery_point": "RP-1", "decision": "SELECTED"}])
        self.assertEqual(result["decision"], "RECOVER_WITH_TRUSTED_AGENT")

    def test_high_risk_low_trust_requires_human(self):
        result = decide(live(90, "HIGH"), gate(), trust(execution=50), ready(), [{"recovery_point": "RP-1", "decision": "SELECTED"}])
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")

    def test_compromised_execution_agent_isolated_with_fallback(self):
        result = decide(live(90, "HIGH"), gate(), trust(execution=20), ready(), [{"recovery_point": "RP-1", "decision": "SELECTED"}])
        self.assertEqual(result["decision"], "RECOVER_WITH_TRUSTED_AGENT")
        self.assertEqual(result["authority"], "TRUSTED_AGENT_ONLY")

    def test_compromised_execution_agent_without_fallback_contains(self):
        agent_trust = trust(execution=20)
        for name in agent_trust:
            agent_trust[name]["score"] = 20
            agent_trust[name]["state"] = "COMPROMISED"
            agent_trust[name]["authority"] = "REVOKED"
        result = decide(live(90, "CRITICAL"), gate(), agent_trust, ready(), [{"recovery_point": "RP-1", "decision": "SELECTED"}])
        self.assertEqual(result["decision"], "EMERGENCY_CONTAINMENT")

    def test_unsafe_backup_is_rejected(self):
        result = decide(live(), {"decision": "NO SAFE RECOVERY POINT AVAILABLE", "recommended": None, "assessments": []}, trust(), ready(), [{"recovery_point": "RP-1", "decision": "REJECTED"}])
        self.assertEqual(result["decision"], "NO_SAFE_RECOVERY_POINT")

    def test_system_not_ready_blocks_recovery(self):
        result = decide(live(), gate(), trust(), ready(40), [{"recovery_point": "RP-1", "decision": "SELECTED"}])
        self.assertEqual(result["decision"], "SYSTEM_NOT_RECOVERY_READY")


if __name__ == "__main__":
    unittest.main()