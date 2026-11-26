import unittest

import copy

from gateway.policy import decide, load_policy, policy_fp, validate_result

POLICY = load_policy()


def r(checker, risk=0, signals=(), hard=False, conf=None, ev="e"):
    d = {"checker": checker, "risk": risk, "hard_block": hard, "signals": list(signals), "evidence": ev, "latency_ms": 1}
    if conf is not None:
        d["confidence"] = conf
    return d


def clean(**over):
    base = {"injection": r("injection"), "supply_chain": r("supply_chain"), "identity": r("identity")}
    base.update(over)
    return base


class DecideTest(unittest.TestCase):
    def test_clean_is_allow(self):
        d = decide(clean(), POLICY)
        self.assertEqual((d.grade, d.score), ("allow", 100))

    def test_score_restrict(self):  # 100 - 40*0.6 = 76
        d = decide(clean(injection=r("injection", 40, ["llm_flagged"])), POLICY)
        self.assertEqual((d.grade, d.score), ("restrict", 76))

    def test_score_block(self):  # 100 - 90*0.6 = 46
        self.assertEqual(decide(clean(injection=r("injection", 90)), POLICY).grade, "block")

    def test_hard_block(self):
        self.assertEqual(decide(clean(supply_chain=r("supply_chain", 0, ["malicious_package"], hard=True)), POLICY).grade, "block")

    def test_confidence_block(self):
        self.assertEqual(decide(clean(injection=r("injection", 10, ["llm_flagged"], conf=0.85)), POLICY).grade, "block")

    def test_confidence_below_limit(self):
        self.assertEqual(decide(clean(injection=r("injection", 0, conf=0.5)), POLICY).grade, "allow")

    def test_error_is_restrict(self):
        d = decide(clean(supply_chain=RuntimeError("OSV down")), POLICY)
        self.assertEqual(d.grade, "restrict")
        self.assertTrue(any("checker_error" in x for x in d.reasons))

    def test_missing_checker_is_restrict(self):
        res = clean()
        del res["identity"]
        self.assertEqual(decide(res, POLICY).grade, "restrict")

    def test_block_beats_error(self):
        d = decide(clean(injection=r("injection", 90, hard=True), identity=TimeoutError("slow")), POLICY)
        self.assertEqual(d.grade, "block")

    def test_min_restrict_signal(self):  # 점수는 높아도 critical_vuln이면 제한
        d = decide(clean(supply_chain=r("supply_chain", 20, ["critical_vuln"])), POLICY)
        self.assertEqual((d.grade, d.score), ("restrict", 95))

    def test_identity_changed_restrict(self):
        self.assertEqual(decide(clean(identity=r("identity", 10, ["identity_changed"])), POLICY).grade, "restrict")

    def test_no_supply_info_alone_allows(self):  # 100 - 40*0.25 = 90
        d = decide(clean(supply_chain=r("supply_chain", 40, ["no_supply_info"])), POLICY)
        self.assertEqual((d.grade, d.score), ("allow", 90))


class ValidateTest(unittest.TestCase):
    def test_unknown_signal_rejected(self):
        with self.assertRaises(ValueError):
            validate_result("injection", r("injection", 10, ["ssh_key"]))

    def test_bad_risk_rejected(self):
        with self.assertRaises(ValueError):
            validate_result("injection", r("injection", 150))

    def test_bool_is_not_int(self):
        with self.assertRaises(ValueError):
            validate_result("injection", {**r("injection"), "risk": True})

    def test_model_and_prompt_version_must_be_str(self):
        validate_result("injection", {**r("injection"), "model": "gpt-x", "prompt_version": "v1"})
        for k, bad in (("model", 5), ("prompt_version", None), ("model", "")):
            with self.assertRaises(ValueError, msg=k):
                validate_result("injection", {**r("injection"), k: bad})


class PolicyFpTest(unittest.TestCase):
    def test_same_values_same_fp(self):
        reordered = dict(reversed(list(copy.deepcopy(POLICY).items())))
        self.assertEqual(policy_fp(POLICY), policy_fp(reordered))

    def test_value_change_changes_fp(self):
        p = copy.deepcopy(POLICY)
        p["thresholds"]["allow"] = 81
        self.assertNotEqual(policy_fp(POLICY), policy_fp(p))


if __name__ == "__main__":
    unittest.main()
