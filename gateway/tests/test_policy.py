import unittest

import copy

import tempfile
from pathlib import Path

from gateway.policy import checker_fp, decide, judge_fp, load_policy, policy_fp, validate_result

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


class CheckerFpTest(unittest.TestCase):
    """검사기 지문 (결정 #36): B·C 코드나 모델 설정이 바뀌면 판정을 재사용하지 않는다."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "checkers" / "tests").mkdir(parents=True)
        (self.root / "checkers" / "rules.py").write_text("RISK = {'hidden_tag': 40}\n", encoding="utf-8")
        (self.root / "checkers" / "tests" / "test_x.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def fp(self, env=None):
        return checker_fp(self.root, env or {}, "real")

    def test_checker_code_change(self):
        before = self.fp()
        (self.root / "checkers" / "rules.py").write_text("RISK = {'hidden_tag': 50}\n", encoding="utf-8")
        self.assertNotEqual(before, self.fp())

    def test_tests_ignored(self):
        before = self.fp()
        (self.root / "checkers" / "tests" / "test_x.py").write_text("x = 2\n", encoding="utf-8")
        self.assertEqual(before, self.fp())

    def test_model_setting_counts_but_paths_do_not(self):
        base = self.fp()
        self.assertNotEqual(base, self.fp({"LINKUD_B_MODEL": "other"}))
        self.assertEqual(base, self.fp({"LINKUD_DB": "/x.db", "LINKUD_AUDIT": "/a", "LINKUD_LOG": "DEBUG"}))
        self.assertEqual(base, self.fp({"OPENAI_API_KEY": "sk-x", "PATH": "/bin"}))

    def test_budget_settings_do_not_count(self):
        """B의 예산·단가·저장 위치·대기 시간은 판정과 무관 → 바꿔도 승인이 풀리지 않는다."""
        base = self.fp()
        self.assertEqual(base, self.fp({"LINKUD_B_BUDGET_USD": "10", "LINKUD_B_INPUT_PRICE": "1",
                                        "LINKUD_B_OUTPUT_PRICE": "5", "LINKUD_B_CACHE": "/c.db",
                                        "LINKUD_B_TIMEOUT": "20"}))
        for k in ("LINKUD_B_MODEL", "LINKUD_B_EFFORT", "LINKUD_B_MAX_OUTPUT_TOKENS"):  # 판정에 영향 → 남김
            self.assertNotEqual(base, self.fp({k: "x"}), k)

    def test_dotenv_linkud_only(self):
        base = self.fp()
        (self.root / ".env").write_text("OPENAI_API_KEY=sk-secret\n", encoding="utf-8")
        self.assertEqual(base, self.fp())  # 키는 지문에 안 들어감
        (self.root / ".env").write_text("OPENAI_API_KEY=sk-secret\nLINKUD_B_MODEL=m2\n", encoding="utf-8")
        self.assertNotEqual(base, self.fp())

    def test_judge_fp_combines(self):
        self.assertNotEqual(judge_fp(POLICY, self.root, {}, "real"), judge_fp(POLICY, self.root, {"LINKUD_B_MODEL": "x"}, "real"))


if __name__ == "__main__":
    unittest.main()
