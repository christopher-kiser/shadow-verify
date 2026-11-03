from shadow_verify.models import PropertyResult, Verdict
from shadow_verify.verdict import decide


def _prop(name: str, verdict: Verdict) -> PropertyResult:
    return PropertyResult(name=name, verdict=verdict, reason=f"{name}:{verdict.value}")


def test_empty_observation_is_not_assessed():
    verdict, reasons = decide([])
    assert verdict == Verdict.NOT_ASSESSED
    assert reasons == ("checker produced no property results",)


def test_all_pass_is_pass():
    verdict, _reasons = decide([_prop("a", Verdict.PASS), _prop("b", Verdict.PASS)])
    assert verdict == Verdict.PASS


def test_any_fail_wins_over_not_assessed():
    verdict, reasons = decide(
        [
            _prop("a", Verdict.PASS),
            _prop("b", Verdict.NOT_ASSESSED),
            _prop("c", Verdict.FAIL),
        ]
    )
    assert verdict == Verdict.FAIL
    assert "c:FAIL" in reasons
    assert "b:NOT_ASSESSED" in reasons


def test_not_assessed_when_nothing_contradicts():
    verdict, _reasons = decide([_prop("a", Verdict.PASS), _prop("b", Verdict.NOT_ASSESSED)])
    assert verdict == Verdict.NOT_ASSESSED
