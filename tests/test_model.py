"""The pure-Python models and the mandatory checks of the governance-gateway package."""

from __future__ import annotations

import json

import pytest
from governance_gateway import checks
from governance_gateway.model import TextClassifier, data_text, load_classifier, load_screen


def test_models_match_scikit_learn_on_the_parity_sentences():
    parity = json.loads(data_text("parity.json"))
    assert len(parity["texts"]) > 40
    for model, expected in ((load_classifier(), parity["guardrail"]),
                            (load_screen(), parity["screen"])):
        for text, p in zip(parity["texts"], expected):
            assert model.safety_score(text) == pytest.approx(p, abs=1e-9)


def test_screen_is_much_cheaper_than_the_classifier():
    screen, clf = load_screen(), load_classifier()
    assert sum(v.offset + len(v.index) for v in screen.vectorizers) < \
        sum(len(v.index) for v in clf.vectorizers)
    assert 0 < screen.threshold < clf.threshold < 1


def _tiny(**over) -> dict:
    spec = {"vectorizers": [{"analyzer": "word", "ngramRange": [1, 2], "lowercase": True,
                             "tokenPattern": r"(?u)\b\w\w+\b", "sublinearTf": True,
                             "norm": "l2", "useIdf": True, "offset": 0,
                             "vocabulary": ["bad", "very bad", "good"], "idf": [2.0, 3.0, 1.0]}],
            "coef": [4.0, 2.0, -3.0], "intercept": -1.0, "threshold": 0.5}
    spec.update(over)
    return spec


def test_scoring_follows_tfidf_and_the_logistic_function():
    import math

    m = TextClassifier(_tiny())
    # "very bad": terms bad (idf 2), very bad (idf 3); "very" is out of vocabulary.
    a, b = 2.0, 3.0
    norm = math.sqrt(a * a + b * b)
    z = -1.0 + 4.0 * a / norm + 2.0 * b / norm
    assert m.safety_score("Very BAD") == pytest.approx(1 / (1 + math.exp(-z)))
    assert m.safety_score("nothing known here") == pytest.approx(1 / (1 + math.exp(1.0)))
    assert m.flag("very bad") and not m.flag("good good")


def test_char_wb_ngrams_follow_scikit_learn():
    from governance_gateway.model import _Vectorizer

    v = _Vectorizer({"analyzer": "char_wb", "ngramRange": [3, 5], "lowercase": True,
                     "tokenPattern": "", "sublinearTf": True, "norm": "l2", "useIdf": True,
                     "offset": 0, "vocabulary": [], "idf": []})
    assert v.terms("Hi  x") == [" hi", "hi ", " hi ", " x "]


def test_unsupported_options_are_refused():
    spec = _tiny()
    spec["vectorizers"][0]["analyzer"] = "char"
    with pytest.raises(ValueError):
        TextClassifier(spec)


def test_pii_scan_redacts_and_reports_kinds():
    clean, found, redacted = checks.pii_scan("mail jane.doe@example.com or call +44 20 7946 0958")
    assert not clean and found == ["e-mail address", "telephone number"]
    assert redacted == "mail [E-MAIL ADDRESS] or call [TELEPHONE NUMBER]"
    assert checks.pii_scan("SSN 123-45-6789")[1] == ["national ID"]
    assert checks.pii_scan("nothing personal") == (True, [], "nothing personal")


def test_format_check():
    assert checks.format_check("hello")
    assert not checks.format_check("   ")
    assert not checks.format_check(None)
    assert not checks.format_check("x" * (checks.MAX_MESSAGE_CHARS + 1))


def test_version_is_the_same_everywhere():
    tomllib = pytest.importorskip("tomllib")  # Python 3.11+
    from pathlib import Path

    import governance_gateway

    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    server = json.loads((root / "server.json").read_text())
    assert governance_gateway.__version__ == project == server["version"]
    assert all(p["version"] == project for p in server["packages"])
