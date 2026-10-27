"""TF-IDF + logistic-regression classifiers scored in pure Python from JSON.

The models were trained with scikit-learn and exported as data (vocabulary, inverse
document frequencies, weights), so loading them needs no scikit-learn and runs no code.
Scoring follows scikit-learn's TfidfVectorizer exactly for the options used here: word
n-grams with its token pattern, character n-grams within word boundaries (char_wb),
lowercasing, sublinear term frequency, idf weighting and L2 normalisation per
vectoriser, then the logistic function of the weighted sum.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache, cache
from importlib import resources

_WHITE_SPACES = re.compile(r"\s\s+")  # scikit-learn's char_wb normalisation


class _Vectorizer:
    def __init__(self, spec: dict) -> None:
        if spec["analyzer"] not in ("word", "char_wb"):
            raise ValueError(f"unsupported analyzer {spec['analyzer']!r}")
        self.analyzer = spec["analyzer"]
        self.low, self.high = spec["ngramRange"]
        self.lowercase = spec["lowercase"]
        self.token = re.compile(spec["tokenPattern"])
        self.sublinear = spec["sublinearTf"]
        self.norm = spec["norm"]
        self.use_idf = spec["useIdf"]
        self.offset = spec["offset"]
        self.index = {term: i for i, term in enumerate(spec["vocabulary"])}
        self.idf = spec["idf"]

    def terms(self, text: str) -> list[str]:
        if self.lowercase:
            text = text.lower()
        out: list[str] = []
        if self.analyzer == "word":
            tokens = self.token.findall(text)
            for n in range(self.low, self.high + 1):
                if n == 1:
                    out.extend(tokens)
                else:
                    out.extend(" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
            return out
        for word in _WHITE_SPACES.sub(" ", text).split():
            w = f" {word} "
            for n in range(self.low, self.high + 1):
                offset = 0
                out.append(w[offset:offset + n])
                while offset + n < len(w):
                    offset += 1
                    out.append(w[offset:offset + n])
                if offset == 0:  # the word is shorter than n: one n-gram for all larger n
                    break
        return out

    def features(self, text: str) -> dict[int, float]:
        counts: dict[int, int] = {}
        for term in self.terms(text):
            j = self.index.get(term)
            if j is not None:
                counts[j] = counts.get(j, 0) + 1
        values = {j: (1.0 + math.log(c) if self.sublinear else float(c))
                  * (self.idf[j] if self.use_idf else 1.0) for j, c in counts.items()}
        if self.norm == "l2":
            length = math.sqrt(sum(v * v for v in values.values()))
            if length > 0:
                values = {j: v / length for j, v in values.items()}
        elif self.norm is not None:
            raise ValueError(f"unsupported norm {self.norm!r}")
        return values


class TextClassifier:
    """A binary TF-IDF + logistic-regression classifier loaded from its JSON export."""

    def __init__(self, spec: dict) -> None:
        self.kind = spec.get("kind", "")
        self.vectorizers = [_Vectorizer(v) for v in spec["vectorizers"]]
        self.coef = spec["coef"]
        self.intercept = spec["intercept"]
        self.threshold = spec["threshold"]

    @classmethod
    def from_json(cls, text: str) -> TextClassifier:
        return cls(json.loads(text))

    def safety_score(self, text: str) -> float:
        """Probability of the positive class (harmful / suspicious)."""
        z = self.intercept
        for vec in self.vectorizers:
            for j, value in vec.features(text).items():
                z += self.coef[vec.offset + j] * value
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def flag(self, text: str) -> bool:
        return self.safety_score(text) >= self.threshold


def data_text(name: str) -> str:
    return resources.files("governance_gateway").joinpath("data", name).read_text("utf-8")


@cache
def load_classifier() -> TextClassifier:
    """The safety classifier: flags toxic messages and jailbreak attempts."""
    return TextClassifier.from_json(data_text("guardrail.json"))


@cache
def load_screen() -> TextClassifier:
    """The suspicion screen: a cheap classifier that decides who needs the full check."""
    return TextClassifier.from_json(data_text("screen.json"))
