"""A governance gateway: deadline-aware checks that an AI agent calls before it acts.

Requests join one first-in, first-out queue served on the real clock, and each request
carries its own deadline. The mandatory checks (format, personal-data scan) always run.
The safety classifier, the slow and optional check, runs only if a cheap suspicion
screen finds the text suspicious (when a screen is used) AND the classifier's estimated
cost still fits before the deadline.

Verdicts:
    block    the format check failed, or the classifier judged the text harmful
    redact   personal data was found; ``redacted`` is the text with it masked
    allow    nothing found (the reasons say if the classifier was skipped or screened out)

The gateway never returns the text it was given, only the redacted copy when it found
personal data. Its optional audit log (one JSON line per decision) records verdicts,
the kinds of personal data found and timing, never the text.

The classifier's cost is estimated from its recent measured costs, by default their
90th percentile: costs have a heavy tail, and deciding with the mean lets some checked
requests finish late.

``decision_matrix`` and ``simulate_load`` answer planning questions from the study's
results and from the measured guardrail workload bundled with the package; neither
contains any message text.
"""

from __future__ import annotations

import json
import math
import queue
import random
import threading
import time
from collections import deque
from concurrent.futures import Future
from dataclasses import asdict, dataclass, field
from pathlib import Path
from statistics import fmean
from typing import Any

from governance_gateway.checks import format_check, pii_scan
from governance_gateway.model import data_text, load_classifier

DEFAULT_DEADLINE_MS = 100.0
SKIP_COST_MS = 0.01  # the study's cost of deciding to skip a check
TRAFFIC_CV = {"even": 0, "steady": 1, "random": 1, "poisson": 1, "bursty": 2}
ESTIMATORS = ("mean", "p90")


def percentile(values, q: float) -> float:
    """The q-th percentile with linear interpolation (NumPy's default method)."""
    xs = sorted(float(v) for v in values)
    if not xs:
        raise ValueError("no values")
    pos = (len(xs) - 1) * q / 100.0
    lo = math.floor(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def cost_estimate(samples, estimator: str = "p90") -> float:
    """Expected cost of the next classifier check from recent measured costs (ms)."""
    if estimator == "mean":
        return fmean(samples)
    if estimator == "p90":
        return percentile(samples, 90)
    raise ValueError(f"estimator must be one of {ESTIMATORS}")


@dataclass
class Decision:
    verdict: str
    reasons: list[str]
    format_ok: bool
    pii_found: list[str]
    redacted: str | None
    classifier: str  # "ran", "skipped" (no time left) or "screened out" (not suspicious)
    harmful: bool | None
    probability: float | None
    deadline_ms: float
    waited_ms: float
    checks_ms: float
    lag_ms: float
    on_time: bool
    mandatory_on_time: bool
    screen: str | None = None  # "suspicious" or "clear" when a screen is used

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _Request:
    text: str
    deadline_ms: float
    arrived: float
    source: str = "api"
    future: Future = field(default_factory=Future)


class Gateway:
    """FIFO workers on the real clock, running the deadline-aware guardrail.

    ``guard`` and ``screen`` are any objects with ``safety_score(text) -> float`` and a
    ``threshold``; by default the bundled classifier, and no screen.
    """

    def __init__(self, guard: Any = None, initial_estimate_ms: float = 1.0,
                 window: int = 200, history: int = 1000, workers: int = 1,
                 estimator: str = "p90", audit_path: str | Path | None = None,
                 screen: Any = None) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        cost_estimate([1.0], estimator)  # validates the name
        self.guard = guard if guard is not None else load_classifier()
        self.guard.safety_score("warm up")  # the first call is slow; keep it out of the estimate
        self.screen = screen
        if screen is not None:
            screen.safety_score("warm up")
        self.workers, self.estimator = workers, estimator
        self._est = initial_estimate_ms
        self._recent: deque[float] = deque(maxlen=window)
        self._lags: deque[float] = deque(maxlen=history)
        self._decisions: deque[dict[str, Any]] = deque(maxlen=200)
        self._queue: queue.Queue[_Request | None] = queue.Queue()
        self._lock = threading.Lock()
        self._audit = Path(audit_path).expanduser() if audit_path else None
        if self._audit:
            self._audit.parent.mkdir(parents=True, exist_ok=True)
        self._counts = {"requests": 0, "on_time": 0, "mandatory_on_time": 0,
                        "classifier_skipped": 0, "screened_out": 0, "allow": 0, "redact": 0,
                        "block": 0}
        self._started = time.time()
        self._workers = [threading.Thread(target=self._serve, name=f"gsl-gateway-{i}",
                                          daemon=True) for i in range(workers)]
        for w in self._workers:
            w.start()

    # --- requests ---------------------------------------------------------------------

    def check(self, text: str, deadline_ms: float = DEFAULT_DEADLINE_MS,
              timeout: float | None = 30.0, source: str = "api") -> Decision:
        """Queue ``text`` for checking within ``deadline_ms`` and wait for the decision."""
        if not deadline_ms > 0:
            raise ValueError("deadline_ms must be positive")
        req = _Request(text if isinstance(text, str) else "", float(deadline_ms),
                       time.monotonic(), source)
        self._queue.put(req)
        return req.future.result(timeout=timeout)

    def close(self) -> None:
        for _ in self._workers:
            self._queue.put(None)
        for w in self._workers:
            w.join(timeout=5)

    def _serve(self) -> None:
        while True:
            req = self._queue.get()
            if req is None:
                return
            try:
                req.future.set_result(self._process(req))
            except Exception as exc:  # noqa: BLE001 - surfaced to the caller
                req.future.set_exception(exc)

    def _process(self, req: _Request) -> Decision:
        start = time.monotonic()
        deadline_at = req.arrived + req.deadline_ms / 1e3
        ok = format_check(req.text)
        clean, found, redacted = pii_scan(req.text)
        mandatory_done = time.monotonic()
        reasons: list[str] = []
        harmful = probability = None
        screen = None
        if ok and self.screen is not None:
            score = self.screen.safety_score(req.text)
            screen = "suspicious" if score >= self.screen.threshold else "clear"
        left_ms = (deadline_at - time.monotonic()) * 1e3
        if screen == "clear":
            classifier = "screened out"
            reasons.append(f"safety classifier not needed: the screen found nothing suspicious "
                           f"(score {score:.2f} < {self.screen.threshold:.2f})")
        elif ok and self._est <= left_ms:
            t0 = time.monotonic()
            probability = self.guard.safety_score(req.text)
            cost_ms = (time.monotonic() - t0) * 1e3
            harmful = probability >= self.guard.threshold
            with self._lock:
                self._recent.append(cost_ms)
                self._est = cost_estimate(self._recent, self.estimator)
            classifier = "ran"
        else:
            classifier = "skipped"
            if ok:
                reasons.append(f"safety classifier skipped: {max(left_ms, 0):.2f} ms left before "
                               f"the deadline, it needs about {self._est:.2f} ms")
        finish = time.monotonic()
        if not ok:
            verdict = "block"
            reasons.insert(0, "format check failed: empty, not text, or longer than 4,000 "
                              "characters")
        elif harmful:
            verdict = "block"
            reasons.insert(0, f"safety classifier: likely harmful or a jailbreak attempt "
                              f"(score {probability:.2f} ≥ {self.guard.threshold:.2f})")
        elif not clean:
            verdict = "redact"
            reasons.insert(0, "personal data found: " + ", ".join(found))
        else:
            verdict = "allow"
        lag_ms = (finish - req.arrived) * 1e3
        decision = Decision(
            verdict=verdict, reasons=reasons, format_ok=ok, pii_found=found,
            redacted=redacted if found else None, classifier=classifier, harmful=harmful,
            probability=None if probability is None else round(probability, 4),
            deadline_ms=req.deadline_ms, waited_ms=round((start - req.arrived) * 1e3, 3),
            checks_ms=round((finish - start) * 1e3, 3), lag_ms=round(lag_ms, 3),
            on_time=lag_ms <= req.deadline_ms,
            mandatory_on_time=(mandatory_done - req.arrived) * 1e3 <= req.deadline_ms,
            screen=screen)
        with self._lock:
            c = self._counts
            c["requests"] += 1
            c["on_time"] += decision.on_time
            c["mandatory_on_time"] += decision.mandatory_on_time
            c["classifier_skipped"] += classifier == "skipped"
            c["screened_out"] += classifier == "screened out"
            c[verdict] += 1
            self._lags.append(lag_ms)
            record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "source": req.source,
                      "verdict": verdict, "pii_found": found, "screen": screen,
                      "classifier": classifier,
                      "harmful": harmful, "deadline_ms": req.deadline_ms,
                      "lag_ms": decision.lag_ms, "on_time": decision.on_time,
                      "mandatory_on_time": decision.mandatory_on_time}
            self._decisions.append(record)
            if self._audit:
                with self._audit.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
        return decision

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """The latest decisions, newest last: verdicts and timing, never the text."""
        with self._lock:
            return list(self._decisions)[-max(0, int(limit)):]

    # --- monitoring -------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """What the gateway has done so far: counts, lag and how often it skipped."""
        with self._lock:
            c = dict(self._counts)
            lags = list(self._lags) or [0.0]
            est = self._est
        n = c["requests"]
        return {
            "requests": n,
            "queue_length": self._queue.qsize(),
            "verdicts": {k: c[k] for k in ("allow", "redact", "block")},
            "on_time_share": c["on_time"] / n if n else None,
            "mandatory_on_time_share": c["mandatory_on_time"] / n if n else None,
            "classifier_skipped_share": c["classifier_skipped"] / n if n else None,
            "screened_out_share": c["screened_out"] / n if n else None,
            "cascade": self.screen is not None,
            "lag_ms": {"mean": round(fmean(lags), 3),
                       "p95": round(percentile(lags, 95), 3),
                       "last": round(lags[-1], 3)} if n else None,
            "classifier_cost_estimate_ms": round(est, 3),
            "estimator": self.estimator,
            "workers": self.workers,
            "uptime_s": round(time.time() - self._started, 1),
        }


# --- planning tools ------------------------------------------------------------------------

def decision_matrix(deadline_ms: float = 100.0, traffic: str = "random",
                    peak_factor: float = 1.0, recall: float = 0.86, target: float = 0.70,
                    cost_share: float = 0.88, load: float = 0.8) -> dict[str, Any]:
    """Which checking policy a pipeline needs at a given mean load (the decision matrix).

    Breaking loads come from the simulation study (log-scale detector, 80% target, 100
    replications) for the nearest studied deadline, divided by the peak-hour factor q;
    the capacity multiplier M = 1/(1 - h*s) comes from the caller's detector.
    """
    cv = TRAFFIC_CV.get(traffic.lower())
    if cv is None:
        raise ValueError(f"traffic must be one of {sorted(TRAFFIC_CV)}")
    if not (0 < target <= 1 and 0 < recall <= 1 and 0 <= cost_share < 1):
        raise ValueError("recall and target must be in (0, 1]; cost_share in [0, 1)")
    if peak_factor < 1 or load <= 0 or deadline_ms <= 0:
        raise ValueError("peak_factor must be at least 1; load and deadline_ms positive")
    grid = [g for g in json.loads(data_text("study.json"))["decisionGrid"] if g["cv"] == cv]
    row = min(grid, key=lambda g: abs(math.log(g["deadlineMs"] / deadline_ms)))
    h = max(0.0, 1.0 - target / recall)
    m = 1.0 / (1.0 - h * cost_share)
    full = (row["full"] or 0.0) / peak_factor
    sampling = full * m
    aware = (row["aware"] or 0.0) / peak_factor
    if recall <= target:
        regime, advice = "better detector", ("The detector's recall is below the target: no "
                                             "checking policy can meet it.")
    elif load <= full:
        regime, advice = "full checking", "Checking every event meets the target."
    elif load <= max(sampling, aware):
        regime, advice = "adaptive checking", ("Full checking would miss deadlines; use "
                                               "deadline-aware checking.")
    else:
        need = load / max(sampling, aware, 1e-9)
        regime, advice = "more capacity", (f"Add capacity (at least x{need:.2f}) or a faster "
                                           "detector.")
    return {"regime": regime, "advice": advice, "h": round(h, 4), "M": round(m, 4),
            "full_checking_holds_to": round(full, 3), "fixed_sampling_holds_to": round(sampling, 3),
            "deadline_aware_holds_to": round(aware, 3), "load": load,
            "study_row": {"traffic_cv": cv, "deadline_ms": row["deadlineMs"]}}


def _workload() -> dict:
    data = json.loads(data_text("workload.json"))
    c = data["costMs"]
    return {"mandatory": [f + p for f, p in zip(c["format"], c["pii"])],
            "classifier": c["classifier"], "flag": data["flag"], "harmful": data["harmful"],
            "wildchat": data["wildchatSeconds"], "measured": data["measured"]}


def _arrivals(n: int, rate: float, traffic: str, rng: random.Random,
              wildchat: list[float]) -> list[float]:
    """Arrival offsets in seconds of n messages at a mean rate per second."""
    if traffic in ("steady", "random", "poisson"):
        t, out = 0.0, [0.0]
        for _ in range(n - 1):
            t += rng.expovariate(rate)
            out.append(t)
        return out
    if traffic == "rush_hour":  # half the rate in the outer thirds, twice it in the middle
        third, t, out = n / rate / 3, 0.0, [0.0]
        for _ in range(n - 1):
            t += rng.expovariate(rate * (2 if third <= t < 2 * third else 0.5))
            out.append(t)
        return out
    if traffic == "real_chatbot":  # real WildChat conversation times, rescaled to the rate
        start = rng.randrange(0, len(wildchat) - n)
        raw = sorted(wildchat[start + i] + rng.random() for i in range(n))
        scale = (n - 1) / rate / (raw[-1] - raw[0])
        return [(r - raw[0]) * scale for r in raw]
    raise ValueError("traffic must be steady, rush_hour or real_chatbot")


def simulate_load(load: float = 1.3, deadline_ms: float = 100.0, traffic: str = "steady",
                  seconds: float = 15.0, seed: int = 0) -> dict[str, Any]:
    """Race 'check everything' against the deadline-aware guard on a simulated clock.

    Messages are drawn from the measured ToxicChat test set (labels, verdicts and
    per-message costs only); ``load`` is the arrival rate over one checker's capacity.
    """
    if not (0 < load <= 3 and 0 < deadline_ms <= 5000 and 0 < seconds <= 120):
        raise ValueError("load in (0, 3], deadline_ms in (0, 5000], seconds in (0, 120]")
    w = _workload()
    rng = random.Random(seed)
    rate = load * w["measured"]["capacityPerSecond"]
    n = max(2, int(rate * seconds))
    pick = [rng.randrange(len(w["harmful"])) for _ in range(n)]
    arrivals = [a * 1e3 for a in _arrivals(n, rate, traffic, rng, w["wildchat"])]
    out = {}
    for policy in ("full", "deadline_aware"):
        free, est, recent = 0.0, w["measured"]["meanClassifierMs"], deque(maxlen=200)
        caught = harmful = pii_ok = skipped = 0
        lag = 0.0
        for arrive, j in zip(arrivals, pick):
            start = max(arrive, free)
            mandatory_done = start + w["mandatory"][j]
            ran = policy == "full" or mandatory_done + est <= arrive + deadline_ms
            free = mandatory_done + (w["classifier"][j] if ran else SKIP_COST_MS)
            lag = free - arrive
            harmful += w["harmful"][j]
            caught += bool(w["harmful"][j] and ran and w["flag"][j] and lag <= deadline_ms)
            pii_ok += mandatory_done - arrive <= deadline_ms
            if ran:
                recent.append(w["classifier"][j])
                est = sum(recent) / len(recent)
            else:
                skipped += 1
        out[policy] = {"final_lag_ms": round(lag, 1), "harmful_caught_in_time": caught,
                       "harmful_arrived": harmful, "pii_checks_on_time": round(pii_ok / n, 4),
                       "classifier_skipped": round(skipped / n, 4)}
    return {"messages": n, "load": load, "deadline_ms": deadline_ms, "traffic": traffic,
            "capacity_per_s": w["measured"]["capacityPerSecond"],
            "note": "check costs measured with the thesis's scikit-learn implementation",
            "policies": out}
