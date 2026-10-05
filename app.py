"""
Football SIEM — live World Cup match -> security-log-style anomaly detection.
"""
import os, time, threading, itertools
from dataclasses import dataclass, field
from typing import Optional
import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "4"))
SOURCE = os.getenv("SOURCE", "mock")
ESPN_LEAGUE = os.getenv("ESPN_LEAGUE", "fifa.world")
EVENT_ID = os.getenv("EVENT_ID", "")

@dataclass
class Snapshot:
    minute: int = 0
    status: str = "live"
    home: str = "HOME"
    away: str = "AWAY"
    home_seed: int = 0
    away_seed: int = 0
    score: tuple = (0, 0)
    possession: tuple = (50, 50)
    shots: tuple = (0, 0)
    shots_on: tuple = (0, 0)
    fouls: tuple = (0, 0)
    xg: tuple = (0.0, 0.0)
    passing: tuple = (0, 0)
    field_tilt: tuple = (50, 50)
    pressure: tuple = (0, 0)
    transitions: tuple = (0, 0)
    line_breaks: tuple = (0, 0)
    rest_defense: tuple = (50, 50)
    note: str = ""

class MockSource:
    def __init__(self):
        self.t0 = None
        self.started = False

    def start(self):
        self.t0 = time.time()
        self.started = True

    def fetch(self) -> Optional[Snapshot]:
        if not self.started or self.t0 is None:
            return Snapshot(
                minute=0,
                status="READY",
                home="KOREA",
                away="CZECHIA",
                score=(0, 0),
                possession=(50, 50),
                shots=(0, 0),
                shots_on=(0, 0),
                fouls=(0, 0),
                xg=(0.0, 0.0),
                passing=(0, 0),
                field_tilt=(50, 50),
                pressure=(0, 0),
                transitions=(0, 0),
                line_breaks=(0, 0),
                rest_defense=(50, 50),
                note="press start to arm the match monitor",
            )

        m = min(int((time.time() - self.t0) * 3), 90)

        def ramp(a, b, lo, hi):
            if m <= lo:
                return a
            if m >= hi:
                return b
            return a + (b - a) * (m - lo) / (hi - lo)

        score = (0, 0)
        if m >= 59:
            score = (0, 1)
        if m >= 67:
            score = (1, 1)
        if m >= 80:
            score = (2, 1)

        note = ""
        if 59 <= m < 67:
            note = "set-piece header — Krejci puts Czechia ahead"
        elif 67 <= m < 80:
            note = "Hwang In-beom levels for Korea"
        elif m >= 80:
            note = "Oh Hyeon-gyu (sub) completes the turnaround"

        poss_k = int(ramp(56, 68, 0, 70))
        shots = (int(ramp(0, 20, 0, 90)), int(ramp(0, 6, 0, 90)))
        shots_on = (int(ramp(0, 7, 0, 90)), int(ramp(0, 2, 0, 88)))
        fouls = (int(ramp(0, 8, 0, 90)), int(ramp(0, 15, 0, 90)))
        xg = (round(ramp(0.05, 2.45, 0, 90), 2), round(ramp(0.02, 0.74, 0, 90), 2))
        passing = (int(ramp(82, 91, 0, 90)), int(ramp(79, 72, 0, 90)))
        field_tilt = (int(ramp(52, 71, 0, 90)), int(ramp(48, 29, 0, 90)))
        pressure = (int(ramp(48, 88, 0, 90)), int(ramp(44, 57, 0, 90)))
        transitions = (int(ramp(0, 6, 0, 90)), int(ramp(0, 9, 0, 90)))
        line_breaks = (int(ramp(1, 17, 0, 90)), int(ramp(0, 6, 0, 90)))
        rest_defense = (int(ramp(58, 81, 0, 90)), int(ramp(53, 34, 0, 90)))

        return Snapshot(
            minute=m,
            status="FT" if m >= 90 else "live",
            home="KOREA",
            away="CZECHIA",
            score=score,
            possession=(poss_k, 100 - poss_k),
            shots=shots,
            shots_on=shots_on,
            fouls=fouls,
            xg=xg,
            passing=passing,
            field_tilt=field_tilt,
            pressure=pressure,
            transitions=transitions,
            line_breaks=line_breaks,
            rest_defense=rest_defense,
            note=note,
        )

class EspnSource:
    SB  = "https://site.api.espn.com/apis/site/v2/sports/soccer/{lg}/scoreboard"
    SUM = "https://site.web.api.espn.com/apis/site/v2/sports/soccer/{lg}/summary"
    UA  = {"User-Agent": "Mozilla/5.0 (football-siem build-day)"}

    def __init__(self):
        self.event_id = EVENT_ID or None

    def _get(self, url, **params):
        r = httpx.get(url, params=params, headers=self.UA, timeout=15)
        r.raise_for_status()
        return r.json()

    def _pick_event(self):
        events = self._get(self.SB.format(lg=ESPN_LEAGUE)).get("events", [])
        if not events:
            return None
        live = [e for e in events if e.get("status", {}).get("type", {}).get("state") == "in"]
        return (live[0] if live else events[0])["id"]

    @staticmethod
    def _stat(stats, *names):
        for s in stats:
            tags = ((s.get("name") or "").lower(), (s.get("label") or "").lower(),
                    (s.get("abbreviation") or "").lower())
            if any(n in tags for n in names):
                v = s.get("displayValue", s.get("value", 0))
                if isinstance(v, str):
                    v = v.replace("%", "").split("/")[0].strip() or 0
                try:
                    return float(v)
                except (TypeError, ValueError):
                    return 0
        return 0

    def fetch(self) -> Optional[Snapshot]:
        if not self.event_id:
            self.event_id = self._pick_event()
        if not self.event_id:
            return None
        data = self._get(self.SUM.format(lg=ESPN_LEAGUE), event=self.event_id)
        comp = data["header"]["competitions"][0]
        cs = comp["competitors"]
        home = next(c for c in cs if c["homeAway"] == "home")
        away = next(c for c in cs if c["homeAway"] == "away")
        stt = comp.get("status", {})
        state = stt.get("type", {}).get("state", "in")
        clock = stt.get("displayClock", "") or ""
        lead = ""
        for ch in clock:
            if ch.isdigit():
                lead += ch
            else:
                break
        minute = int(lead) if lead else int((stt.get("clock") or 0) // 60)
        snap = Snapshot(
            minute=minute,
            status={"in": "live", "post": "FT", "pre": "PRE"}.get(state, state),
            home=home["team"]["displayName"].upper(),
            away=away["team"]["displayName"].upper(),
            score=(int(home.get("score") or 0), int(away.get("score") or 0)),
        )
        box = (data.get("boxscore") or {}).get("teams") or []
        by_id = {t["team"]["id"]: t.get("statistics", []) for t in box}
        hs = by_id.get(home["team"]["id"], [])
        as_ = by_id.get(away["team"]["id"], [])
        if hs and as_:
            snap.possession = (int(self._stat(hs, "possessionpct", "possession")) or 50,
                               int(self._stat(as_, "possessionpct", "possession")) or 50)
            snap.shots = (int(self._stat(hs, "totalshots", "shots")), int(self._stat(as_, "totalshots", "shots")))
            snap.shots_on = (int(self._stat(hs, "shotsontarget", "ontargetshots")), int(self._stat(as_, "shotsontarget", "ontargetshots")))
            snap.fouls = (int(self._stat(hs, "foulscommitted", "fouls")), int(self._stat(as_, "foulscommitted", "fouls")))
        return snap

def make_source():
    return EspnSource() if SOURCE == "espn" else MockSource()

SEQ = itertools.count(1)
INCIDENT_SEQ = itertools.count(100)

@dataclass
class State:
    snap: Snapshot = field(default_factory=Snapshot)
    anomaly: float = 0.05
    peak: float = 0.05
    threat: str = "NOMINAL"
    telemetry: dict = field(default_factory=lambda: {
        "threat_score": 5,
        "possession_delta": 0,
        "shot_pressure": 0,
        "xg_delta": 0.0,
        "field_tilt_delta": 0,
        "transition_risk": 0,
        "press_intensity": 0,
        "line_break_delta": 0,
        "rest_defense_gap": 0,
    })
    techniques: dict = field(default_factory=lambda: {
        "TAC-001": False, "TAC-002": False, "TAC-003": False, "TAC-004": False})
    log: list = field(default_factory=list)
    incidents: list = field(default_factory=list)
    hunts: list = field(default_factory=list)
    playbook: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    alert: Optional[dict] = None

class Detector:
    def __init__(self):
        self.state = State()
        self.prev: Optional[Snapshot] = None

    def _log(self, sev, tag, msg, src="match.telemetry", mitre="TAC-BASE", sensor="edge-node-1", rule="R-BASE"):
        self.state.log.append({
            "seq": next(SEQ),
            "min": self.state.snap.minute,
            "ts": f"00:{self.state.snap.minute:02d}:{(self.state.snap.minute * 7) % 60:02d}",
            "sev": sev,
            "tag": tag,
            "src": src,
            "sensor": sensor,
            "rule": rule,
            "mitre": mitre,
            "msg": msg,
        })
        self.state.log = self.state.log[-90:]

    def _alert(self, kind, hd, ttl, det, mitre, stay=False):
        self.state.alert = {"seq": next(SEQ), "kind": kind, "hd": hd, "ttl": ttl, "det": det, "mitre": mitre, "stay": stay}

    def _incident(self, sev, title, summary, status="open"):
        self.state.incidents.insert(0, {"id": f"INC-{next(INCIDENT_SEQ)}", "minute": self.state.snap.minute, "severity": sev, "title": title, "summary": summary, "status": status})
        self.state.incidents = self.state.incidents[:6]

    def _timeline(self, phase, detail):
        self.state.timeline.insert(0, {"minute": self.state.snap.minute, "phase": phase, "detail": detail})
        self.state.timeline = self.state.timeline[:6]

    def _set_hunts(self, snap: Snapshot, possession_delta: int, pressure_gap: int):
        self.state.hunts = [
            {"name": "Possession drift", "query": f"poss_delta>{abs(possession_delta)}", "hits": max(abs(possession_delta) // 4, 1)},
            {"name": "Transition spikes", "query": f"transitions_away={snap.transitions[1]}", "hits": max(snap.transitions[1] // 2, 1)},
            {"name": "Rest-defense cracks", "query": f"rest_gap={snap.rest_defense[0]-snap.rest_defense[1]}", "hits": max(abs(snap.rest_defense[0]-snap.rest_defense[1]) // 10, 1)},
            {"name": "Press overload", "query": f"press_gap={pressure_gap}", "hits": max(abs(pressure_gap) // 8, 1)},
        ]

    def _set_playbook(self, threat, transition_risk, line_break_delta, rest_defense_gap):
        actions = [
            {"title": "Validate telemetry integrity", "status": "done" if threat != "CRITICAL" else "running", "owner": "SOC", "eta": "now"},
            {"title": "Check rest-defense spacing", "status": "running" if transition_risk >= 3 else "queued", "owner": "Analyst", "eta": "15s"},
            {"title": "Correlate line breaks with xG spike", "status": "running" if line_break_delta >= 6 else "queued", "owner": "Detector", "eta": "20s"},
            {"title": "Escalate upset alert to bridge", "status": "running" if threat == "CRITICAL" or transition_risk >= 4 else "queued", "owner": "Commander", "eta": "30s"},
        ]
        if rest_defense_gap >= 20:
            actions.append({"title": "Recommend containment block", "status": "queued", "owner": "Coach AI", "eta": "40s"})
        self.state.playbook = actions[:5]

    def update(self, s: Snapshot):
        st = self.state
        prev = self.prev

        if prev and prev.status in ("FT", "AET", "PEN") and s.status in ("FT", "AET", "PEN"):
            st.snap = s
            return st

        st.snap = s
        leader = 0 if s.score[0] > s.score[1] else (1 if s.score[1] > s.score[0] else -1)
        dominant = 0 if s.possession[0] >= s.possession[1] else 1
        minority = 1 - dominant

        xg_delta = round(s.xg[0] - s.xg[1], 2)
        shot_pressure = (s.shots[0] + 2 * s.shots_on[0]) - (s.shots[1] + 2 * s.shots_on[1])
        transition_risk = max(0, s.transitions[1] - s.transitions[0])
        press_intensity = max(0, s.pressure[0] - s.pressure[1])
        possession_delta = s.possession[0] - s.possession[1]
        field_tilt_delta = s.field_tilt[0] - s.field_tilt[1]
        line_break_delta = s.line_breaks[0] - s.line_breaks[1]
        rest_defense_gap = s.rest_defense[0] - s.rest_defense[1]

        if leader >= 0:
            gap = abs(s.score[0] - s.score[1])
            poss_dom = max(s.possession) / 100
            mism = 1.0 if leader != dominant else 0.0
            st.anomaly = min(0.08 + 0.32 * gap * poss_dom * mism + 0.30 * mism + 0.05 * transition_risk / 5 + 0.04 * max(0, line_break_delta) / 8, 0.99)
        st.peak = max(st.peak, st.anomaly)
        st.threat = "CRITICAL" if st.anomaly >= 0.85 else "ELEVATED" if st.anomaly >= 0.5 else "NOMINAL"
        st.telemetry = {
            "threat_score": int(round(st.anomaly * 100)),
            "possession_delta": possession_delta,
            "shot_pressure": shot_pressure,
            "xg_delta": xg_delta,
            "field_tilt_delta": field_tilt_delta,
            "transition_risk": transition_risk,
            "press_intensity": press_intensity,
            "line_break_delta": line_break_delta,
            "rest_defense_gap": rest_defense_gap,
        }

        st.techniques["TAC-002"] = max(s.possession) >= 62 or s.pressure[0] >= 70
        st.techniques["TAC-003"] = (min(s.possession) <= 35 and s.shots_on[minority] <= s.shots_on[dominant])
        st.techniques["TAC-001"] = transition_risk >= 3 or (leader == 1 and dominant == 0)
        st.techniques["TAC-004"] = (s.score[1] > 0 and s.xg[1] < 0.9) or (s.score[0] >= 2 and s.shots_on[0] <= s.score[0] + 1)
        self._set_hunts(s, possession_delta, press_intensity)
        self._set_playbook(st.threat, transition_risk, line_break_delta, rest_defense_gap)

        if prev is None:
            self._log("info", "SYS", "monitor armed · baseline established", "soc.pipeline", "TAC-INIT", "ctrl-plane", "R-BOOT")
            self._log("info", "AUTH", "telemetry bus connected · feed integrity nominal", "soc.ingest", "TAC-PIPE", "ingest-gw", "R-HEALTH")
            self._log("info", "HUNT", "threat hunts primed for possession drift / transition spikes", "soc.hunt", "TAC-HUNT", "hunt-orch", "R-HUNT")
            self._timeline("Baseline", "Monitor armed and sensors green")
            self.prev = s
            return st

        if s.note and s.note != prev.note:
            self._log("info", "NEWS", s.note, "soc.intel", "TAC-INTEL", "intel-feed", "R-NEWS")
            self._timeline("Intel", s.note)
        if abs(field_tilt_delta) >= 18 and abs(prev.field_tilt[0] - prev.field_tilt[1]) < 18:
            self._log("warn", "TILT", f"final-third occupation surge · field tilt {s.field_tilt[0]}:{s.field_tilt[1]}", "soc.analytics", "TAC-TILT", "tilt-model", "R-TILT")
            self._incident("medium", "Territory breach", f"Field tilt widened to {s.field_tilt[0]}:{s.field_tilt[1]} — final third pinned")
            self._timeline("Territory", f"Field tilt widened to {s.field_tilt[0]}:{s.field_tilt[1]}")
        if line_break_delta >= 6 and (prev.line_breaks[0] - prev.line_breaks[1]) < 6:
            self._log("warn", "LINES", f"progressive line breaks surging · delta {line_break_delta}", "soc.analytics", "TAC-BREAK", "break-model", "R-LB6")
            self._incident("medium", "Structure puncture", f"KOREA line-break delta reached {line_break_delta}; central lanes compromised")
            self._timeline("Penetration", f"Line-break delta hit {line_break_delta}")
        if press_intensity >= 20 and (prev.pressure[0] - prev.pressure[1]) < 20:
            self._incident("medium", "High press campaign", f"KOREA press intensity climbed to {press_intensity}; turnover pressure building")
            self._log("warn", "PRESS", f"high press campaign detected · intensity {press_intensity}", "soc.edr", "TAC-002", "press-sensor", "R-PRESS20")
            self._timeline("Pressure", f"Press intensity hit {press_intensity}")
        if transition_risk >= 4 and max(0, prev.transitions[1] - prev.transitions[0]) < 4:
            self._incident("high", "Counter window exposed", f"CZECHIA transition risk index hit {transition_risk}; rest-defense unstable")
            self._log("warn", "TRANS", f"counter lane exposure · risk index {transition_risk}", "soc.edr", "TAC-001", "transition-sensor", "R-TRANS4")
            self._timeline("Exposure", f"Transition risk escalated to {transition_risk}")
        if rest_defense_gap >= 22 and (prev.rest_defense[0] - prev.rest_defense[1]) < 22:
            self._log("warn", "REST", f"rest-defense stretched · gap {rest_defense_gap}", "soc.analytics", "TAC-REST", "restdef-model", "R-REST22")
            self._incident("high", "Containment fracture", f"Rest-defense gap widened to {rest_defense_gap}; counter cover degraded")
        if xg_delta >= 0.9 and s.score[0] == s.score[1] and prev.score == s.score:
            self._log("info", "XG", f"xG pressure building · delta +{xg_delta}", "soc.analytics", "TAC-XG", "xg-model", "R-XG09")

        if s.possession != prev.possession:
            self._log("info", "POSS", f"territorial control {s.possession[0]}% / {s.possession[1]}%", "soc.telemetry", "TAC-TERR", "field-bus", "R-POSS")
        for side, name in ((0, s.home), (1, s.away)):
            if s.score[side] > prev.score[side]:
                scorer_poss = prev.possession[side]
                against_run = scorer_poss <= 40
                self._log("crit", "GOAL", f"GOAL — {name} ({s.score[0]}-{s.score[1]})" + (" · against run of play" if against_run else ""), "soc.edr", "TAC-GOAL", "goal-sensor", "R-GOAL")
                if against_run:
                    self._incident("critical", "Upset sequence detected", f"{name} scored with only {scorer_poss}% possession; territorial control inverted")
                    self._timeline("Detonation", f"{name} scored against run of play")
                    if s.score[side] > s.score[1 - side]:
                        self._alert("warn", "RULE FIRED · R-07 momentum", "UPSET DETECTED", f"<b>{name}</b> scores against the run of play on <b>{scorer_poss}%</b> possession.<br>Transition risk, line breaks, and scoreline diverged.", "MAP · TAC-001 Counter-Attack")
                    else:
                        self._log("warn", "ANOMALY", f"{name} scores against run of play · {scorer_poss}% possession", "soc.analytics", "TAC-001", "anomaly-core", "R-UPSET")
                elif s.score[side] > s.score[1 - side] and prev.score[side] <= prev.score[1 - side] and side == dominant and st.peak >= 0.5:
                    self._incident("low", "Threat contained", f"{name} restored control after upset window collapsed", status="resolved")
                    self._timeline("Containment", f"{name} restored control and closed the upset window")
                    self._alert("ok", "RULE CLEARED · R-07 resolved", "THREAT CONTAINED", f"<b>{name}</b> retakes the lead on <b>{scorer_poss}%</b> possession.<br>Control-plane metrics have normalized.", "RESOLVE · TAC-002 High Press")
            if s.shots[side] > prev.shots[side]:
                self._log("info", "SHOT", f"{name} shot volume {s.shots[side]} · on-target {s.shots_on[side]}", "soc.telemetry", "TAC-SHOT", "shot-bus", "R-SHOT")
            if s.fouls[side] > prev.fouls[side]:
                self._log("warn", "FOUL", f"{name} foul count {s.fouls[side]} · disruption rising", "soc.telemetry", "TAC-FOUL", "foul-bus", "R-FOUL")

        if s.status in ("FT", "AET", "PEN") and prev.status not in ("FT", "AET", "PEN"):
            self._log("crit", "FT", f"FULL-TIME · {s.home} {s.score[0]}-{s.score[1]} {s.away}", "soc.pipeline", "TAC-END", "ctrl-plane", "R-CLOSE")
            summary = f"Peak threat {st.peak:.2f}, xG delta {xg_delta:+.2f}, field tilt {s.field_tilt[0]}:{s.field_tilt[1]}"
            self._incident("info", "Post-match report generated", summary, status="closed")
            self._timeline("Closure", "Post-match report exported to analyst bridge")
            if st.peak >= 0.5:
                self._alert("ok", "INCIDENT CLOSED · control restored", "CONTROL RESTORED", f"Favorite went behind, then recovered · final <b>{s.home} {s.score[0]}-{s.score[1]} {s.away}</b>.<br>Peak anomaly {st.peak:.2f} → resolved to {st.anomaly:.2f}.", "EXPORT · incident-report.pdf", stay=True)

        self.prev = s
        return st

detector = Detector()
source = make_source()

def reset_demo():
    global detector, source
    detector = Detector()
    source = make_source()

def start_demo():
    reset_demo()
    if hasattr(source, "start"):
        source.start()

def poll_loop():
    while True:
        try:
            snap = source.fetch()
            if snap:
                detector.update(snap)
        except Exception as e:
            detector._log("warn", "SYS", f"poll error · {type(e).__name__}", "soc.pipeline", "TAC-ERR", "ctrl-plane", "R-ERR")
        time.sleep(POLL_SECONDS)

app = FastAPI(title="Football SIEM")

@app.on_event("startup")
def _start():
    threading.Thread(target=poll_loop, daemon=True).start()

@app.get("/state")
def state():
    st = detector.state
    return JSONResponse({
        "minute": st.snap.minute,
        "status": st.snap.status,
        "home": st.snap.home,
        "away": st.snap.away,
        "home_seed": st.snap.home_seed,
        "away_seed": st.snap.away_seed,
        "score": list(st.snap.score),
        "possession": list(st.snap.possession),
        "shots": list(st.snap.shots),
        "shots_on": list(st.snap.shots_on),
        "fouls": list(st.snap.fouls),
        "xg": list(st.snap.xg),
        "passing": list(st.snap.passing),
        "field_tilt": list(st.snap.field_tilt),
        "pressure": list(st.snap.pressure),
        "transitions": list(st.snap.transitions),
        "line_breaks": list(st.snap.line_breaks),
        "rest_defense": list(st.snap.rest_defense),
        "anomaly": round(st.anomaly, 2),
        "threat": st.threat,
        "telemetry": st.telemetry,
        "techniques": st.techniques,
        "log": st.log,
        "incidents": st.incidents,
        "hunts": st.hunts,
        "playbook": st.playbook,
        "timeline": st.timeline,
        "alert": st.alert,
        "started": getattr(source, "started", True),
    })

@app.post("/start")
def start():
    start_demo()
    return JSONResponse({"ok": True})

@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
