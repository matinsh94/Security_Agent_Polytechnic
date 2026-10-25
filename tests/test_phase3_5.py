import pytest
from scripts.siem_connector import SIEMConnector
from scripts.chat_bot import ChatBot
from scripts.vector_store import VectorStore
from scripts.anomaly_detector import AnomalyDetector
from scripts.threat_actor_attribution import ThreatActorAttribution
from scripts.geo_mapper import GeoMapper
from scripts.playbook_engine import PlaybookEngine
from scripts.threat_classifier import ThreatClassifier
from scripts.fp_filter import FPFilter
from scripts.breach_predictor import BreachPredictor
from scripts.malware_clusterer import MalwareClusterer
from scripts.zero_day_predictor import ZeroDayPredictor

def test_modules_instantiate():
    assert SIEMConnector() is not None
    assert ChatBot() is not None
    vs = VectorStore(db_path="/tmp/kilo/v.db")
    vs.add("1", "test threat")
    assert vs.search("test")
    ad = AnomalyDetector()
    assert len(ad.detect([1,2,3,100])) == 4
    assert ThreatActorAttribution().attribute("phishing apt") 
    assert GeoMapper().map_ip("1.1.1.1")["ip"] == "1.1.1.1"
    pe = PlaybookEngine(playbook_dir="/tmp/kilo/pb")
    pb = pe.generate({"cve_id": "CVE-2024-1", "ioc": "1.2.3.4"})
    assert "steps" in pb
    tc = ThreatClassifier(model_path="/tmp/kilo/m.pkl")
    assert tc.predict("x") in (0,1)
    assert FPFilter().is_false_positive("ab") is True
    assert 0 <= BreachPredictor().score({"threat_score": 80}) <= 1.0
    assert MalwareClusterer().cluster([{"family":"a"}])
    assert 0 <= ZeroDayPredictor().predict("zero-day unpatched") <= 1.0
