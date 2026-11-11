from pathlib import Path

import pytest

from autocra import engine, report, requirements
from autocra.model import Polarity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def analysis(tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    # Les jeux d'essai vivent sous tests/fixtures : on lève les exclusions par défaut.
    return engine.analyse(FIXTURES, out, with_sbom=False, excludes=())


def rules(analysis, requirement_id, polarity=None):
    evidence = next(e for e in analysis.evidences if e.reference == requirement_id)
    return {f.rule_id for f in evidence.findings if polarity is None or f.polarity is polarity}


def test_referentiel_complet():
    assert len(requirements.REQUIREMENTS) == 22
    assert sum(r.part == "I" for r in requirements.REQUIREMENTS) == 14
    assert sum(r.part == "II" for r in requirements.REQUIREMENTS) == 8


def test_points_d_entree(analysis):
    found = rules(analysis, "CRA-I-1-2j")
    assert {"py-django-url", "py-drf-router", "py-flask-fastapi-route", "js-express-route", "js-server-listen"} <= found


def test_messages_temps_reel(analysis):
    evidence = next(e for e in analysis.evidences if e.reference == "CRA-I-1-2j")
    handlers = [f for f in evidence.findings if f.rule_id == "js-socket-handler"]
    # "connection" et "editItem" sont des points d'entrée ; "error" n'en est pas un.
    assert len(handlers) == 2


def test_questionnaire(analysis):
    text = report.render_questionnaire(analysis)
    assert "CRA-I-1-1" in text and "analyse de risques" in text
    assert "CRA-I-1-2d" not in text  # aucune question pour cette exigence


def test_reglages_par_defaut(analysis):
    contre = rules(analysis, "CRA-I-1-2b", Polarity.CONTRE)
    assert {"py-django-debug-true", "py-django-allowed-hosts-wildcard", "py-hardcoded-password"} <= contre
    assert "py-django-password-validators" in rules(analysis, "CRA-I-1-2b", Polarity.POUR)


def test_cryptographie(analysis):
    contre = rules(analysis, "CRA-I-1-2e", Polarity.CONTRE)
    assert {"py-weak-hash", "py-tls-verify-disabled", "js-weak-hash", "js-tls-verify-disabled"} <= contre


def test_appels_sortants_sans_delai(analysis):
    evidence = next(e for e in analysis.evidences if e.reference == "CRA-I-1-2i")
    missing = [f for f in evidence.findings if f.rule_id == "py-http-timeout-missing"]
    assert len(missing) == 1  # l'appel avec timeout=10 n'est pas signalé


def test_preuves_localisees(analysis):
    for f in analysis.findings:
        if f.category != "process" and f.category != "sbom":
            assert f.location.file and f.location.line


def test_absence_n_est_pas_un_verdict(analysis):
    evidence = next(e for e in analysis.evidences if e.reference == "CRA-II-5")
    assert "security-policy-absent" in {f.rule_id for f in evidence.findings}
    assert "absence non prouvée" in evidence.findings[0].message


def test_rapport(analysis, tmp_path):
    report.write_json(analysis, tmp_path / "p.json")
    text = report.render_markdown(analysis)
    assert "ne déclare pas la conformité" in text
    assert "CRA-I-1-2b" in text and "CRA-II-8" in text
