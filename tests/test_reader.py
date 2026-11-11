from pathlib import Path

from autocra import engine, reader, report, requirements
from autocra.model import Status

FIXTURES = Path(__file__).parent / "fixtures"


class FakeReader:
    name = "faux-modele"

    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def complete(self, system, user, schema):
        self.prompts.append(user)
        return self.answer, 1000, 200


ANSWER = {
    "etat_propose": "écart",
    "synthese": "Le mode de débogage est actif par défaut.",
    "elements_pour": [{"fichier": "pyapp/settings.py", "ligne": 7, "explication": "Règles de mot de passe."}],
    "elements_contre": [
        {"fichier": "pyapp/settings.py", "ligne": 3, "explication": "DEBUG vaut True."},
        {"fichier": "pyapp/inexistant.py", "ligne": 99, "explication": "Citation inventée."},
    ],
    "manques": ["Lire la documentation d'installation."],
    "confiance": "moyenne",
}


def run(only=("CRA-I-1-2b",), answer=ANSWER, tmp_path=None):
    fake = FakeReader(answer)
    analysis = engine.analyse(FIXTURES, tmp_path, with_sbom=False, excludes=(), reader=fake, only=only)
    return analysis, fake


def test_lecture_limitee_aux_exigences_demandees(tmp_path):
    analysis, fake = run(tmp_path=tmp_path)
    assert list(analysis.assessments) == ["CRA-I-1-2b"]
    assert len(fake.prompts) == 1


def test_extraits_numerotes_dans_le_message(tmp_path):
    _, fake = run(tmp_path=tmp_path)
    prompt = fake.prompts[0]
    assert "## pyapp/settings.py, lignes 1 à" in prompt
    assert "    3  DEBUG = True" in prompt
    assert "CRA-I-1-2b" in prompt


def test_citation_hors_extraits_non_verifiee(tmp_path):
    analysis, _ = run(tmp_path=tmp_path)
    a = analysis.assessments["CRA-I-1-2b"]
    assert a.status is Status.ECART
    assert [c.verified for c in a.contre] == [True, False]
    assert a.unverified == 1
    text = report.render_markdown(analysis)
    assert "(non vérifiée)" in text and "à valider par une personne" in text


def test_echec_du_modele_n_arrete_pas_l_analyse(tmp_path):
    class Broken(FakeReader):
        def complete(self, system, user, schema):
            raise RuntimeError("panne")

    analysis = engine.analyse(FIXTURES, tmp_path, with_sbom=False, excludes=(), reader=Broken({}),
                              only=("CRA-I-1-2b",))
    assert "panne" in analysis.assessments["CRA-I-1-2b"].error
    assert "échec" in report.render_markdown(analysis)


def test_elements_non_montres_sont_comptes(tmp_path, monkeypatch):
    monkeypatch.setattr(reader, "MAX_EXCERPT_CHARS", 400)
    analysis, fake = run(tmp_path=tmp_path)
    a = analysis.assessments["CRA-I-1-2b"]
    assert a.omitted > 0 and a.shown + a.omitted == len(analysis.evidences[2].findings)
    assert "ne sont pas montrés ici" in fake.prompts[0]


def test_schema_couvre_les_cinq_etats():
    assert set(reader.STATUS_VALUES) == {
        "respectée", "partielle", "écart", "dépend de l'installation", "absence non prouvée"}
    assert requirements.get("CRA-I-1-2b").part == "I"


def test_lecture_hors_ligne(tmp_path):
    import json
    offline = reader.FileReader(tmp_path)
    first = engine.analyse(FIXTURES, tmp_path, with_sbom=False, excludes=(), reader=offline, only=("CRA-I-1-2b",))
    assert "réponse attendue" in first.assessments["CRA-I-1-2b"].error
    assert (tmp_path / "prompts" / "CRA-I-1-2b.md").exists()
    (tmp_path / "reponses" / "CRA-I-1-2b.json").write_text(json.dumps(ANSWER), encoding="utf-8")
    second = engine.analyse(FIXTURES, tmp_path, with_sbom=False, excludes=(), reader=offline, only=("CRA-I-1-2b",))
    assert second.assessments["CRA-I-1-2b"].status is Status.ECART


def test_elements_sans_emplacement_ne_sont_pas_omis(tmp_path):
    from autocra.model import Finding, Location, Polarity
    from autocra.reader import build_excerpts
    (tmp_path / "a.py").write_text("x = 1\n")
    findings = [
        Finding(category="sbom", rule_id="sbom", message="Inventaire produit", location=Location("", 0),
                requirements=["CRA-II-1"], polarity=Polarity.POUR),
        Finding(category="setting", rule_id="py-env-variable", message="Réglage", location=Location("a.py", 1),
                requirements=["CRA-II-1"], polarity=Polarity.NEUTRE),
    ]
    excerpts, omitted = build_excerpts(tmp_path, findings)
    assert len(excerpts) == 1 and omitted == 0
