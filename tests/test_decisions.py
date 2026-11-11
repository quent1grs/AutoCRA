import pytest

from autocra import cli, decisions, engine, report


def test_decision_enregistree_et_historique(tmp_path):
    decisions.record(tmp_path, "CRA-I-1-2d", "partielle", "Alice Martin", "abc123", "Voir le lien de partage.")
    decisions.record(tmp_path, "CRA-I-1-2d", "respectée", "Alice Martin", "def456")
    assert len(decisions.load(tmp_path)) == 2  # l'historique est gardé
    assert decisions.latest(tmp_path)["CRA-I-1-2d"].status == "respectée"


@pytest.mark.parametrize("reference, status, author", [
    ("CRA-X", "partielle", "Alice"),          # exigence inconnue
    ("CRA-I-1-2d", "à examiner", "Alice"),    # état de départ de l'outil, pas une décision
    ("CRA-I-1-2d", "partielle", "  "),        # personne non nommée
])
def test_decision_refusee(tmp_path, reference, status, author):
    with pytest.raises(ValueError):
        decisions.record(tmp_path, reference, status, author, None)


def test_rapport_montre_la_decision_et_le_changement_de_code(tmp_path):
    code = tmp_path / "code"
    code.mkdir()
    out = tmp_path / "out"
    decisions.record(out, "CRA-I-1-2d", "partielle", "Alice Martin", "ancienne-version")
    analysis = engine.analyse(code, out, with_sbom=False)
    text = report.render_markdown(analysis)
    assert "partielle, par Alice Martin" in text
    assert "le code a changé depuis" in text
    assert "Cette fiche n'est pas validée" in text  # les autres fiches
    assert "validées par une personne sur cette version du code : 0 sur 22" in text


def test_commande_valider(tmp_path, capsys):
    code = tmp_path / "code"
    code.mkdir()
    out = tmp_path / "out"
    assert cli.main(["valider", "CRA-II-6", "--etat", "respectée", "--par", "Alice", "--code", str(code), "-o", str(out)]) == 0
    assert decisions.latest(out)["CRA-II-6"].author == "Alice"
