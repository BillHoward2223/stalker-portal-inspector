"""Source guardrails for the portal adapter."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNED = ("portal.php", "JsHttpRequest", "action=handshake", "hashlib", "prehash", "verify=False")


def test_adapters_do_not_embed_an_undocumented_handshake() -> None:
    for path in (ROOT / "adapters").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for token in BANNED:
            assert token not in source, f"{path.name} contains {token}"
    documented = (ROOT / "adapters" / "documented_api_adapter.py").read_text(encoding="utf-8")
    assert "verify=True" in documented
    assert "trust_env=False" in documented
    assert "follow_redirects=False" in documented
