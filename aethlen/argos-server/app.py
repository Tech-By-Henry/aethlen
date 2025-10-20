import os
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ConfigDict

# Where Argos packages live (mount a volume here)
PKG_DIR = os.environ.get("ARGOS_PACKAGES_DIR", "/packages")
os.environ["ARGOS_PACKAGES_DIR"] = PKG_DIR  # ensure argostranslate uses it

from argostranslate import package, translate  # after setting env var

app = FastAPI(title="Argos Translate API", version="0.1.0")


def list_pairs() -> List[Dict[str, Any]]:
    pairs = []
    for p in package.get_installed_packages():
        pairs.append(
            {
                "from": getattr(p, "from_code", "?"),
                "to": getattr(p, "to_code", "?"),
                "version": getattr(p, "version", "?"),
            }
        )
    return pairs


class TranslateRequest(BaseModel):
    # accept multiple common key names so tools are flexible
    model_config = ConfigDict(populate_by_name=True)
    q: Optional[str] = None
    text: Optional[str] = None
    source: Optional[str] = None
    target: Optional[str] = None
    from_: Optional[str] = Field(None, alias="from")
    to: Optional[str] = None
    source_language_code: Optional[str] = None
    target_language_code: Optional[str] = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "packages_dir": PKG_DIR,
        "installed_pairs": list_pairs(),
    }


@app.get("/pairs")
def pairs():
    return list_pairs()


@app.post("/translate")
def do_translate(req: TranslateRequest):
    text = req.q or req.text
    src = req.source or req.from_ or req.source_language_code
    tgt = req.target or req.to or req.target_language_code

    if not text or not src or not tgt:
        raise HTTPException(
            400,
            "Provide text ('q' or 'text'), 'source'/'from' and 'target'/'to'.",
        )

    try:
        translator = translate.get_translation(src, tgt)
    except Exception:
        raise HTTPException(
            422,
            f"No translation model for {src}->{tgt}. Installed pairs: {list_pairs()}",
        )

    try:
        out = translator.translate(text)
    except Exception as e:
        raise HTTPException(500, f"Translation failed: {e}")

    return {"translation": out, "source": src, "target": tgt}
