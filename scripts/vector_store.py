"""Vector store for semantic search over threat findings."""
from __future__ import annotations
import json, logging, os, sqlite3
from typing import Any
logger = logging.getLogger(__name__)

class VectorStore:
    def __init__(self, db_path: str = "data/vector.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("CREATE TABLE IF NOT EXISTS docs (id TEXT PRIMARY KEY, text TEXT, meta TEXT)")
        self.conn.commit()
        self.chroma = None
        try:
            import chromadb
            self.chroma = chromadb.Client()
            self.collection = self.chroma.get_or_create_collection("threats")
        except Exception:
            self.collection = None

    def add(self, doc_id: str, text: str, meta: dict[str, Any] | None = None) -> None:
        self.conn.execute("INSERT OR REPLACE INTO docs VALUES (?,?,?)", (doc_id, text, json.dumps(meta or {})))
        self.conn.commit()
        if self.collection is not None:
            try:
                self.collection.add(documents=[text], ids=[doc_id], metadatas=[meta or {}])
            except Exception as e:
                logger.warning("chroma add failed: %s", e)

    def search(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        if self.collection is not None:
            try:
                res = self.collection.query(query_texts=[query], n_results=k)
                out = []
                for i, d in enumerate(res.get("documents", [[]])[0]):
                    out.append({"id": res["ids"][0][i], "text": d, "meta": res["metadatas"][0][i]})
                return out
            except Exception as e:
                logger.warning("chroma search failed: %s", e)
        # fallback substring
        cur = self.conn.execute("SELECT id,text,meta FROM docs WHERE text LIKE ?", (f"%{query}%",))
        return [{"id": r[0], "text": r[1], "meta": json.loads(r[2])} for r in cur.fetchall()[:k]]
