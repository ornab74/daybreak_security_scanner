"""Local-first conversation journal plus optional Weaviate semantic memory.

Weaviate is *only* addressed via fixed loopback endpoint. Memories are saved
only when enabled in the UI. Separate SQLite history remains usable offline.
"""
from __future__ import annotations
import json
import sqlite3
import uuid
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import URLError, HTTPError
from platformdirs import user_data_dir

ROOT = Path(user_data_dir("DaybreakSecurityScanner", "Local"))
WEAVIATE = "http://127.0.0.1:8080"
OLLAMA = "http://127.0.0.1:11434"
CLASS_NAME = "DaybreakMemory"
MAX_TEXT = 12000
# Ignore environment proxy settings for local-only memory traffic.
DIRECT = build_opener(ProxyHandler({}))

class MemoryError(RuntimeError): pass

def _post(url, payload, timeout=20, method="POST"):
    req=Request(url, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"}, method=method)
    try:
        with DIRECT.open(req, timeout=timeout) as r: return json.load(r)
    except (URLError, HTTPError, ValueError, TimeoutError) as e:
        raise MemoryError(f"Local memory service unavailable: {type(e).__name__}") from e

def embed(text, model="nomic-embed-text"):
    data=_post(OLLAMA+"/api/embed", {"model":model,"input":text[:MAX_TEXT]}, timeout=90)
    vectors=data.get("embeddings", [])
    if not vectors or not isinstance(vectors[0], list): raise MemoryError("Ollama returned no embedding. Pull nomic-embed-text first.")
    return vectors[0]

def _ensure_schema():
    req=Request(WEAVIATE+"/v1/schema/"+CLASS_NAME)
    try:
        with DIRECT.open(req,timeout=5): return
    except HTTPError as e:
        if e.code != 404: raise MemoryError(f"Weaviate schema HTTP {e.code}") from e
    except URLError as e: raise MemoryError("Weaviate is not running on localhost:8080.") from e
    _post(WEAVIATE+"/v1/schema",{"class":CLASS_NAME,"vectorizer":"none",
        "properties":[{"name":"scope","dataType":["text"],"indexFilterable":True},
                      {"name":"session","dataType":["text"],"indexFilterable":True},
                      {"name":"role","dataType":["text"]},{"name":"content","dataType":["text"]},
                      {"name":"created","dataType":["date"]}]})

class MemoryStore:
    def __init__(self, path=None):
        self.path=Path(path) if path else ROOT/"chat.sqlite3"
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY, title TEXT NOT NULL, created TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, session TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, created TEXT NOT NULL, vector_id TEXT)")
            if not db.execute("SELECT value FROM config WHERE key='scope'").fetchone():
                db.execute("INSERT INTO config VALUES ('scope',?)",(str(uuid.uuid4()),))
    def _db(self): return sqlite3.connect(self.path,timeout=5)
    @property
    def scope(self):
        with self._db() as db: return db.execute("SELECT value FROM config WHERE key='scope'").fetchone()[0]
    def new_chat(self):
        ident=str(uuid.uuid4())
        with self._db() as db: db.execute("INSERT INTO conversations VALUES (?,?,?)",(ident,"New chat",datetime.now(timezone.utc).isoformat()))
        return ident
    def chats(self):
        with self._db() as db: return db.execute("SELECT id,title FROM conversations ORDER BY created DESC").fetchall()
    def messages(self,session):
        with self._db() as db: return db.execute("SELECT role,content FROM messages WHERE session=? ORDER BY rowid",(session,)).fetchall()
    def save(self,session,role,content,remember=False,embedding_model="nomic-embed-text"):
        if role not in ("user","assistant") or not content or len(content)>MAX_TEXT: raise ValueError("Invalid chat message")
        with self._db() as db:
            if not db.execute("SELECT 1 FROM conversations WHERE id=?",(session,)).fetchone():
                raise ValueError("Unknown conversation")
        vid=None
        if remember:
            _ensure_schema()
            vid=str(uuid.uuid4())
            vec=embed(content,embedding_model)
            _post(WEAVIATE+"/v1/objects",{"class":CLASS_NAME,"id":vid,"properties":{
                "scope":self.scope,"session":session,"role":role,"content":content,
                "created":datetime.now(timezone.utc).isoformat()},"vector":vec},timeout=30)
        ident=str(uuid.uuid4())
        with self._db() as db:
            if not db.execute("SELECT 1 FROM conversations WHERE id=?",(session,)).fetchone(): raise ValueError("Unknown conversation")
            db.execute("INSERT INTO messages VALUES (?,?,?,?,?,?)",(ident,session,role,content,datetime.now(timezone.utc).isoformat(),vid))
            if role=="user":
                db.execute("UPDATE conversations SET title=? WHERE id=? AND title='New chat'",(content[:75],session))
        return ident
    def recall(self,query,k=5,embedding_model="nomic-embed-text"):
        _ensure_schema()
        vector=embed(query,embedding_model)
        # GraphQL arguments are JSON literals (safe for both vector and scope).
        gql = ('{ Get { ' + CLASS_NAME + '(nearVector:{vector:' + json.dumps(vector) +
               '}, where:{path:["scope"],operator:Equal,valueText:' + json.dumps(self.scope) +
               '}, limit:' + str(min(max(k, 1), 12)) +
               ') {content role session _additional {id distance}} } }')
        result=_post(WEAVIATE+"/v1/graphql",{"query":gql})
        if result.get("errors"): raise MemoryError("Weaviate semantic search failed.")
        return result.get("data",{}).get("Get",{}).get(CLASS_NAME,[]) or []
    def search_history(self, query, k=10, session=None):
        """Offline keyword search of the local SQLite journal, newest first."""
        if not isinstance(query,str) or not query.strip():
            return []
        limit=min(max(int(k),1),50)
        escaped=query.strip().replace("\\","\\\\").replace("%","\\%").replace("_","\\_")
        sql=("SELECT id,session,role,content,created FROM messages "
             "WHERE content LIKE ? ESCAPE '\\'")
        params=["%"+escaped+"%"]
        if session is not None:
            sql+=" AND session=?"
            params.append(session)
        sql+=" ORDER BY created DESC LIMIT ?"
        params.append(limit)
        with self._db() as db:
            rows=db.execute(sql,params).fetchall()
        return [{"id":ident,"session":sid,"role":role,"content":content,
                 "created":created,"source":"sqlite"} for ident,sid,role,content,created in rows]

    def memory_stats(self):
        """Local counts, including the number of messages indexed in Weaviate."""
        with self._db() as db:
            conversations=db.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
            messages=db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            indexed=db.execute("SELECT COUNT(*) FROM messages WHERE vector_id IS NOT NULL").fetchone()[0]
        return {"conversations":conversations,"messages":messages,
                "weaviate_indexed":indexed,"sqlite_only":messages-indexed}

    def hybrid_recall(self,query,k=5,embedding_model="nomic-embed-text",session=None):
        """Merge semantic Weaviate results with offline SQLite keyword matches.

        Weaviate is the semantic source of truth; SQLite supplies exact-match
        recall and remains useful if local services are unavailable.
        """
        limit=min(max(int(k),1),12)
        lexical=self.search_history(query,k=limit,session=session)
        semantic=[]
        error=None
        try:
            semantic=self.recall(query,k=limit,embedding_model=embedding_model)
        except MemoryError as exc:
            error=exc
        results=[]
        seen=set()
        for item in semantic:
            if session is not None and item.get("session")!=session:
                continue
            key=(item.get("session"),item.get("role"),item.get("content"))
            if key in seen: continue
            seen.add(key)
            results.append({**item,"source":"weaviate"})
        for item in lexical:
            key=(item["session"],item["role"],item["content"])
            if key in seen: continue
            seen.add(key)
            results.append(item)
        if not results and error is not None:
            raise error
        return results[:limit]

    def forget_chat(self,session):
        with self._db() as db:
            ids=[r[0] for r in db.execute("SELECT vector_id FROM messages WHERE session=? AND vector_id IS NOT NULL",(session,))]
        for vid in ids: self._delete_vector(vid)
        with self._db() as db:
            db.execute("DELETE FROM messages WHERE session=?",(session,))
            db.execute("DELETE FROM conversations WHERE id=?",(session,))
    def forget_all(self):
        with self._db() as db:
            ids=[r[0] for r in db.execute("SELECT vector_id FROM messages WHERE vector_id IS NOT NULL")]
        for vid in ids: self._delete_vector(vid)
        with self._db() as db:
            db.execute("DELETE FROM messages")
            db.execute("DELETE FROM conversations")
    def _delete_vector(self,ident):
        req=Request(WEAVIATE+"/v1/objects/"+CLASS_NAME+"/"+ident,method="DELETE")
        try:
            with DIRECT.open(req,timeout=10): pass
        except HTTPError as e:
            if e.code!=404: raise MemoryError("Could not delete Weaviate memory.") from e
        except URLError as e: raise MemoryError("Cannot delete Weaviate memory while offline.") from e
