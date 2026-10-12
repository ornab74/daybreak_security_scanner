import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from chat_memory import MemoryStore, MemoryError


class ChatMemoryTests(unittest.TestCase):
    def test_local_history_and_isolated_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=MemoryStore(Path(tmp)/"history.db")
            first=store.new_chat()
            second=store.new_chat()
            store.save(first,"user","hello")
            store.save(second,"user","other")
            self.assertEqual(store.messages(first),[("user","hello")])
            self.assertEqual(store.messages(second),[("user","other")])
            self.assertEqual(len(store.chats()),2)
            store.forget_chat(first)
            self.assertEqual(store.messages(first),[])
            self.assertEqual(len(store.chats()),1)

    def test_opt_in_only(self):
        with tempfile.TemporaryDirectory() as tmp, patch("chat_memory._ensure_schema") as schema:
            store=MemoryStore(Path(tmp)/"history.db")
            ident=store.new_chat()
            store.save(ident,"user","do not embed")
            schema.assert_not_called()

    def test_memory_failure_never_silently_saves_untracked_vector(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=MemoryStore(Path(tmp)/"history.db")
            ident=store.new_chat()
            with patch("chat_memory._ensure_schema",side_effect=MemoryError("offline")):
                with self.assertRaises(MemoryError):
                    store.save(ident,"user","secret",remember=True)
            self.assertEqual(store.messages(ident),[])

    def test_recall_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=MemoryStore(Path(tmp)/"history.db")
            with patch("chat_memory._ensure_schema"),patch("chat_memory.embed",return_value=[0.2,0.8]),patch(
                "chat_memory._post",return_value={"data":{"Get":{"DaybreakMemory":[{"content":"saved fact"}]}}}
            ) as req:
                out=store.recall("hello")
                self.assertEqual(out[0]["content"],"saved fact")
                self.assertIn(store.scope,req.call_args.args[1]["query"])

if __name__=="__main__":
    unittest.main()
