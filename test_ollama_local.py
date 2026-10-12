import io
import json
import unittest
from unittest.mock import patch, Mock

from ollama_local import OllamaError, available_models, pull_model, start_server


class OllamaLocalTests(unittest.TestCase):
    def test_lists_local_models(self):
        response = io.BytesIO(json.dumps({"models": [{"name": "qwen2.5-coder:7b"}, {"name": "llama3.2:3b"}]}).encode())
        with patch("ollama_local.urllib.request.urlopen", return_value=response) as mocked:
            self.assertEqual(available_models(), ["llama3.2:3b", "qwen2.5-coder:7b"])
            self.assertEqual(mocked.call_args.args[0], "http://127.0.0.1:11434/api/tags")

    def test_bad_model_never_reaches_subprocess(self):
        with patch("ollama_local.subprocess.run") as run:
            with self.assertRaises(OllamaError):
                pull_model("foo; touch /tmp/example")
            run.assert_not_called()

    def test_missing_binary_prevents_download(self):
        with patch("ollama_local.ollama_installed", return_value=False):
            with self.assertRaises(OllamaError):
                pull_model("qwen2.5-coder:7b")

    def test_pull_runs_without_shell(self):
        with patch("ollama_local.ollama_installed", return_value=True), patch(
            "ollama_local.subprocess.run", return_value=Mock(returncode=0)
        ) as run:
            pull_model("qwen2.5-coder:7b")
            self.assertEqual(run.call_args.args[0], ["ollama", "pull", "qwen2.5-coder:7b"])
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_start_existing_server_does_not_launch_second_instance(self):
        with patch("ollama_local.ollama_installed", return_value=True), patch(
            "ollama_local.available_models", return_value=[]
        ), patch("ollama_local.subprocess.Popen") as process:
            start_server()
            process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
