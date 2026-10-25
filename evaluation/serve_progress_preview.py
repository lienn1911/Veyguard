"""Static stage preview in isolated state; no model call or analyst decision."""

from evaluation import serve_ui_acceptance as preview

preview.api._ai_service._set_progress(
    "INC-169BFBAAF1BA", "analyse", 65, "Comparing the retrieved evidence and drafting findings."
)
if __name__ == "__main__":
    preview.api.ThreadingHTTPServer(("127.0.0.1", 8790), preview.Handler).serve_forever()
