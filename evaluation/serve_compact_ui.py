from pathlib import Path
src=Path(__file__).with_name('serve_ui_acceptance.py')
text=src.read_text(encoding='utf-8').replace("('final-ui-fixture' if FIXTURE else 'final-ui-test')", "'compact-ui-check-20261024'")
exec(compile(text,str(src),'exec'))
