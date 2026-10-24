import importlib.util,os,tempfile
from pathlib import Path
base=Path(r'C:\Users\NITRO V15\AppData\Local\OpenAI-Profiles\Account-B\codex-home\plugins\cache\openai-primary-runtime\documents\26.1022.11436\skills\documents')
work=Path('reports/report-work').resolve()
tempfile.tempdir=str(work)
os.environ['PATH']=r'C:\Users\NITRO V15\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\poppler\Library\bin'+os.pathsep+os.environ['PATH']
spec=importlib.util.spec_from_file_location('document_renderer',base/'render_docx.py')
renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
# Windows host has no LibreOffice bundle. Native Word exported the same DOCX;
# retain the packaged renderer's PDF rasterization and page-naming pipeline.
renderer.convert_to_pdf=lambda *args,**kwargs:(str(work/'project-name.pdf'),'Rendered by Microsoft Word 16')
pages=renderer.rasterize(str(Path('reports/Competition_Report_formatted.docx').resolve()),str(work/'project-name-pages'),130,False,False)
print(len(pages),'pages rendered')
