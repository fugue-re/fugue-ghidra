import subprocess

from os import environ, path
from tempfile import TemporaryDirectory
from typing import Optional


def import_headless(input_path: str, output_path: str, ghidra_root: Optional[str] = None):
    if ghidra_root is None:
        ghidra_root = environ['GHIDRA_INSTALL_DIR']

    with TemporaryDirectory() as root:
        ghidra = path.join(ghidra_root, 'support', 'analyzeHeadless')
        result = subprocess.run([
            ghidra,
            str(root),
            'project',
            '-import', input_path,
            '-deleteProject',
            '-preScript', 'FugueAnalysisOptions.java',
            '-postScript', 'FugueExport.java',
            'FugueForceOverwrite:true',
            f'FugueOutput:{output_path}'
        ])

        if result.returncode != 100:
            raise Exception(f'import failed for {input_path}')
