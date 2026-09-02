"""Local development library for the multi-step-tool-attacks competition.

NOT part of the submission. The submitted /kaggle/working/attack.py is loaded
standalone by the evaluator and must be self-contained — do NOT import attacklib
from attack.py. Use attacklib for offline recon, the local search harness, the
cell archive, and candidate verification.
"""
from attacklib.sdkpath import ensure_sdk_on_path

ensure_sdk_on_path()
