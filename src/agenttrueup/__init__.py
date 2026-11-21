"""agenttrueup — trust, but reconcile.

Verify what your AI coding agent *said* against what your filesystem,
git state and manifests *actually* show, and flag what it left behind.
100% local, read-only, standard library only.
"""

try:
    from importlib.metadata import version as _meta_version

    __version__ = _meta_version("agenttrueup")
except Exception:  # not installed (running from a clone): keep the fallback
    __version__ = "0.3.2"
