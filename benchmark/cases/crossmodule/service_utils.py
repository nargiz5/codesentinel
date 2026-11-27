"""Helper called from another module (cross-module flow)."""
import os


def restart(service):
    os.system("systemctl restart " + service)  # expect: vuln CWE-78
