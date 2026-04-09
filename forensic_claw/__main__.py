"""
Entry point for running forensic-claw as a module: python -m forensic_claw
"""

from forensic_claw.cli.commands import app

if __name__ == "__main__":
    app()
