"""Sentinel CLI entry point."""

import os
import subprocess
import sys

import click

from src import __version__ as _SENTINEL_VERSION


@click.group()
def main():
    """Sentinel — network intrusion detection system."""
    pass


@main.command()
def version():
    """Print sentinel version + git commit."""
    git_hash = "unknown"
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2,
        )
        if r.returncode == 0:
            git_hash = r.stdout.strip()
    except Exception:
        pass
    click.echo(f"sentinel {_SENTINEL_VERSION} ({git_hash})")


@main.command()
@click.option("-i", "--interface", required=False,
              help="Network interface to capture on (e.g. eth0). "
                   "Falls back to config file.")
@click.option("-c", "--config", default="config.yaml", show_default=True,
              help="Path to config.yaml.")
@click.option("--no-dashboard", is_flag=True, default=False,
              help="Disable curses dashboard (plain text output).")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Print raw hex bytes for every packet.")
@click.option("--output", type=click.Choice(["stdout", "file", "http_post"]),
              default="stdout", show_default=True,
              help="Where to emit codex-contract events.")
@click.option("--output-url", default=None,
              help="URL for http_post output.")
@click.option("--output-file", default=None,
              help="File path for file output.")
def run(interface, config, no_dashboard, verbose, output, output_url, output_file):
    """Run sentinel against a network interface."""
    if os.geteuid() != 0:
        click.echo("[!] sentinel run requires root. Re-run with sudo.", err=True)
        sys.exit(1)

    # defer the heavy import so `sentinel version` is fast
    from src.main import run_sentinel

    run_sentinel(
        interface=interface,
        config_path=config,
        no_dashboard=no_dashboard,
        verbose=verbose,
        output_spec=output,
        output_url=output_url,
        output_file=output_file,
    )


if __name__ == "__main__":
    main()
