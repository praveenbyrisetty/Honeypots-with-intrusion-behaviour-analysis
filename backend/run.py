"""
Adaptive Honeypot Layer — Entry Point
Starts all low-interaction and medium-interaction honeypots.
"""

import os
import sys
import signal
import logging
import time

# Add the backend directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from data_collection.db import init_db
from data_collection.logger import HoneypotLogger

# Low-interaction honeypots
from honeypots.low_interaction.ssh_honeypot import LowSSHHoneypot
from honeypots.low_interaction.ftp_honeypot import LowFTPHoneypot
from honeypots.low_interaction.http_honeypot import LowHTTPHoneypot
from honeypots.low_interaction.telnet_honeypot import LowTelnetHoneypot
from honeypots.low_interaction.smb_honeypot import LowSMBHoneypot

# Medium-interaction honeypots
from honeypots.medium_interaction.ssh_honeypot import MedSSHHoneypot
from honeypots.medium_interaction.ftp_honeypot import MedFTPHoneypot
from honeypots.medium_interaction.http_honeypot import MedHTTPHoneypot


def setup_logging():
    """Configure console logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)-24s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    setup_logging()
    log = logging.getLogger("honeypot.main")

    # ── Initialise data layer ─────────────────────────────────────────
    log.info("Initialising database...")
    init_db(config.DATABASE_PATH)

    log.info("Initialising logger...")
    hp_logger = HoneypotLogger(
        log_dir=config.LOG_DIR,
        max_bytes=config.LOG_MAX_BYTES,
        backup_count=config.LOG_BACKUP_COUNT,
    )

    # ── Create all honeypots ──────────────────────────────────────────
    honeypots = [
        # Low-interaction
        LowSSHHoneypot(logger=hp_logger),
        LowFTPHoneypot(logger=hp_logger),
        LowHTTPHoneypot(logger=hp_logger),
        LowTelnetHoneypot(logger=hp_logger),
        LowSMBHoneypot(logger=hp_logger),
        # Medium-interaction
        MedSSHHoneypot(logger=hp_logger),
        MedFTPHoneypot(logger=hp_logger),
        MedHTTPHoneypot(logger=hp_logger),
    ]

    # ── Start all ─────────────────────────────────────────────────────
    log.info("=" * 60)
    log.info("  ADAPTIVE HONEYPOT LAYER")
    log.info("=" * 60)

    for hp in honeypots:
        try:
            hp.start()
        except Exception as e:
            log.error(f"Failed to start {hp.name}: {e}")

    log.info("-" * 60)
    log.info("  All honeypots running. Press Ctrl+C to stop.")
    log.info("-" * 60)

    # Print summary table
    log.info("")
    log.info(f"  {'Honeypot':<24} {'Port':<8} {'Type':<20} {'Status'}")
    log.info(f"  {'─'*24} {'─'*8} {'─'*20} {'─'*10}")
    for hp in honeypots:
        hp_type = "Low-Interaction" if hp.name.startswith("low_") else "Medium-Interaction"
        status = "✓ Running" if hp.is_running else "✗ Failed"
        log.info(f"  {hp.name:<24} {hp.port:<8} {hp_type:<20} {status}")
    log.info("")

    # ── Wait for shutdown ─────────────────────────────────────────────
    def shutdown(sig, frame):
        log.info("\nShutting down all honeypots...")
        for hp in honeypots:
            hp.stop()
        log.info("All honeypots stopped. Goodbye.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
