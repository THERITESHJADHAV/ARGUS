"""
ARGUS - Adaptive Real-time Guard for Unified Security
=====================================================
Main runner script.

Usage:
    python run_argus.py                         # Run everything (network + windows)
    python run_argus.py --mode network          # Only network detection
    python run_argus.py --mode windows          # Only Windows event detection
    python run_argus.py --interface "Wi-Fi"     # Specify network interface
    python run_argus.py --list-interfaces       # List available network interfaces
"""

import sys
import os
import argparse
import threading
import time

# ─────────────────────────────────────────────────────────────────────────────
# Ensure the backend directory is on the Python path so that
# `from app.detection...` works regardless of where the script is launched.
# ─────────────────────────────────────────────────────────────────────────────
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_model_path():
    """Resolve the Random Forest model path robustly."""
    model_path = (
        Path(BACKEND_DIR)
        / "app"
        / "models"
        / "argus_network_best_model.joblib"
    )
    if not model_path.exists():
        print(f"[ARGUS ERROR] Model not found at: {model_path}")
        print("[ARGUS] Please ensure the model file is in: backend/app/models/")
        sys.exit(1)
    return str(model_path)


def list_network_interfaces():
    """Print all available Scapy/Npcap network interfaces."""
    try:
        from scapy.all import get_if_list, get_if_addr
        print()
        print("=" * 70)
        print("AVAILABLE NETWORK INTERFACES")
        print("=" * 70)
        interfaces = get_if_list()
        if not interfaces:
            print("  No interfaces found. Is Npcap installed?")
        for iface in interfaces:
            try:
                addr = get_if_addr(iface)
            except Exception:
                addr = "unknown"
            print(f"  [{iface}]  IP: {addr}")
        print("=" * 70)
        print()
    except Exception as e:
        print(f"[ARGUS ERROR] Could not list interfaces: {e}")


def check_npcap():
    """Warn if Npcap is not installed (required for live capture on Windows)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        if not ifaces:
            raise RuntimeError("No Npcap interfaces")
        return True
    except Exception:
        print()
        print("WARNING: Npcap may not be installed or accessible.")
        print("    Live packet capture requires Npcap on Windows.")
        print("    Download from: https://npcap.com/#download")
        print()
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Runner functions
# ─────────────────────────────────────────────────────────────────────────────

def run_network_detection(interface=None):
    """Start the ARGUS network detection engine (blocking)."""
    from app.detection.network_detection_engine import NetworkDetectionEngine

    model_path = get_model_path()
    engine = NetworkDetectionEngine(model_path)
    engine.start(interface=interface)


def run_windows_detection(interval=5):
    """Start the ARGUS Windows detection engine (blocking)."""
    from app.detection.windows_detection_engine import WindowsDetectionEngine

    engine = WindowsDetectionEngine(
        failure_threshold=5,
        time_window_seconds=60
    )
    engine.start(interval_seconds=interval)


def run_unified(interface=None, windows_interval=5):
    """
    Run both network AND Windows detection concurrently in separate threads.
    """
    print()
    print("=" * 70)
    print("  ARGUS UNIFIED DETECTION SERVICE -- STARTING")
    print("=" * 70)
    print(f"  Network interface : {interface or 'auto-detect'}")
    print(f"  Windows interval  : {windows_interval}s")
    print("  Press Ctrl+C to stop all detectors.")
    print("=" * 70)
    print()

    stop_event = threading.Event()

    def network_thread():
        try:
            run_network_detection(interface=interface)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\n[ARGUS NETWORK ERROR] {e}")
        finally:
            stop_event.set()

    def windows_thread():
        try:
            run_windows_detection(interval=windows_interval)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\n[ARGUS WINDOWS ERROR] {e}")
        finally:
            stop_event.set()

    t_net = threading.Thread(target=network_thread, daemon=True, name="argus-network")
    t_win = threading.Thread(target=windows_thread, daemon=True, name="argus-windows")

    t_net.start()
    t_win.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print()
        print("[ARGUS] Shutdown signal received -- stopping all detectors...")

    stop_event.set()
    t_net.join(timeout=3)
    t_win.join(timeout=3)
    print("[ARGUS] All detectors stopped. Goodbye.")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ARGUS -- Adaptive Real-time Guard for Unified Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        "--mode",
        choices=["all", "network", "windows"],
        default="all",
        help="Detection mode: 'all' (default), 'network', or 'windows'"
    )

    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface for packet capture (e.g. 'Wi-Fi', 'Ethernet')"
    )

    parser.add_argument(
        "--windows-interval",
        type=int,
        default=5,
        help="How often (seconds) to poll Windows Security log (default: 5)"
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_network_interfaces()
        return

    print()
    print("=" * 70)
    print("   ARGUS -- Adaptive Real-time Guard for Unified Security")
    print("   Real-time Network + Windows Threat Detection")
    print("=" * 70)
    print()

    if args.mode == "network":
        check_npcap()
        run_network_detection(interface=args.interface)

    elif args.mode == "windows":
        run_windows_detection(interval=args.windows_interval)

    else:
        check_npcap()
        run_unified(
            interface=args.interface,
            windows_interval=args.windows_interval
        )


if __name__ == "__main__":
    main()
