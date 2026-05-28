#!/usr/bin/env python3
"""
BGP configuration loader for router devices.
Loads topology from a JSON config and pushes BGP configurations via PtyExecutor.
"""

import json
import argparse
import concurrent.futures
import logging
import os
import sys

# Import PtyExecutor from pty_control
from pty_control import PtyExecutor


def eth_to_port(eth_name: str) -> str:
    """
    将eth接口名转换为端口格式。
    例如：'eth0' -> '0/7/-5'，'eth10' -> '0/7/5'
    """
    i = int(eth_name[3:])  # 提取eth后面的数字
    assert i >= 5 and i <= 14
    return f"0/7/{i-5}"


def init_device(config_entry: dict, program_path: str, password: str, base_working_dir: str) -> bool:
    """
    Initialize a single device with given config entry.

    Args:
        config_entry: Router config entry from topology JSON (must contain "local_idx")
        program_path: Path to the switch CLI program
        password: Login password for the switch
        base_working_dir: Base directory for device working directories

    Returns:
        True if initialization succeeded, False otherwise
    """

    device_name = f"ne8000-{config_entry['local_idx']}"
    working_dir = os.path.join(base_working_dir, device_name, "TOR")

    try:
        # Initialize PtyExecutor
        executor = PtyExecutor(
            program_path=program_path,
            password=password,
            working_dir=working_dir
        )

        # Test with a simple command to verify connection
        # Note: The execute_command method may require specific prompts.
        # For now, just creating the executor is enough to verify login.
        # We'll close it immediately as we're just testing initialization.
        # TODO: add executor.execute_command()

        asn = config_entry["asn"]
        router_id = config_entry["router_id"]
        cmds = ["sys"]
        assert len(config_entry["links"]) == len(config_entry["peers"])

        for link, peer in zip(config_entry["links"], config_entry["peers"]):
            interface_name = peer["self_interface"]
            ip = link["self_ip"]
            port = eth_to_port(interface_name)

            interface_ip_setup_cmds = [
                f"interface {port}", f"ip address {ip} 30", "quit", "commit"]
            cmds.extend(interface_ip_setup_cmds)
        bgp_cmds = [f"bgp {asn}", f"router-id {router_id}",
                    "ipv4-family unicast"]
        for link in config_entry["links"]:
            peer_ip = link["neighbor_ip"]
            remote_as = link["remote_as"]
            bgp_cmds.extend(
                [f"peer {peer_ip} as-number {remote_as}", f"peer {peer_ip} enable"])

        cmds.extend(bgp_cmds)
        results = []
        for cmd in cmds:
            result = executor.execute_command(cmd)
            results.append(result)

        executor.close()

        logging.info(f"Successfully initialized device {device_name}")
        return True

    except Exception as e:
        logging.error(f"Failed to initialize device {device_name}: {e}")
        return False


def init_devices_parallel(configs: dict, program_path: str, password: str,
                          base_working_dir: str, max_workers: int = None) -> dict:
    """
    Initialize multiple devices in parallel from topology config.

    Args:
        configs: Topology config dict containing "routers" list
        program_path: Path to the switch CLI program
        password: Login password for the switch
        base_working_dir: Base directory for device working directories
        max_workers: Maximum number of parallel workers (default: number of devices or CPU count)

    Returns:
        Dictionary mapping device index to initialization result (True/False)
    """
    routers = configs.get("routers", [])
    if not routers:
        logging.error("No routers found in config")
        return {}

    if max_workers is None:
        max_workers = min(len(routers), os.cpu_count() or 4)

    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {
            executor.submit(init_device, entry, program_path, password, base_working_dir): idx
            for idx, entry in enumerate(routers)
        }

        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                result = future.result()
                results[idx] = result
                if result:
                    logging.info(
                        f"Device {idx} initialization completed successfully")
                else:
                    logging.error(f"Device {idx} initialization failed")
            except Exception as e:
                logging.error(
                    f"Unexpected error during initialization of device {idx}: {e}")
                results[idx] = False

    return results


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="BGP configuration loader for router devices"
    )

    parser.add_argument(
        "--program", "-p",
        default="/usr/local/bin/time_client",
        help="Path to switch CLI program (default: /usr/local/bin/time_client)"
    )

    parser.add_argument(
        "--password", "-P",
        default="huawei123",
        help="Login password for the switch (default: huawei123)"
    )

    parser.add_argument(
        "--base-dir", "-d",
        default="/root/workspace/containers",
        help="Base directory for device working directories (default: /root/workspace/containers)"
    )

    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Maximum number of parallel workers (default: number of devices or CPU count)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-error output"
    )

    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to router topology JSON configuration file"
    )

    args = parser.parse_args()
    if not os.path.exists(args.config):
        print(f"Error: {args.config} does not exist")
        sys.exit(1)

    # Setup logging
    if args.quiet:
        logging.basicConfig(level=logging.WARNING,
                            format="%(levelname)s: %(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s - %(levelname)s - %(message)s")
    else:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s")

    logging.info(f"Program: {args.program}")
    logging.info(f"Base directory: {args.base_dir}")
    logging.info(f"Max workers: {args.workers if args.workers else 'auto'}")

    with open(args.config, "r") as f:
        configs = json.load(f)

    # Initialize devices in parallel
    results = init_devices_parallel(
        configs=configs,
        program_path=args.program,
        password=args.password,
        base_working_dir=args.base_dir,
        max_workers=args.workers
    )

    # Summary
    success_count = sum(1 for result in results.values() if result)
    failure_count = len(results) - success_count

    print(f"\n{'='*60}")
    print(f"Initialization Summary")
    print(f"{'='*60}")
    print(f"Total devices: {len(results)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {failure_count}")

    if failure_count > 0:
        failed_indices = [idx for idx,
                          success in results.items() if not success]
        print(f"Failed devices: {failed_indices}")
        sys.exit(1)
    else:
        print("All devices initialized successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()