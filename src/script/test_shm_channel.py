#! /usr/bin/env python
import subprocess
from itertools import product

# send the request one by one (i.e., single)


def run_single_request(q_depth, total_request):
    command = f"./test_single_request {q_depth} {total_request}"
    args = command.split()
    subprocess.run(args=args, check=True, capture_output=True)


def run_burst_request(q_depth, batch_size, num_requests):
    command = f"./test_burst_request {q_depth} {batch_size} {num_requests}"
    args = command.split()
    subprocess.run(args=args, check=True, capture_output=True)


q_depths = [2**i for i in range(13)]
batch_sizes = [2**i for i in range(7)]
# stress test
total_requests = [2**i for i in range(20)]


def test_single_request():
    print(
        f"single request test with {len(q_depths)*len(total_requests)} combinations")
    for q_depth, total_request in product(q_depths, total_requests):
        try:
            run_single_request(q_depth=q_depth, total_request=total_request)
        except Exception:
            print(
                f"[FAILED] test_single_request: q_depth={q_depth} total_request={total_request}")
            raise


def test_burst_request():
    print(
        f"burst request test with {len(q_depths)*len(total_requests)*len(batch_sizes)} combinations")
    for q_depth, total_request, bs in product(q_depths, total_requests, batch_sizes):
        try:
            run_burst_request(q_depth=q_depth, batch_size=bs,
                              num_requests=total_request)
        except Exception:
            print(
                f"[FAILED] test_burst_request: q_depth={q_depth} total_request={total_request} batch_size={bs}")
            raise


if __name__ == "__main__":
    test_burst_request()
    test_single_request()

    print('All tests passed')
