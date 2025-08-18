import subprocess
# send the request one by one (i.e., single)
def run_single_request(q_depth,total_request):
    command = f"./test_single_request {q_depth} {total_request}"
    args = command.split()
    subprocess.run(args=args,check=True)

q_depths = [2**i for i in range(13)]


def test_request_equal_qdepth():
    pass
    