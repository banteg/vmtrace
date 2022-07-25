import json
from collections import Counter, defaultdict
from contextlib import contextmanager
from functools import wraps
from itertools import count, zip_longest
from time import perf_counter
from typing import Dict, List

import distributed
import requests
from ape import chain, networks
from evm_trace import vmtrace
from hexbytes import HexBytes
from humanize import naturalsize
from msgspec import DecodeError
from rich import print
from tqdm import tqdm
from typer import Typer

app = Typer(pretty_exceptions_show_locals=False)


@contextmanager
def timed(label):
    start = perf_counter()
    yield
    print(f"[yellow]{label} took [bold]{perf_counter() - start:.3f}s")


def mainnet(f):
    @wraps(f)
    def decorator(*args, **kwds):
        with networks.ethereum.mainnet.use_default_provider():
            return f(*args, **kwds)

    return decorator


class Measure:
    def __init__(self, label, total=1):
        self.label = label
        self.total = total

    def __enter__(self):
        self.start = perf_counter()
        return self

    @property
    def elapsed(self):
        return perf_counter() - self.start

    @property
    def rate(self):
        return self.total / self.elapsed

    def __exit__(self, *args):
        elapsed = perf_counter() - self.start
        print(
            f"[yellow]{self.label} {self.total:,d} took [bold]{elapsed:.3f}s ({self.rate:,.2f}/s)"
        )


def request_raw(method, params) -> bytes:
    with timed("fetch"):
        resp = requests.post(
            chain.provider.uri,  # type: ignore
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        )
    print(f"[yellow]size={naturalsize(len(resp.content))}")
    return resp.content


def trace_transaction(tx: str) -> vmtrace.VMTrace:
    buffer = request_raw("trace_replayTransaction", [tx, ["vmTrace"]])
    with timed("decode"):
        trace: vmtrace.VMTrace = vmtrace.from_rpc_response(buffer)
    return trace


def trace_block(height: int) -> List[vmtrace.VMTrace]:
    buffer = request_raw("trace_replayBlockTransactions", [hex(height), ["vmTrace"]])
    with timed("decode"):
        traces: List[vmtrace.VMTrace] = vmtrace.from_rpc_response(buffer)
    print(f"[green]found traces={len(traces)}")
    return traces


@app.command()
@mainnet
def trace(tx: str, verbose: bool = False, address: str = None):
    with timed("total"):
        trace = trace_transaction(tx)

        with timed("replay"):
            peak_mem: Dict[str, int] = defaultdict(int)
            i = 0
            t0 = perf_counter()
            for i, frame in enumerate(
                vmtrace.to_trace_frames(trace, address=address, copy_memory=False), 1
            ):
                peak_mem[frame.address] = max(
                    peak_mem[frame.address], len(frame.memory)
                )
                if verbose:
                    print(frame)
            t1 = perf_counter()

        print(f"[yellow]{i / (t1 - t0):,.2f} frames/s ({i:,d} frames)")

    print("peak memory allocated")
    print(dict(Counter(peak_mem).most_common()))


@app.command("compare")
@mainnet
def compare_methods(tx: str, verbose: bool = True, address: str = None):
    # fetch a geth trace and compare with what we calculate from vmtrace
    # exit at the first non-matching frame
    # use `cast run --debug <tx>` for a similarly styled interactive debugger
    vmtrace_frames = vmtrace.to_trace_frames(trace_transaction(tx), address=address)
    reference_frames = chain.provider.get_transaction_trace(tx)
    i = 0

    for i, (a, b) in tqdm(enumerate(zip(vmtrace_frames, reference_frames))):
        if (a.op, a.pc, a.depth) != (b.op, b.pc, b.depth):
            print(f"[bold red]a: pc={a.pc} op={a.op} depth={a.depth}")
            print(f"[bold red]b: pc={b.pc} op={b.op} depth={b.depth}")
            raise ValueError("traced unaligned")

        stack_a = a.stack
        stack_b = b.stack

        a_memory = a.memory
        b_memory = b"".join(b.memory)
        # geth sometimes add memory expansion out of nowhere
        while len(b_memory) > len(a_memory):
            if sum(b_memory[-32:]) == 0:
                b_memory = b_memory[:-32]

        failed = a.memory != b_memory or stack_a != stack_b

        if failed or verbose:
            if failed:
                print("[red]failed after op")
                # print(op)
                print("[yellow]memory")
                a_memory = [
                    HexBytes(a.memory[s : s + 32]) for s in range(0, len(a.memory), 32)
                ]
                for word, (mem_a, mem_b) in enumerate(zip_longest(a_memory, b.memory)):
                    color = "red" if mem_a != mem_b else "green"
                    mem_a = mem_a.hex() if mem_a is not None else f'[dim]{"-"*66}[/]'
                    mem_b = mem_b.hex() if mem_b is not None else f'[dim]{"-"*66}[/]'
                    print(f"{hex(word * 32)[2:]:>4}| [{color}]{mem_a} {mem_b}")

                print("[yellow]stack")
                for n, (s_a, s_b) in enumerate(
                    zip_longest(reversed(stack_a), reversed(stack_b))
                ):
                    color = "red" if s_a != s_b else "green"
                    s_a = (
                        s_a.rjust(32, b"\x00").hex()
                        if s_a is not None
                        else f"[dim]---[/]"
                    )
                    s_b = (
                        s_b.rjust(32, b"\x00").hex()
                        if s_b is not None
                        else f"[dim]---[/]"
                    )
                    print(f"{hex(n)[2:]:>4}| [{color}]{s_a} {s_b}")

            if failed:
                print(f"[bold red]failed after {i} steps")
                raise ValueError()

    print(f"[bold green]all good, compared {i} frames")


@app.command()
@mainnet
def fuzz(compare: bool = True, blocks: int = 100, min_gas_limit: int = 1_000_000):
    c = count(1)
    f = open("compare-failed.txt", "at")
    height = chain.blocks.height
    for number in range(height - blocks, height):
        block = chain.blocks[number]
        print(f"[bold yellow]{block.number}")
        for tx in block.transactions:
            if (tx.gas_limit or 0) < min_gas_limit:
                continue
            tx_hash = tx.txn_hash.hex()
            print(f"{next(c)}. {tx_hash}")
            if compare:
                with timed("compare"):
                    try:
                        compare_methods(tx_hash, verbose=True, address=tx.receiver)
                    except (ValueError, DecodeError) as e:
                        print(e)
                        f.write(json.dumps({"tx": tx_hash, "error": str(e)}) + "\n")
                        f.flush()
            else:
                trace(tx_hash, address=tx.receiver)

    f.close()


@app.command()
@mainnet
def block_fuzz():
    for height in range(chain.blocks.height, 0, -1):
        print(height)
        with timed("[red]total"):
            traces = trace_block(height)

            with Measure("replay") as measure:
                t0 = perf_counter()
                measure.total = 0
                for trace in traces:
                    for frame in vmtrace.to_trace_frames(trace, copy_memory=False):
                        measure.total += 1


class WorkerConnection(distributed.WorkerPlugin):
    def setup(self, worker):
        networks.ethereum.mainnet.use_default_provider().__enter__()




@app.command()
@mainnet
def bench(blocks: int = 10):
    t0 = perf_counter()
    f = open('bench.jsonl', 'wt')
    for height in range(chain.blocks.height - blocks, chain.blocks.height):
        print(height)
        frames = 0
        t1 = perf_counter()
        traces = trace_block(height)
        t2 = perf_counter()
        for trace in traces:
            for frame in vmtrace.to_trace_frames(trace, copy_memory=False):
                frames += 1
        t3 = perf_counter()

        res = {'block': height, 'frames': frames, 'traces': len(traces), 'fetch': t2 - t1, 'replay': t3 - t2}
        print(res)
        f.write(json.dumps(res) + '\n')
        f.flush()
    
    f.close()



@app.command()
def peak_memory(blocks: int = 10):
    """
    Measure peak memory usage fetching multiple blocks in parallel with dask.
    """
    cluster = distributed.LocalCluster(n_workers=16)
    client = distributed.Client(cluster)
    client.register_worker_plugin(WorkerConnection())
    print(client.dashboard_link)

    with open("peak-memory.jsonl", "wt") as f:
        with networks.ethereum.mainnet.use_default_provider():
            block_range = range(chain.blocks.height - blocks, chain.blocks.height)
        for future in tqdm(client.map(measure_block_memory, block_range), total=blocks):
            for result in future.result():
                f.write(json.dumps(result) + "\n")


def measure_block_memory(height):
    print(f"[green]processing block {height}")
    txs = [tx for tx in chain.blocks[height].transactions]
    traces = trace_block(height)
    results = []
    for tx, trace in zip(txs, traces):
        peak_mem: Dict[str, int] = defaultdict(int)
        for frame in vmtrace.to_trace_frames(
            trace, address=tx.receiver, copy_memory=False
        ):
            peak_mem[frame.address] = max(peak_mem[frame.address], len(frame.memory))
        if peak_mem:
            res = {
                "block_number": height,
                "tx": tx.txn_hash.hex(),
                "peak_mem": dict(Counter(peak_mem).most_common()),
            }
            results.append(res)
    return results


if __name__ == "__main__":
    app()
