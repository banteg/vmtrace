import json
from collections import Counter, defaultdict
from contextlib import contextmanager
from itertools import count, zip_longest
from time import perf_counter

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


def fetch_trace_data(tx) -> bytes:
    resp = requests.post(
        chain.provider.uri,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "trace_replayTransaction",
            "params": [tx, ["vmTrace"]],
        },
    )
    return resp.content


@app.command()
def trace(tx: str, verbose: bool = False, address: str = None):
    with timed("total"):
        with timed("fetch"):
            resp = fetch_trace_data(tx)
            print(f"[yellow]trace size: {naturalsize(len(resp))}")

        with timed("decode"):
            trace = vmtrace.from_rpc_response(resp)

        with timed("replay"):
            peak_mem = defaultdict(int)
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

    print("[bold magenta]peak memory allocated")
    print(dict(Counter(peak_mem).most_common()))


@app.command("compare")
def compare_methods(tx: str, verbose: bool = True, address: str = None):
    # fetch a geth trace and compare with what we calculate from vmtrace
    # exit at the first non-matching frame
    # use `cast run --debug <tx>` for a similarly styled interactive debugger
    with timed("fetch vmtrace"):
        vmtrace_frames = vmtrace.to_trace_frames(
            vmtrace.from_rpc_response(fetch_trace_data(tx)),
            address=address,
        )
    # with timed("fetch geth"):
    # consume the full iterator to measure how long it takes
    peak_mem = defaultdict(int)
    reference_frames = chain.provider.get_transaction_trace(tx)
    i = 0

    for i, (a, b) in tqdm(enumerate(zip(vmtrace_frames, reference_frames))):
        if (a.op, a.pc, a.depth) != (b.op, b.pc, b.depth):
            print(f"[bold red]a: pc={a.pc} op={a.op} depth={a.depth}")
            print(f"[bold red]b: pc={b.pc} op={b.op} depth={b.depth}")
            raise ValueError("traced unaligned")

        peak_mem[a.address] = max(peak_mem[a.address], len(a.memory))

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

    print("[bold magenta]peak memory allocated")
    print(dict(Counter(peak_mem).most_common()))


@app.command()
def fuzz(compare: bool = True, blocks: int = 100, min_gas_limit: int = 1_000_000):
    c = count(1)
    f = open("compare-failed.txt", "at")
    height = chain.blocks.height
    for number in range(height - blocks, height):
        block = chain.blocks[number]
        print(f"[bold yellow]{block.number}")
        for tx in block.transactions:
            if tx.gas_limit < min_gas_limit:
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
def block_fuzz():
    for number in range(chain.blocks.height, 0, -1):
        print(number)
        with timed("[red]total"):
            with timed("fetch"):
                resp = requests.post(
                    chain.provider.uri,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "trace_replayBlockTransactions",
                        "params": [hex(number), ["vmTrace"]],
                    },
                )
                print(f"[green]response size={naturalsize(len(resp.content))}")

            with timed("decode"):
                vmtraces = vmtrace.from_rpc_response(resp.content, is_list=True)
                print(f"[green]found traces={len(vmtraces)}")

            with timed("replay"):
                t0 = perf_counter()
                frames = 0
                for trace in vmtraces:
                    for frame in vmtrace.to_trace_frames(trace, copy_memory=False):
                        frames += 1
                print(
                    f"[green]replay speed={frames / (perf_counter() - t0):,.2f} frames/s"
                )


@app.command()
def save(tx: str):
    data = fetch_trace_data(tx)
    with open(f"vmtrace-{tx}.json", "wt") as f:
        f.write(json.dumps(json.loads(data)["result"]["vmTrace"], indent=2))


if __name__ == "__main__":
    with networks.ethereum.mainnet.use_default_provider():
        app()
