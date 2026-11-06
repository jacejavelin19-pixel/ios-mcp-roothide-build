#!/usr/bin/env python3
"""Run on a host with direct access to the target's Unix socket (no TCP).

Example on device, with Python 3 installed:
  python3 smoke.py /path/to/container/tmp/.me_012345
The application must already be injected and foregrounded.
"""
import base64
import json
import socket
import sys


class RPC:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect(path)
        self.stream = self.sock.makefile("rb")
        self.next_id = 0

    def request(self, op, args=None, fail=False, fragmented=False):
        self.next_id += 1
        frame = json.dumps(dict(id=self.next_id, op="engine." + op,
                                args=args or {})).encode() + b"\n"
        if fragmented:
            for byte in frame:
                self.sock.sendall(bytes([byte]))
        else:
            self.sock.sendall(frame)
        reply = json.loads(self.stream.readline(1024 * 1024))
        assert reply["id"] == self.next_id, reply
        assert reply["ok"] is not fail, reply
        return reply.get("result", reply.get("error"))

    def close(self):
        self.stream.close()
        self.sock.close()


def run(path):
    rpc = RPC(path)
    hooks = []
    handles = set()
    try:
        ping = rpc.request("ping", fragmented=True)
        assert ping["arch"] in ("arm64", "arm64e") and ping["pid"] > 0
        rpc.request("unknown", fail=True)
        rpc.request("read_mem", {"address": "0x0", "length": 8}, fail=True)
        rpc.request("protect", {"address": "0x0", "length": 8, "prot": "rwx"}, fail=True)
        # Two requests in one write exercise coalesced NDJSON frames.
        rpc.sock.sendall(b'{"id":-1,"op":"engine.ping"}\n{"id":-2,"op":"engine.ping"}\n')
        assert json.loads(rpc.stream.readline())["id"] == -1
        assert json.loads(rpc.stream.readline())["id"] == -2
        classes = rpc.request("classes", {"filter": "MCPTestVault"})
        assert any(c["name"] == "MCPTestVault" for c in classes["classes"])
        desc = rpc.request("describe", {"class": "MCPTestVault"})
        assert any(m["sel"] == "verifyPinCode:" for m in desc["methods"])
        assert {"_secretToken", "_magicCounter"} <= {i["name"] for i in desc["ivars"]}
        target = rpc.request("invoke", {"target": "class:MCPTestVault", "selector": "sharedVault"})["ret"]
        handles.add(target["handle"])
        handle = "handle:" + str(target["handle"])

        def invoke(selector, args=None):
            return rpc.request("invoke", {"target": handle, "selector": selector, "args": args or []})["ret"]

        assert invoke("verifyPinCode:", [0]) == 0
        secret = rpc.request("get_ivar", {"handle": handle, "name": "_secretToken"})["value"]
        handles.add(secret["handle"])
        assert rpc.request("invoke", {"target": secret, "selector": "isEqualToString:",
                                      "args": ["MCP_VAULT_SECRET_129"]})["ret"]
        old_counter = rpc.request("get_ivar", {"handle": handle, "name": "_magicCounter"})["value"]
        try:
            rpc.request("set_ivar", {"handle": handle, "name": "_magicCounter", "value": 42})
            assert rpc.request("get_ivar", {"handle": handle, "name": "_magicCounter"})["value"] == 42
        finally:
            rpc.request("set_ivar", {"handle": handle, "name": "_magicCounter", "value": old_counter})

        hook = rpc.request("hook_objc", {"class": "MCPTestVault", "selector": "- verifyPinCode:",
                                        "override_return": 1, "max_events": 2})["hook_key"]
        hooks.append(hook)
        assert invoke("verifyPinCode:", [0]) == 1
        assert invoke("verifyPinCode:", [7]) == 1
        events = rpc.request("hook_events", {"hook_key": hook})
        assert events["count"] == 2 and events["events"][-1]["args"] == [7], events
        rpc.request("unhook", {"hook_key": hook})
        hooks.remove(hook)
        assert invoke("verifyPinCode:", [0]) == 0

        address = hex(invoke("engineScratchAddress"))
        old = rpc.request("read_mem", {"address": address, "length": 64})["data_base64"]
        marker = b"MCPTest engine round trip\0"
        try:
            rpc.request("write_mem", {"address": address, "data_base64": base64.b64encode(marker).decode()})
            data = rpc.request("read_mem", {"address": address, "length": len(marker)})
            assert base64.b64decode(data["data_base64"]) == marker
        finally:
            rpc.request("write_mem", {"address": address, "data_base64": old})
        found = rpc.request("search_mem", {"text": "MCPTest", "module": "MCPTestTarget", "limit": 8})
        assert found["count"] > 0, found
        assert int(rpc.request("call", {"symbol": "getpid"})["ret"], 16) == ping["pid"]

        hook = rpc.request("hook_native", {"symbol": "open", "record": True})["hook_key"]
        hooks.append(hook)
        invoke("runEngineProbe")
        events = rpc.request("hook_events", {"hook_key": hook})
        assert events["count"] > 0 and events["events"], events
        rpc.request("unhook", {"hook_key": hook})
        hooks.remove(hook)
        count = rpc.request("hook_events", {"hook_key": hook})["count"]
        invoke("runEngineProbe")
        assert rpc.request("hook_events", {"hook_key": hook})["count"] == count
        print(json.dumps({"passed": True, "pid": ping["pid"], "arch": ping["arch"],
                          "checks": "framing, errors, introspection, handles, ivars, hooks, memory, native call"}))
    finally:
        for hook in hooks:
            rpc.request("unhook", {"hook_key": hook})
        for handle in handles:
            rpc.request("release", {"handle": handle})
        rpc.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke.py UNIX_SOCKET_PATH")
    run(sys.argv[1])
