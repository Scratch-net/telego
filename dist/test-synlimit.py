#!/usr/bin/env python3
"""Exercise rule generation and removal without touching the host firewall."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "synlimit.sh"
MOCK = r'''
import json
import os
from pathlib import Path
import sys

path = Path(os.environ["SYN_TEST_STATE"])
state = json.loads(path.read_text())
family = Path(sys.argv[0]).name
args = sys.argv[1:]
state["calls"].append([family, args])
rules = state[family]
if args[0] == "-L":
    print("Chain DOCKER-USER (1 references)")
    for i, rule in enumerate(rules, 1):
        tag = rule[rule.index("--comment") + 1]
        print(f"{i} ACCEPT tcp -- any any /* {tag} */")
elif args[0] == "-D":
    del rules[int(args[2]) - 1]
elif args[0] == "-I":
    rules.insert(int(args[2]) - 1, args[3:])
else:
    raise SystemExit("unexpected mock invocation")
path.write_text(json.dumps(state))
'''


class SynlimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="telego-synlimit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for family in ("iptables", "ip6tables"):
            executable = self.root / family
            executable.write_text(f"#!{sys.executable}\n" + MOCK)
            executable.chmod(0o700)
        self.state = self.root / "state.json"
        rules = [["--comment", "telego-syn-4430"], ["--comment", "telego-syn-443"]]
        self.state.write_text(json.dumps({"calls": [], "iptables": rules, "ip6tables": rules}))
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        SYN_TEST_STATE=str(self.state))

    def run_script(self, port, action="apply"):
        return subprocess.run(["bash", str(SCRIPT), port, action, "eth-test"],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_published_port_and_exact_clear(self):
        result = self.run_script("443")
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state.read_text())
        for family in ("iptables", "ip6tables"):
            rules = state[family]
            self.assertEqual(len(rules), 5)
            self.assertEqual(rules[-1], ["--comment", "telego-syn-4430"])
            for rule in rules[:4]:
                self.assertNotIn("--dport", rule)
                self.assertEqual(rule[rule.index("--ctorigdstport") + 1], "443")
                self.assertEqual(rule[rule.index("--ctdir") + 1], "ORIGINAL")
                self.assertEqual(rule[rule.index("-i") + 1], "eth-test")
        result = self.run_script("443", "clear")
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.state.read_text())
        for family in ("iptables", "ip6tables"):
            self.assertEqual(state[family], [["--comment", "telego-syn-4430"]])

    def test_invalid_ports_do_not_modify_firewall(self):
        for port in ("0", "65536", "-1", "443x", "999999999999999999999"):
            with self.subTest(port=port):
                result = self.run_script(port)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("port must be", result.stderr)
        self.assertEqual(json.loads(self.state.read_text())["calls"], [])


if __name__ == "__main__":
    unittest.main()
