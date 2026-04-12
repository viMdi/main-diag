#!/usr/bin/python3
import sys
import pexpect
import re
import time
import os
from dotenv import load_dotenv

load_dotenv()

from database.client import DatabaseClient
from telnet.client import DLinkTelnetClient


class CableDiagClient(DLinkTelnetClient):
    def connect_no_paging(self):
        try:
            print(f"  Connected to {self.host}...\n")

            self.session = pexpect.spawn(f"telnet {self.host}", timeout=10)
            self.session.expect(r"User[Nn]ame:")
            self.session.sendline(self.username)
            self.session.expect(r"[Pp]ass[Ww]ord")
            self.session.sendline(self.password)
            self.session.expect(["5#", "admin#", "#", ">", "Switch#"], timeout=10)

            self.connected = True
            return True
        except Exception as e:
            print(f"  Connection failed: {e}")
            return False

    def cable_diagnostic_only(self, port):
        """Только диагностика кабеля"""
        try:
            self.session.sendline("")
            self.session.expect(["5#", "admin#", "#", "Switch#"], timeout=5)

            prompt = self.session.before.decode("utf-8", errors="ignore")

            if "DGS-1210" in prompt or "1210" in prompt:
                cmd = f"cable diagnostic port {port}"
            else:
                cmd = f"cable_diag ports {port}"

            self.session.sendline(cmd)
            time.sleep(2)
            self.session.sendline("")
            self.session.expect(["5#", "admin#", "#"], timeout=5)
            output = self.session.before.decode("utf-8", errors="ignore")


            match = re.search(
                r"Link (?:Up|Down)\s+([^\n]+(?:\s+Pair\s?\d+.?(?:OK|OPEN|SHORT|CROSSTALK|SHUTDOWN)(?:\s+at\s+\d+\s+M)?[^\n]*)*)",
                output,
                re.DOTALL | re.IGNORECASE,
            )

            if match:
                result = match.group(1)
                result = re.sub(r"\s+", " ", result)
                print(f"  CABLE DIAG: {result}")
            else:
                print("  CABLE DIAG: no result\n")

        except Exception as e:
            print(f"  Error: {e}\n")


def main():
    db = DatabaseClient()
    if not db.connect():
        print("Database connection error")
        sys.exit(1)

    print("Cable Diagnostic Tool")

    try:
        while True:
            search = input("\nuser number: ").strip()

            if search.lower() in ["exit", "quit", "q"]:
                print("Exit")
                break

            users = db.get_user_by_number(search)
            if not users:
                print("User not found")
                continue

            user = users[0]

            print(f"\n  SWITCH: {user['switch']}")
            print(f"  PORT:   {user['port']}")

            confirm = input("\n  Run cable diagnostic? (y/n): ").strip().lower()
            if confirm not in ["y", "yes"]:
                continue

            switch = CableDiagClient(user["switch"])
            if switch.connect_no_paging():
                switch.cable_diagnostic_only(user["port"])
                switch.disconnect()
            else:
                print("Connection failed\n")

    except KeyboardInterrupt:
        print("\nExit")
    finally:
        db.close()


if __name__ == "__main__":
    main()
