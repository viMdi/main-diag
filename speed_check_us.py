#!/usr/bin/python3
import sys
import pexpect
import re
import time
from MAIN_DIAGA import DatabaseClient, DLinkTelnetClient
import cfg


class InteractiveDLink(DLinkTelnetClient):
    def connect_interactive(self):
        """подключение без отключения clipaging"""
        try:
            self.session = pexpect.spawn(f"telnet {self.host}", timeout=2)
            self.session.expect(r"User[Nn]ame:")
            self.session.sendline(self.username)
            self.session.expect(r"[Pp]ass[Ww]ord")
            self.session.sendline(self.password)
            self.session.expect(["5#", "admin#", "#", ">", "Switch#"], timeout=2)
            self.connected = True
            return True
        except:
            return False


def monitor_packets_live(switch, port):
    """мониторинг пакетов в реальном времени"""
    switch.session.sendline(f"show packet ports {port}")
    time.sleep(1)

    try:
        while True:
            time.sleep(2)
            try:
                data = switch.session.read_nonblocking(size=10000, timeout=1).decode(
                    errors="ignore"
                )
                matches = re.findall(
                    r"(?:RX|TX) Bytes.*?\d+\s+(\d+)", data, re.IGNORECASE
                )
                rx_bytes = int(matches[0]) if matches else 0
                tx_bytes = int(matches[1]) if len(matches) > 1 else 0

                rx_mbps = round(rx_bytes * 8 / 1000000, 1)
                tx_mbps = round(tx_bytes * 8 / 1000000, 1)

                print(
                    f"\rRX: {rx_bytes} bytes ({rx_mbps} Mbs) | TX: {tx_bytes} bytes ({tx_mbps} Mbs)   ",
                    end="",
                    flush=True,
                )
            except:
                continue
    except KeyboardInterrupt:
        print("\n")
        switch.session.sendcontrol("c")
        time.sleep(0.5)
        switch.session.sendline("")
        return


def main():
    db = DatabaseClient(cfg.DB_CONFIG)
    if not db.connect():
        print("Error DB")
        sys.exit(1)

    try:
        while True:
            search = input("\nUs_num: ").strip()

            if search.lower() in ["exit", "quit", "q", "выход"]:
                break

            users = db.get_user_by_number(search)
            if not users:
                print("Not found")
                continue

            user = users[0]
            switch = InteractiveDLink(user["switch"])
            if switch.connect_interactive():
                monitor_packets_live(switch, user["port"])
            else:
                print("Error connect")

    except KeyboardInterrupt:
        print("\n")
    finally:
        db.close()


if __name__ == "__main__":
    main()
