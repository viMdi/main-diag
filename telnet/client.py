import pexpect
import time
import re
import cfg

# Константы таймаутов (в секундах)
TIMEOUTS = {
    "PROMPT": 1,
    "COMMAND": 1,
    "LOG": 2,
    "ACCESS": 4,
    "CABLE": 1,
    "RECOVERY": 0.5,
}


class DLinkTelnetClient:
    """класс для работы со свитчом"""

    def __init__(self, host, disable_paging=True):
        self.host = host
        self.disable_paging = disable_paging
        self.username = cfg.SWITCH_USERNAME
        self.password = cfg.SWITCH_PASSWORD
        self.session = None
        self.connected = False
        self.gateway_ip = None

    def _ensure_prompt(self):
        """гарантирует, что мы в промпте перед командой"""
        try:
            self.session.sendline("")
            self.session.expect(
                ["5#", "admin#", "#", "Switch#"], timeout=TIMEOUTS["PROMPT"]
            )
            return True
        except:
            # пробуем восстановиться
            try:
                self.session.sendcontrol("c")
                time.sleep(TIMEOUTS["RECOVERY"])
                self.session.sendline("")
                self.session.expect(
                    ["5#", "admin#", "#", "Switch#"], timeout=TIMEOUTS["PROMPT"]
                )
                return True
            except:
                return False

    def connect(self, quiet=False):
        try:
            if not quiet:
                print(f"  Connect to {self.host}...")

            self.session = pexpect.spawn(f"telnet {self.host}", timeout=6)
            self.session.expect(r"User[Nn]ame:")
            self.session.sendline(self.username)
            self.session.expect(r"[Pp]ass[Ww]ord")
            self.session.sendline(self.password)
            self.session.expect(
                ["5#", "admin#", "#", ">", "Switch#"], timeout=TIMEOUTS["PROMPT"]
            )

            if self.disable_paging:
                self.session.sendline("disable clipaging")
                self.session.expect(
                    ["5#", "admin#", "#", "Switch#"], timeout=TIMEOUTS["PROMPT"]
                )

            if not quiet:
                print("  SUCCESSFUL")
            self.connected = True
            return True

        except Exception:
            if not quiet:
                print(f"  Свитч упал: {self.host}")
            return False

    def disconnect(self):
        """закрыть соединение или остаться в интерактивном"""
        if self.session and self.connected:
            try:
                self.session.sendline("enable clipaging")
                self.session.sendline("\r")
                self.session.expect(
                    ["5#", "admin#", "#", "Switch#"], timeout=TIMEOUTS["PROMPT"]
                )
                self.session.sendline("logout")
                self.session.sendline("exit")
                self.session.close()
                print("  ++COMPLETED++")
                print()
            except:
                pass
            self.connected = False

    def check_port_status(self, port):
        """проверка статуса порта (show ports)"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline(f"show ports {port}")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            data_port = self.session.before.decode("utf-8", errors="ignore")

            res = re.search(r"\b\d+[M]\S+|(Li\S+.\S+)", data_port)
            if res:
                print(f"  LINK STATUS: {res.group()}")
            else:
                print("  LINK STATUS: not defined")

        except Exception as e:
            print(f"  Ошибка при проверке порта: {e}")
            self._ensure_prompt()

    def check_mac_addresses(self, port):
        """проверка MAC-адресов на порту (show fdb port)"""
        try:
            if not self._ensure_prompt():
                return []

            self.session.sendline(f"show fdb port {port}")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            data_fdb = self.session.before.decode("utf-8", errors="ignore")

            res_mac = re.findall(
                r"^\s*\d+\s+\S+\s+((?:[A-F0-9]{2}[-]){5}[A-F0-9]{2})",
                data_fdb,
                re.MULTILINE | re.IGNORECASE,
            )

            if res_mac:
                mac_list = [mac.upper() for mac in res_mac]
                total = len(mac_list)

                type_match = re.search(r"(Dynamic|Permanent)", data_fdb, re.IGNORECASE)
                mac_type = type_match.group(1) if type_match else "no result"

                if total > 4:
                    first_four = mac_list[:4]
                    print(f"  MAC: {', '.join(first_four)} (+{total - 4})")
                else:
                    print(f"  MAC: {', '.join(mac_list)}")

                print(f"  PORT_SECURITY: {mac_type}")
                return mac_list
            else:
                print("  MAC: not found")
                return []
        except Exception as e:
            print(f"  Ошибка при поиске MAC-адресов: {e}")
            self._ensure_prompt()
            return []

    def check_dhcp_relay(self):
        """проверка dhcp_relay на enable/disable (show dhcp_relay)"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline("show dhcp_relay")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            dhcp_relay = self.session.before.decode("utf-8", errors="ignore")

            res_dhcp = re.search(r"R\S+\s\S+\s+[:].(\S+)", dhcp_relay)
            if res_dhcp:
                print(f"  DHCP_RELAY: {res_dhcp.group(1)}")
            else:
                print("  DHCP_RELAY: not defined")

        except Exception as e:
            print(f"  Ошибка при проверке dhcp: {e}")
            self._ensure_prompt()

    def check_gateway_l3(self):
        """ищем ип шлюза на л2"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline("show switch")
            time.sleep(0.3)
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            res_gateway = self.session.before.decode("utf-8", errors="ignore")

            res_def_gate = re.search(
                r"Default Gateway\s*:\s*(\S+)", res_gateway, re.IGNORECASE
            )
            if res_def_gate:
                self.gateway_ip = res_def_gate.group(1)
                print(f"  DEF_GATEWEY: {res_def_gate.group(1)}")
            else:
                print("  DEF_GATEWAY: not defined")

        except Exception as e:
            print(f"  Ошибка при проверке default_gateway: {e}")
            self._ensure_prompt()

    def check_arp_on_gateway(self, user_ip, mac_from_l2):
        """подключение к L3 свитчу и проверка ARP записи"""
        if not self.gateway_ip:
            return

        try:
            gw = DLinkTelnetClient(self.gateway_ip, disable_paging=False)

            if gw.connect(quiet=True):
                arp_data = ""

                gw.session.sendline(f"show arpentry ipaddress {user_ip}")
                time.sleep(0.3)
                gw.session.expect(
                    ["5#", "admin#", "Switch#", "#"], timeout=TIMEOUTS["COMMAND"]
                )
                arp_data = gw.session.before.decode("utf-8", errors="ignore")

                if "Invalid" in arp_data or "^" in arp_data or not arp_data.strip():
                    gw.session.sendline(f"sh arp {user_ip}")
                    time.sleep(0.3)
                    gw.session.expect(
                        ["5#", "admin#", "Switch#", "#"], timeout=TIMEOUTS["COMMAND"]
                    )
                    arp_data = gw.session.before.decode("utf-8", errors="ignore")

                arp_mac = None
                ip_found = False

                for line in arp_data.split("\n"):
                    if (
                        "show arpentry" in line
                        or "sh arp" in line
                        or "Command:" in line
                    ):
                        continue
                    if user_ip in line:
                        ip_found = True
                        mac_match = re.search(
                            r"((?:[A-F0-9]{2}[-]){5}[A-F0-9]{2})", line, re.IGNORECASE
                        )
                        if mac_match:
                            arp_mac = mac_match.group(1).upper()
                            break

                if not ip_found and not arp_mac:
                    gw.session.sendline(f"show iproute {user_ip}")
                    time.sleep(0.3)
                    gw.session.expect(
                        ["5#", "admin#", "Switch#", "#"], timeout=TIMEOUTS["COMMAND"]
                    )
                    route_data = gw.session.before.decode("utf-8", errors="ignore")

                    gateway_match = re.search(
                        r"\d+\.\d+\.\d+\.\d+/\d+\s+(\d+\.\d+\.\d+\.\d+)", route_data
                    )

                    if gateway_match:
                        new_gateway = gateway_match.group(1)
                        print(
                            f"  ARP: gateway found {new_gateway}, trying to connect..."
                        )

                        try:
                            gw.session.sendline("logout")
                            gw.session.close()
                        except:
                            pass

                        new_gw = DLinkTelnetClient(new_gateway, disable_paging=False)

                        if new_gw.connect(quiet=True):
                            new_gw.session.sendline(
                                f"show arpentry ipaddress {user_ip}"
                            )
                            time.sleep(0.3)
                            new_gw.session.expect(
                                ["5#", "admin#", "Switch#", "#"],
                                timeout=TIMEOUTS["COMMAND"],
                            )
                            new_arp_data = new_gw.session.before.decode(
                                "utf-8", errors="ignore"
                            )

                            if (
                                "Invalid" in new_arp_data
                                or "^" in new_arp_data
                                or not new_arp_data.strip()
                            ):
                                new_gw.session.sendline(f"sh arp {user_ip}")
                                time.sleep(0.3)
                                new_gw.session.expect(
                                    ["5#", "admin#", "Switch#", "#"],
                                    timeout=TIMEOUTS["COMMAND"],
                                )
                                new_arp_data = new_gw.session.before.decode(
                                    "utf-8", errors="ignore"
                                )

                            new_arp_mac = None
                            new_ip_found = False

                            for line in new_arp_data.split("\n"):
                                if (
                                    "show arpentry" in line
                                    or "sh arp" in line
                                    or "Command:" in line
                                ):
                                    continue
                                if user_ip in line:
                                    new_ip_found = True
                                    mac_match = re.search(
                                        r"((?:[A-F0-9]{2}[-]){5}[A-F0-9]{2})",
                                        line,
                                        re.IGNORECASE,
                                    )
                                    if mac_match:
                                        new_arp_mac = mac_match.group(1).upper()
                                        break

                            if not mac_from_l2:
                                print("  ARP: no result (no MAC on L2)")
                            elif not new_ip_found:
                                print(
                                    "  ARP: no result (IP not found on secondary gateway)"
                                )
                            elif (
                                new_arp_mac
                                and new_arp_mac in mac_from_l2
                                and new_ip_found
                            ):
                                print(
                                    "  ARP: OK (IP and MAC match) - found on secondary gateway"
                                )
                            elif new_arp_mac:
                                print(
                                    f"  ARP: NOT MATCH (L2: {', '.join(mac_from_l2)} | L3: {new_arp_mac}) - on secondary gateway"
                                )
                            else:
                                print(
                                    "  ARP: no result (arpentry not found) - on secondary gateway"
                                )

                            try:
                                new_gw.session.sendline("logout")
                                new_gw.session.close()
                            except:
                                pass

                            return
                        else:
                            print(
                                f"  ARP: failed to connect to the gateway {new_gateway}"
                            )
                    else:
                        print("  ARP: route not found")

                elif not mac_from_l2:
                    print("  ARP: no result (no MAC on L2)")
                elif not ip_found:
                    print("  ARP: no result (IP not found on L3)")
                elif len(mac_from_l2) > 5:
                    print(
                        f"  ARP: {arp_mac if arp_mac else 'MAC not found'} (on port {len(mac_from_l2)} MAC-address, check the port manually)"
                    )
                elif arp_mac and arp_mac in mac_from_l2 and ip_found:
                    print("  ARP: OK (IP and MAC match)")
                elif arp_mac:
                    print(
                        f"  ARP: NOT MATCH (L2: {', '.join(mac_from_l2)} | L3: {arp_mac})"
                    )
                else:
                    print("  ARP: no result (arpentry not found)")

                try:
                    gw.session.sendline("logout")
                    gw.session.close()
                except:
                    pass

        except Exception:
            pass

    def check_utilization_cpu(self):
        """проверка загрузки цп свитча)"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline("show utilization cpu")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            utilization_cpu = self.session.before.decode("utf-8", errors="ignore")

            res_util_cpu = re.search(r"Five.*?(\d+\s*%)", utilization_cpu)
            if res_util_cpu:
                print(f"  UTIL_CPU: {res_util_cpu.group(1)}")
            else:
                print("  UTIL_CPU: not defined")

        except Exception as e:
            print(f"  Ошибка при проверке utilization_cpu: {e}")
            self._ensure_prompt()

    def check_errors_port(self, port):
        """проверка ошибок на порту (show error ports)"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline(f"show error ports {port}")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            error_ports = self.session.before.decode("utf-8", errors="ignore")

            res_error_ports = re.search(r"CRC Error\s+(\d+)", error_ports)
            if res_error_ports:
                print(f"  ERRORS PORT: {res_error_ports.group(1)}")
            else:
                print("  ERRORS PORT: not defined")
        except Exception as e:
            print(f"  Ошибка при проверке error: {e}")
            self._ensure_prompt()

    def check_len_log(self, port):
        """проверка на кол-во падения линка в логах"""
        try:
            self.session.sendline("enable clipaging")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["PROMPT"])

            if not self._ensure_prompt():
                return

            self.session.sendline("show log")
            self.session.sendline("n")
            time.sleep(TIMEOUTS["LOG"])

            try:
                output = self.session.read_nonblocking(
                    size=10000, timeout=TIMEOUTS["LOG"]
                ).decode(errors="ignore")
            except:
                output = ""

            self.session.send("q")
            time.sleep(TIMEOUTS["RECOVERY"])
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])

            self.session.sendline("disable clipaging")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["PROMPT"])

            pattern = r"Port\s+\d+(?::\d+)?"
            res_log = re.findall(pattern, output, re.IGNORECASE)

            if res_log:
                count = len(res_log)
                print(f"  LOGS: port {port} found {count} times")
            else:
                print(f"  LOGS: port {port} not found in logs")

        except Exception as e:
            print(f"  Ошибка при проверке show log: {e}")
            self._ensure_prompt()

    def check_packet_port(self, port):
        """проверка трафика на порту (show packer ports)"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline(f"show packet ports {port}")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            packet_ports = self.session.before.decode("utf-8", errors="ignore")

            matches = re.findall(
                r"(?:RX|TX) Bytes.*?\d+\s+(\d+)", packet_ports, re.IGNORECASE
            )
            rx_bytes = int(matches[0]) if len(matches) > 0 else 0
            tx_bytes = int(matches[1]) if len(matches) > 1 else 0

            rx_mbps = round(rx_bytes * 8 / 1000000, 1)
            tx_mbps = round(tx_bytes * 8 / 1000000, 1)

            print(
                f"  PACKETS PORT: RX {rx_bytes} bytes ({rx_mbps} Mbs) | TX {tx_bytes} bytes ({tx_mbps} Mbs)"
            )

        except Exception as e:
            print(f"  Ошибка при проверке packets: {e}")
            self._ensure_prompt()

    def check_cable_diagnostic(self, port):
        """проверка диагностики кабеля (cable diagnostic port / cable_diag ports)"""
        try:
            if not self._ensure_prompt():
                return

            prompt = self.session.before.decode("utf-8", errors="ignore")

            if "DGS-1210" in prompt or "1210" in prompt:
                cmd = f"cable diagnostic port {port}"
            else:
                cmd = f"cable_diag ports {port}"

            self.session.sendline(cmd)
            time.sleep(TIMEOUTS["CABLE"])
            self.session.sendline("")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            cab_diag = self.session.before.decode("utf-8", errors="ignore")

            cab_diag_port = re.search(
                r"Link (?:Up|Down)\s+([^\n]+(?:\s+Pair\s?\d+.?(?:OK|OPEN|SHORT|CROSSTALK)(?:\s+at\s+\d+\s+M)?[^\n]*)*)",
                cab_diag,
                re.DOTALL | re.IGNORECASE,
            )

            if cab_diag_port:
                result = cab_diag_port.group(1)
                result = re.sub(r"\s+", " ", result)
                print(f"  CABLE DIAG: {result}")
            else:
                print("  CABLE DIAG: no result")

        except Exception as e:
            print(f"  Ошибка при диагностике кабеля: {e}")
            self._ensure_prompt()

    def check_vlan_on_port(self, port):
        """проверка VLAN на порту (show vlan ports)"""
        try:
            if not self._ensure_prompt():
                return

            self.session.sendline(f"show vlan ports {port}")
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            data_vlan = self.session.before.decode("utf-8", errors="ignore")

            vlan_matches = re.findall(
                r"^\s*(\d+)\s+([X-])\s+([X-])", data_vlan, re.MULTILINE
            )

            if not vlan_matches:
                vlan_matches = re.findall(
                    r"^\s*\d+(?::\d+)?\s+(\d+)\s+([X-])\s+([X-])",
                    data_vlan,
                    re.MULTILINE,
                )

            if vlan_matches:
                for vlan_id, untagged_col, tagged_col in vlan_matches:
                    if untagged_col == "X" and tagged_col == "-":
                        print(f"  VLAN {vlan_id}: Untagged")
                    elif untagged_col == "-" and tagged_col == "X":
                        print(f"  VLAN {vlan_id}: Tagged")
                    elif untagged_col == "X" and tagged_col == "X":
                        print(f"  VLAN {vlan_id}: Both (Untagged & Tagged)")
                    else:
                        print(f"  VLAN {vlan_id}: Не участвует")
            else:
                print("  VLAN: no result")

        except Exception as e:
            print(f"  Ошибка при проверке VLAN: {e}")
            self._ensure_prompt()

    def check_access_profile(self, port):
        """проверка access profile на порту"""
        try:
            # получаем промпт для определения модели
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["PROMPT"])
            prompt = self.session.before.decode("utf-8", errors="ignore")

            # отправляем команду show access_profile
            self.session.sendline("show access_profile")
            time.sleep(TIMEOUTS["ACCESS"])

            try:
                self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["ACCESS"])
            except Exception:
                self.session.sendcontrol("c")
                time.sleep(TIMEOUTS["RECOVERY"])
                self.session.sendline("")
                self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["PROMPT"])

            output = self.session.before.decode("utf-8", errors="ignore")

            payload = None
            source_mac = None

            if "DES-3028" in prompt:
                pattern1 = rf"Access ID : \d+ \n\rPorts\t  : {port}.*?\n\r +26 +0x([0-9A-F]+) 0xffffffff"
                pattern2 = rf"Access ID : \d+ \n\rPorts\t  : {port}.*?\n\r +28 +0x([0-9A-F]+) 0xffffffff"

                match = re.search(pattern1, output, re.DOTALL | re.IGNORECASE)
                if not match:
                    match = re.search(pattern2, output, re.DOTALL | re.IGNORECASE)

                if match:
                    payload = match.group(1)

                mac_pattern = rf"Ports\t  : {port}.*?Source MAC\s*\n\r-----------------\s*\n\r((?:[0-9A-F]{{2}}[-]){{5}}[0-9A-F]{{2}})"
                mac_match = re.search(mac_pattern, output, re.DOTALL | re.IGNORECASE)
                if mac_match:
                    source_mac = mac_match.group(1)

            elif "DGS-3000" in prompt:
                pattern = rf"Rule ID.*?Ports:\s*{port}.*?(?:offset_chunk.*?value\s*:\s*(0x[0-9A-F]+).*?){{1,2}}"
                matches = re.findall(pattern, output, re.DOTALL | re.IGNORECASE)
                if matches:
                    payload = matches[1] if len(matches) > 1 else matches[0]

                mac_pattern = rf"Rule ID.*?Ports:\s*{port}.*?Source MAC\s*:\s*((?:[0-9A-F]{{2}}[-]){{5}}[0-9A-F]{{2}})"
                mac_match = re.search(mac_pattern, output, re.DOTALL | re.IGNORECASE)
                if mac_match:
                    source_mac = mac_match.group(1)

            elif "DGS-3120" in prompt:
                # разбиваем вывод на блоки правил
                blocks = re.split(
                    r"--------------------------------------------------------------------------------",
                    output,
                )

                for block in blocks:
                    if f"Ports: {port}" in block:
                        # считаем количество offset_chunk в блоке
                        chunk_count = len(re.findall(r"offset_chunk", block))
                        if chunk_count == 1:
                            # это правило с одним чанком
                            match = re.search(
                                r"value\s*:\s*(0x[0-9A-F]+)", block, re.IGNORECASE
                            )
                            if match:
                                payload = match.group(1)
                                break

                # source mac для 3120
                mac_pattern = rf"Ports:\s*{port}.*?Source MAC\s*:\s*((?:[0-9A-F]{{2}}[-]){{5}}[0-9A-F]{{2}})"
                mac_match = re.search(mac_pattern, output, re.DOTALL | re.IGNORECASE)
                if mac_match:
                    source_mac = mac_match.group(1)

            elif "DGS-1210" in prompt:
                pattern = rf"Ports:\s*{port}\s+.*?Filter Value = (0x[0-9A-F]+)"
                matches = re.findall(pattern, output, re.DOTALL | re.IGNORECASE)
                if matches:
                    payload = matches[-1]

                mac_pattern = rf"Ports:\s*{port}.*?Source MAC\s*:\s*((?:[0-9A-F]{{2}}[-]){{5}}[0-9A-F]{{2}})"
                mac_match = re.search(mac_pattern, output, re.DOTALL | re.IGNORECASE)
                if mac_match:
                    source_mac = mac_match.group(1)

            else:
                print(
                    f"  ACL PROFILE: unsupported switch type (prompt: {repr(prompt)})"
                )

            if payload:
                # очищаем от 0x если есть
                clean_payload = payload.replace("0x", "")
                # проверяем, что длина достаточная для IP (8 символов)
                if len(clean_payload) == 8:
                    # разбиваем на октеты и конвертируем в десятичные
                    ip_parts = []
                    for i in range(0, 8, 2):
                        octet = int(clean_payload[i : i + 2], 16)
                        ip_parts.append(str(octet))
                    ip_address = ".".join(ip_parts)
                    print(f"  ACL PAYLOAD (port {port}): {payload} -> {ip_address}")
                else:
                    print(f"  ACL PAYLOAD (port {port}): {payload}")

            if source_mac and source_mac != "00-00-00-00-00-00":
                print(f"  ACL SOURCE MAC (port {port}): {source_mac}")

            if not payload and not source_mac:
                print(f"  ACL PROFILE (port {port}): not found")

        except Exception as e:
            print(f"  Ошибка при проверке access profile: {e}")

    def run_diagnostic(
        self, port, user_ip=None, switch_ip_from_db=None, gateway_from_db=None
    ):
        """запуск диагностики порта"""
        if not self.connected:
            print("  NE CONNECTIT")
            return

        print(f"\n  [DIAGNOSTIC RESULT {port}]")
        print("  " + "#" * 50)
        print()

        # гарантируем промпт перед началом
        self._ensure_prompt()

        self.check_port_status(port)
        self.check_len_log(port)
        mac_list = self.check_mac_addresses(port)
        self.check_vlan_on_port(port)
        self.check_dhcp_relay()
        self.check_errors_port(port)
        self.check_packet_port(port)

        if (
            switch_ip_from_db
            and gateway_from_db
            and switch_ip_from_db == gateway_from_db
        ):
            self._ensure_prompt()
            self.session.sendline(f"show arpentry ipaddress {user_ip}")
            time.sleep(TIMEOUTS["RECOVERY"])
            self.session.expect(["5#", "admin#"], timeout=TIMEOUTS["COMMAND"])
            arp_data = self.session.before.decode("utf-8", errors="ignore")

            arp_mac = None
            for line in arp_data.split("\n"):
                if "show arpentry" in line or "Command:" in line:
                    continue
                if user_ip in line:
                    mac_match = re.search(
                        r"((?:[A-F0-9]{2}[-]){5}[A-F0-9]{2})", line, re.IGNORECASE
                    )
                    if mac_match:
                        arp_mac = mac_match.group(1).upper()
                        break

            if arp_mac and arp_mac in mac_list:
                print("  ARP: OK (IP and MAC match on local switch)")
            elif arp_mac:
                print(
                    f"  ARP: NOT MATCH (L2: {', '.join(mac_list)} | local ARP: {arp_mac})"
                )
            else:
                print("  ARP: not found on local switch")
        else:
            self.check_gateway_l3()
            if hasattr(self, "gateway_ip") and self.gateway_ip:
                self.check_arp_on_gateway(user_ip, mac_list)

        self.check_utilization_cpu()
        self.check_cable_diagnostic(port)
        self.check_access_profile(port)

        print("\n  " + "#" * 50)
