#!/usr/bin/python3
# dlink_diagnostic_L2.py

import pymysql.cursors
import sys
import pexpect
import time
import re
import cfg


# ==================== КЛАСС ДЛЯ РАБОТЫ С БД ====================


class DatabaseClient:
	"""класс для работы с бд"""

	def __init__(self, config):
		self.config = config
		self.connection = None

	def connect(self):
		"""коннект к бд"""
		try:
			self.connection = pymysql.connect(
				host=self.config["host"],
				user=self.config["user"],
				password=self.config["password"],
				db=self.config["database"],
				charset=self.config["charset"],
				cursorclass=pymysql.cursors.DictCursor,
			)
			return True
		except pymysql.Error as e:
			print(f"Ошибка подключения к БД: {e}")
			return False

	def close(self):
		"""завершить сессию бд"""
		if self.connection:
			self.connection.close()

	def get_user_by_number(self, number):
		"""поиск члена по намберу возвращает список словарей с данными членов"""
		results = []
		# добавить запрос из бд по ип свитча и вывод его имя
		try:
			with self.connection.cursor() as cursor:
				sql = "SELECT PortP, SwitchP, IP, gate, Add_IP, dhcp_type FROM users WHERE number = %s"
				cursor.execute(sql, (number,))
				rows = cursor.fetchall()

				for row in rows:
					user_data = {
						"switch_name": None,  # сюда потом запишем имя свитча
						"port": row.get("PortP") or "",
						"switch": row.get("SwitchP") or "",
						"ip": row.get("IP") or "",
						"gate": row.get("gate") or "",
						"add_ip": row.get("Add_IP") or "",
						"dhcp_type": row.get("dhcp_type") or "",
					}
					results.append(user_data)

		except pymysql.Error as e:
			print(f"Ошибка выполнения запроса: {e}")

		return results

	def get_switch_name_by_ip(self, ip_address):
		"""поиск имени свитча по IP-адресу"""
		try:
			with self.connection.cursor() as cursor:
				# используем LIKE для поиска по началу IP
				sql = "SELECT name FROM switches WHERE IP LIKE %s"
				cursor.execute(sql, (f"{ip_address}%",))
				row = cursor.fetchone()

				if row:
					return row.get("name")
				else:
					return None

		except pymysql.Error as e:
			print(f"  Ошибка при поиске имени свитча в БД: {e}")
		return None


# ==================== КЛАСС ДЛЯ РАБОТЫ СО СВИТЧОМ ====================


class DLinkTelnetClient:
	def __init__(self, host, disable_paging=True):  #
		self.host = host
		self.disable_paging = disable_paging  #
		self.username = cfg.SWITCH_USERNAME
		self.password = cfg.SWITCH_PASSWORD
		self.session = None
		self.connected = False
		self.gateway_ip = None

	def connect(self, quiet=False):
		try:
			if not quiet:
				print(f"  Connect to {self.host}...")

			self.session = pexpect.spawn(f"telnet {self.host}", timeout=6)
			self.session.expect(r"User[Nn]ame:")
			self.session.sendline(self.username)
			self.session.expect(r"[Pp]ass[Ww]ord")
			self.session.sendline(self.password)
			self.session.expect(["5#", "admin#", "#", ">", "Switch#"], timeout=1)

			#  отключаем paging только если флаг True
			if self.disable_paging:
				self.session.sendline("disable clipaging")
				self.session.expect(["5#", "admin#", "#", "Switch#"], timeout=1)

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
				# добавить флаг на gw True
				self.session.sendline("enable clipaging")
				self.session.sendline("\r")
				self.session.expect(["5#", "admin#", "#", "Switch#"], timeout=1)
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
			# клир буфер перед отправкой команды
			self.session.sendline("")
			try:
				self.session.expect(["5#", "admin#"], timeout=1)
			except:
				# если таймаут, пробуем восстановить соединение
				self.session.sendline("\r")
				time.sleep(0.5)
				self.session.expect(["5#", "admin#"], timeout=1)

			# отправляем команду show ports
			self.session.sendline(f"show ports {port}")
			self.session.expect(["5#", "admin#"], timeout=1)
			data_port = self.session.before.decode("utf-8", errors="ignore")

			# статус линка
			res = re.search(r"\b\d+[M]\S+|(Li\S+.\S+)", data_port)
			if res:
				print(f"  LINK STATUS: {res.group()}")
			else:
				print("  LINK STATUS: не определен")

		except Exception as e:
			print(f"  Ошибка при проверке порта: {e}")
			# пробуем переподключиться
			self.session.sendline("\r")
			time.sleep(1)

	def check_mac_addresses(self, port):
		"""Проверка MAC-адресов на порту (show fdb port)"""
		try:
			# клир буфер перед отправкой команды
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)
			# отправляем команду show fdb port
			self.session.sendline(f"show fdb port {port}")
			self.session.expect(["5#", "admin#"], timeout=1)
			data_fdb = self.session.before.decode("utf-8", errors="ignore")

			# ищем все MAC-адреса
			res_mac = re.findall(
				r"^\s*\d+\s+\S+\s+((?:[A-F0-9]{2}[-]){5}[A-F0-9]{2})",
				data_fdb,
				re.MULTILINE | re.IGNORECASE,
			)

			if res_mac:
				mac_list = [mac.upper() for mac in res_mac]

				# ищем тип порта на порт секурити (Dynamic или Permanent)
				type_match = re.search(r"(Dynamic|Permanent)", data_fdb, re.IGNORECASE)
				mac_type = type_match.group(1) if type_match else "не определен"

				print(f"  MAC: {', '.join(mac_list)}")
				print(f"  PORT_SECURITY: {mac_type}")
				return mac_list
			else:
				print("  MAC: не найден")
				return []
		except Exception as e:
			print(f"  Ошибка при поиске MAC-адресов: {e}")
			return []


	def check_dhcp_relay(self):
		"""проверка dhcp_relay на enable/disable (show dhcp_relay)"""
		try:
			# клир буфер перед отправкой команды
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)

			# отправляем команду show dhcp_relay
			self.session.sendline("show dhcp_relay")
			self.session.expect(["5#", "admin#"], timeout=1)
			dhcp_relay = self.session.before.decode("utf-8", errors="ignore")

			# вывод статуса dhcp
			res_dhcp = re.search(r"R\S+\s\S+\s+[:].(\S+)", dhcp_relay)
			if res_dhcp:
				print(f"  DHCP_RELAY: {res_dhcp.group(1)}")
			else:
				print("  DHCP_RELAY: не определен")

		except Exception as e:
			print(f"  Ошибка при проверке dhcp: {e}")

	def check_gateway_l3(self):
		"""ищем ип шлюза на л2"""
		try:
			# клир буфер перед отправкой команды
			self.session.sendline("")
			time.sleep(0.3)
			self.session.expect(["5#", "admin#"], timeout=1)

			# отправляем команду show switch
			self.session.sendline("show switch")
			time.sleep(0.5)
			self.session.expect(["5#", "admin#"], timeout=1)
			res_gateway = self.session.before.decode("utf-8", errors="ignore")

			# временная отладка
			# print("\n  DEBUG - SHOW SWITCH OUTPUT:")
			# print(res_gateway)
			# print("  END DEBUG\n")

			# ищем шлюз
			res_def_gate = re.search(
				r"Default Gateway\s*:\s*(\S+)", res_gateway, re.IGNORECASE
			)
			if res_def_gate:
				self.gateway_ip = res_def_gate.group(1)
				print(f"  DEF_GATEWEY: {res_def_gate.group(1)}")
			else:
				print("  DEF_GATEWAY: не определен")

		except Exception as e:
			print(f"  Ошибка при проверке default_gateway: {e}")

	def check_arp_on_gateway(self, user_ip, mac_from_l2):
		"""подключение к L3 свитчу и проверка ARP записи"""
		if not self.gateway_ip:
			return

		try:
			gw = DLinkTelnetClient(self.gateway_ip, disable_paging=False)

			if gw.connect(quiet=True):
				arp_data = ""

				# пробуем первую команду
				gw.session.sendline(f"show arpentry ipaddress {user_ip}")
				time.sleep(0.5)
				gw.session.expect(["5#", "admin#", "Switch#", "#"], timeout=1)
				arp_data = gw.session.before.decode("utf-8", errors="ignore")

				# если не сработало, пробуем вторую
				if "Invalid" in arp_data or "^" in arp_data or not arp_data.strip():
					gw.session.sendline(f"sh arp {user_ip}")
					time.sleep(0.5)
					gw.session.expect(["5#", "admin#", "Switch#", "#"], timeout=1)
					arp_data = gw.session.before.decode("utf-8", errors="ignore")

				# ищем мак и проверяем ип, пропуская строки с командами
				arp_mac = None
				ip_found = False

				for line in arp_data.split("\n"):
					# пропускаем строки с командами
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

				# если арп не найден, пробуем найти маршрут
				if not ip_found and not arp_mac:
					gw.session.sendline(f"show iproute {user_ip}")
					time.sleep(0.5)
					gw.session.expect(["5#", "admin#", "Switch#", "#"], timeout=1)
					route_data = gw.session.before.decode("utf-8", errors="ignore")

					# ищем ип gateway
					gateway_match = re.search(
						r"\d+\.\d+\.\d+\.\d+/\d+\s+(\d+\.\d+\.\d+\.\d+)", route_data
					)

					if gateway_match:
						new_gateway = gateway_match.group(1)
						print(
							f"  ARP: найден шлюз {new_gateway}, пробуем подключиться..."
						)

						# закрываем текущее соединение
						try:
							gw.session.sendline("logout")
							gw.session.close()
						except:
							pass

						# создаем новое подключение к найденному шлюзу
						new_gw = DLinkTelnetClient(new_gateway, disable_paging=False)

						if new_gw.connect(quiet=True):
							# пробуем первую команду на новом шлюзе
							new_gw.session.sendline(
								f"show arpentry ipaddress {user_ip}"
							)
							time.sleep(0.5)
							new_gw.session.expect(
								["5#", "admin#", "Switch#", "#"], timeout=1
							)
							new_arp_data = new_gw.session.before.decode(
								"utf-8", errors="ignore"
							)

							# если не сработало, пробуем вторую
							if (
								"Invalid" in new_arp_data
								or "^" in new_arp_data
								or not new_arp_data.strip()
							):
								new_gw.session.sendline(f"sh arp {user_ip}")
								time.sleep(0.5)
								new_gw.session.expect(
									["5#", "admin#", "Switch#", "#"], timeout=1
								)
								new_arp_data = new_gw.session.before.decode(
									"utf-8", errors="ignore"
								)

							# ищем мак на новом шлюзе, пропуская строки с командами
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

							# выводим результат
							if not mac_from_l2:
								print("  ARP: отсутствует (нет MAC на L2)")
							elif not new_ip_found:
								print("  ARP: отсутствует (IP не найден на доп. шлюзе)")
							elif (
								new_arp_mac
								and new_arp_mac in mac_from_l2
								and new_ip_found
							):
								print(
									"  ARP: OK (IP и MAC совпадают) - найдено на доп. шлюзе"
								)
							elif new_arp_mac:
								print(
									f"  ARP: НЕ СООТВЕТСТВУЕТ (L2: {', '.join(mac_from_l2)} | L3: {new_arp_mac}) - на доп. шлюзе"
								)
							else:
								print(
									"  ARP: отсутствует (запись не найдена) - на доп. шлюзе"
								)

							# закрываем соединение с новым шлюзом
							try:
								new_gw.session.sendline("logout")
								new_gw.session.close()
							except:
								pass

							return
						else:
							print(
								f"  ARP: не удалось подключиться к шлюзу {new_gateway}"
							)
					else:
						print("  ARP: маршрут не найден")

				# если ара найдена на первом шлюзе, выводим результат
				elif not mac_from_l2:
					print("  ARP: отсутствует (нет MAC на L2)")

				elif not ip_found:
					print("  ARP: отсутствует (IP не найден на L3)")

				elif len(mac_from_l2) > 5:
					print(
						f"  ARP: {arp_mac if arp_mac else 'MAC не найден'} (на порту {len(mac_from_l2)} MAC-адресов, проверьте порт вручную)"
					)

				elif arp_mac and arp_mac in mac_from_l2 and ip_found:
					print("  ARP: OK (IP и MAC совпадают)")

				elif arp_mac:
					print(
						f"  ARP: НЕ СООТВЕТСТВУЕТ (L2: {', '.join(mac_from_l2)} | L3: {arp_mac})"
					)

				else:
					print("  ARP: отсутствует (запись не найдена)")

				# закрываем соединение с первым шлюзом
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
			# клир буфер перед отправкой команды
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)

			# отправляем команду show utilization cpu
			self.session.sendline("show utilization cpu")
			self.session.expect(["5#", "admin#"], timeout=1)
			utilization_cpu = self.session.before.decode("utf-8", errors="ignore")

			# ищем загрузку цп
			res_util_cpu = re.search(r"Five.*?(\d+\s*%)", utilization_cpu)
			if res_util_cpu:
				print(f"  UTIL_CPU: {res_util_cpu.group(1)}")
			else:
				print("  UTIL_CPU: не определен")

		except Exception as e:
			print(f"  Ошибка при проверке utilization_cpu: {e}")

	def check_errors_port(self, port):
		"""Проверка ошибок на порту (show error ports)"""
		try:
			# клир буфер перед отправкой команды
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)

			# отправляем команду show error ports
			self.session.sendline(f"show error ports {port}")
			self.session.expect(["5#", "admin#"], timeout=1)
			error_ports = self.session.before.decode("utf-8", errors="ignore")

			# ищем ошибки на порту
			res_error_ports = re.search(r"CRC Error\s+(\d+)", error_ports)
			if res_error_ports:
				print(f"  ERRORS PORT: {res_error_ports.group(1)}")
			else:
				print("  ERRORS PORT: не определен")

		except Exception as e:
			print(f"  Ошибка при проверке error: {e}")

	def check_packet_port(self, port):
		"""проверка трафика на порту (show packer ports)"""
		try:
			# клир буфер перед отправкой команды
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)

			# отправляем команду show packet ports
			self.session.sendline(f"show packet ports {port}")
			self.session.expect(["5#", "admin#"], timeout=1)
			packet_ports = self.session.before.decode("utf-8", errors="ignore")

			# findall ищет все вхождения (RX и TX)
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

	def check_cable_diagnostic(self, port):
		"""проверка диагностики кабеля (cable diagnostic port / cable_diag ports)"""
		try:
			# очищаем буфер
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)
			prompt = self.session.before.decode("utf-8", errors="ignore")

			if "DGS-1210" in prompt or "1210" in prompt:
				cmd = f"cable diagnostic port {port}"
			else:
				cmd = f"cable_diag ports {port}"

			self.session.sendline(cmd)
			time.sleep(1)
			self.session.sendline("")
			self.session.expect(["5#", "admin#"], timeout=1)
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
				print("  CABLE DIAG: информация не найдена")

		except Exception as e:
			print(f"  Ошибка при диагностике кабеля: {e}")

	def check_vlan_on_port(self, port):
		"""проверка VLAN на порту (show vlan ports)"""
		try:
			# сразу отправляем команду show vlan ports
			self.session.sendline(f"show vlan ports {port}")
			self.session.expect(["5#", "admin#"], timeout=1)
			data_vlan = self.session.before.decode("utf-8", errors="ignore")

			# универсальная регулярка под разные свитчи
			vlan_matches = re.findall(
				r"^\s*(\d+)\s+([X-])\s+([X-])", data_vlan, re.MULTILINE
			)

			# если не зарегало по универсальной, то пробуем второй (с номером порта в начале строки)
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
				print("  VLAN: информация не найдена")

		except Exception as e:
			print(f"  Ошибка при проверке VLAN: {e}")

	def run_diagnostic(self, port, user_ip=None):
		"""запуск диагностики порта"""
		if not self.connected:
			print("  NE CONNECTIT")
			return

		print(f"\n  [DIAGNOSTIC RESULT {port}]")
		print("  " + "=" * 50)
		print()

		self.check_port_status(port)
		mac_list = self.check_mac_addresses(port)  #  получаем MAC здесь
		self.check_vlan_on_port(port)
		self.check_dhcp_relay()
		self.check_errors_port(port)
		self.check_packet_port(port)
		self.check_gateway_l3()
		self.check_utilization_cpu()
		self.check_cable_diagnostic(port)

		if hasattr(self, "gateway_ip") and self.gateway_ip:
			self.check_arp_on_gateway(user_ip, mac_list)  #  используем mac_list

		print("\n  " + "=" * 50)


# ==================== MAIN PROG ====================


def print_header():
	"""вывод результатов"""
	print("\n" + "*" * 70)
	print("DIAGNOSTICA CHLENSKOGO".center(70))
	print("*" * 70)
	print()


def print_user_info(user, idx):
	"""информация юза"""
	print(f"INFO # {idx}\n")
	if user["switch_name"]:
		print(f"  SW MODEL:   {user['switch_name']}")
	print(f"  IP_us:      {user['ip'] if user['ip'] else 'не указан'}")
	print(f"  PORT:       {user['port'] if user['port'] else 'не указан'}")
	print(f"  GATEWAY:    {user['gate'] if user['gate'] else 'не указан'}")
	print(f"  IP_switch:  {user['switch'] if user['switch'] else 'не указан'}")
	print(f"  ADD_ip:     {user['add_ip'] if user['add_ip'] else 'не указан'}")
	print(f"  DHCP_type:  {user['dhcp_type'] if user['dhcp_type'] else 'не указан'}")
	print()


def main():
	print_header()
	# инициализация клиента БД
	db = DatabaseClient(cfg.DB_CONFIG)

	# подключаемся к БД
	if not db.connect():
		print("Что-то пошло не так.")
		sys.exit(1)

	try:
		while True:
			# ввод номера
			search = input("NOMBER CHILEN: ").strip()

			if search.lower() in ["exit", "quit", "q", "выход"]:
				print("\nExit")
				break

			if not search:
				print("Ошибка: введите номер для поиска")
				continue

			print(f"\nFind user with num: {search}")

			# получаем данные из БД
			users = db.get_user_by_number(search)

			if not users:
				print(f"Chlen with num '{search}' not found")
				continue

			print()

			for user in users:
				if user["switch"]:  # если есть IP свитча
					switch_ip = user["switch"]
					# проверяем, что это IP
					ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
					if re.match(ip_pattern, switch_ip):
						# получаем имя свитча из БД
						user["switch_name"] = db.get_switch_name_by_ip(switch_ip)

			# выводим найденные записи
			for idx, user in enumerate(users, 1):
				print_user_info(user, idx)

			# выбор записи для диагностики
			selected_user = None

			if len(users) == 1:
				choice = input("Run diagnostic? (y/n): ").strip().lower()
				if choice in ["y", "yes", "да", "д"]:
					selected_user = users[0]

			# запуск диагностики
			if selected_user:
				switch_info = selected_user["switch"]
				port = selected_user["port"]

				if not switch_info:
					print("Не указан номер члена")
					continue

				if not port:
					print("Не указан номер порта")
					continue

				# проверка является ли switch_info IP адр
				ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

				if re.match(ip_pattern, switch_info):
					# это IP адр
					switch_ip = switch_info

				else:
					# это имя свитча, нужно запросить IP
					print(f"\nswitch: {switch_info}")
					switch_ip = input(
						f"Введите IP адрес свитча {switch_info}: "
					).strip()

					if not switch_ip:
						print("IP адрес не указан")
						continue

				# клиент для подключения к свитчу
				switch = DLinkTelnetClient(host=switch_ip)

				# коннект
				if switch.connect():
					# запуск диагностики порта
					switch.run_diagnostic(port, selected_user["ip"])

					# закрываем соединение
					switch.disconnect()
				else:
					print("Не удалось подключиться к свитчу")

			print("Try?")  # пустая строка перед следующим поиском

	except KeyboardInterrupt:
		print("\n\nПрограмма прервана пользователем.")
	finally:
		db.close()


if __name__ == "__main__":
	main()
