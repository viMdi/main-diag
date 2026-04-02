#!/usr/bin/python3
# dlink_diagnostic_L2.py

from database.client import DatabaseClient
from telnet.client import DLinkTelnetClient
import sys
import re
import os

# ----- main

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
	db = DatabaseClient()

	if not db.connect():
		print("Oops, it didn't work")
		sys.exit(1)

	try:
		while True:
			search = input("us_num: ").strip()

			if search.lower() in ["exit", "quit", "q", "выход"]:
				print("\nExit")
				break

			if not search:
				print("Error: enter number to search")
				continue

			print(f"\nFind user with num: {search}")

			users = db.get_user_by_number(search)

			if not users:
				print(f"Chlen with num '{search}' not found")
				continue

			print()

			for user in users:
				if user["switch"]:
					switch_ip = user["switch"]
					ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
					if re.match(ip_pattern, switch_ip):
						user["switch_name"] = db.get_switch_name_by_ip(switch_ip)

			for idx, user in enumerate(users, 1):
				print_user_info(user, idx)

			selected_user = None

			if len(users) == 1:
				choice = input("Run diagnostic? (y/n): ").strip().lower()
				if choice in ["y", "yes", "да", "д"]:
					selected_user = users[0]

			if selected_user:
				switch_info = selected_user["switch"]
				port = selected_user["port"]

				if not switch_info:
					print("user number not specified")
					continue

				if not port:
					print("port number not specified")
					continue

				ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

				if re.match(ip_pattern, switch_info):
					switch_ip = switch_info
				else:
					print(f"\nswitch: {switch_info}")
					switch_ip = input(f"Enter IP-add {switch_info}: ").strip()
					if not switch_ip:
						print("IP address not specified")
						continue

				switch = DLinkTelnetClient(host=switch_ip)

				if switch.connect():
					switch.run_diagnostic(port, selected_user["ip"], switch_ip, selected_user["gate"])
					switch.disconnect()
				else:
					print("Failed to connect")

			print("Let's try again?")

	except KeyboardInterrupt:
		print("\n\nSCRIPT STOPPED")
	finally:
		db.close()


if __name__ == "__main__":
	main()
