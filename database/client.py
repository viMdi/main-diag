import os
import pymysql.cursors


class DatabaseClient:
    """класс для работы с бд"""

    def __init__(self, config=None):
        if config is None:
            self.config = {
                "host": os.getenv("DB_HOST"),
                "database": os.getenv("DB_NAME"),
                "user": os.getenv("DB_USER"),
                "password": os.getenv("DB_PASSWORD"),
                "charset": os.getenv("DB_CHARSET", "cp1251"),  # charset можно оставить
            }
        else:
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
        try:
            with self.connection.cursor() as cursor:
                sql = "SELECT PortP, SwitchP, IP, gate, Add_IP, dhcp_type FROM users WHERE number = %s"
                cursor.execute(sql, (number,))
                rows = cursor.fetchall()

                for row in rows:
                    user_data = {
                        "switch_name": None,
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
