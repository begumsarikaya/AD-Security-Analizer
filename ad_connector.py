from dataclasses import dataclass
from typing import Optional

from ldap3 import Server, Connection, ALL, SUBTREE


@dataclass
class ADConfig:
    server: str
    user: str
    password: str
    base_dn: str


class ADConnector:
    def __init__(self, config: ADConfig):
        self.config = config
        self.server = Server(self.config.server, get_info=ALL)
        self.connection: Optional[Connection] = None

    def connect(self):
        try:
            self.connection = Connection(
                self.server,
                user=self.config.user,
                password=self.config.password,
                auto_bind=True,
            )
            return True, "Bağlantı başarılı"
        except Exception as e:
            return False, str(e)

    def search_users(self):
        if not self.connection:
            raise Exception("Bağlantı yok")

        self.connection.search(
            search_base=self.config.base_dn,
            search_filter="(&(objectClass=user)(objectCategory=person))",
            search_scope=SUBTREE,
            attributes=[
                "cn",
                "sAMAccountName",
                "userAccountControl",
                "memberOf",
            ],
        )

        users = []

        for entry in self.connection.entries:
            user_data = entry.entry_attributes_as_dict

            member_of = user_data.get("memberOf", [])
            if not isinstance(member_of, list):
                member_of = [member_of]

            is_admin = any("Domain Admins" in str(group) for group in member_of)
            user_data["is_admin"] = is_admin
            user_data["last_logon_days_ago"] = 0

            users.append(user_data)

        return users
