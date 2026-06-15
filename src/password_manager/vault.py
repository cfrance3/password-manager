from password_manager.crypto import encrypt, decrypt, derive_key, generate_salt, hash_master_password
from password_manager.db import get_connection, init_db

class Vault:
    def __init__(self):
        init_db()
        self.conn = get_connection()
        self.cur = self.conn.cursor()

        self._key = None
        self._unlocked = False

        self.salt = self._load_or_create_salt()



    #===========================
    # Salt handling
    #===========================

    def _load_or_create_salt(self):
        self.cur.execute("SELECT value FROM metadata WHERE key='salt'")
        row = self.cur.fetchone()

        if row:
            return row[0]
        
        salt = generate_salt()
        self.cur.execute(
            "INSERT INTO metadata (key, value) VALUES (?,?)",
            ("salt", salt)
        )
        self.conn.commit()

        return salt
    

    #===========================
    # Add entry
    #===========================

    def add_entry(self, service: str, username: str, password: str):
        self._require_unlocked()
        
        encrypted = encrypt(password, self._key)

        self.cur.execute("""
            INSERT INTO vault_entries (service, username, password_encrypted)
            VALUES (?,?,?)
        """, (service, username, encrypted))

        self.conn.commit()
    

    #===========================
    # Get entries
    #===========================

    def get_all_encrypted(self):
        self.cur.execute("""
            SELECT service, username, password_encrypted 
            FROM vault_entries
        """)

        return self.cur.fetchall()


    def decrypt_entry(self, encrypted_pasword: bytes):
        self._require_unlocked()
        
        return decrypt(encrypted_pasword, self._key)
    

    def get_all(self, decrypt: bool = False):
        self._require_unlocked()

        rows = self.get_all_encrypted()

        if not decrypt:
            return rows
        
        return [
            {
                "service": s,
                "username": u,
                "password": self.decrypt_entry(p)
            }
            for s, u, p in rows
        ]

    def _verifier_exists(self):
        self.cur.execute("SELECT value FROM metadata WHERE key='verifier'")
        return self.cur.fetchone() is not None
    

    def _setup_new_vault(self, password: str):
        verifier = hash_master_password(password, self.salt)

        self.cur.execute(
            "INSERT INTO metadata (key, value) VALUES (?,?)",
            ("verifier", verifier)
        )

        self.conn.commit()
        print("New vault created.")
    

    def _authenticate(self, password: str):
        self.cur.execute("SELECT value FROM metadata WHERE key='verifier'")
        stored_verifier = self.cur.fetchone()[0]

        test_verifier = hash_master_password(password, self.salt)

        if test_verifier != stored_verifier:
            raise ValueError("Invalid master passworwd")
        
        print("Vault unlocked")
    

    def lock(self):
        self._key = None
        self._unlocked = False
        print("Vault locked")
    

    def unlock(self, master_password: str):
        if self._verifier_exists():
            self._authenticate(master_password)
        
        else:
            self._setup_new_vault(master_password)
            print("Vault initialized")

        self._key = derive_key(master_password, self.salt)
        self._unlocked = True
    

    def is_locked(self):
        return not self._unlocked
    

    def _require_unlocked(self):
        if not self._unlocked or self._key is None:
            raise ValueError("Vault is locked")