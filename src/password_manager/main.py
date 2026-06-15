from password_manager.vault import Vault
from password_manager.generator import generate_password

def main():
    vault = Vault()
    
    master = input("Enter master password: ")
    vault.unlock(master)

    pw = generate_password(16)
    vault.add_entry("gmail", "user@gmail.com", pw)

    print("\nStored entries:\n")
    for row in vault.get_all(decrypt=True):
        print(row)

    input("\nPress Enter to lock vault...")
    vault.lock()

if __name__ == "__main__":
    main()