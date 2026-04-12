from impacket.structure import Structure
from Cryptodome.Hash import MD4
from binascii import hexlify
import argparse

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ("Version", "<H"),
        ("Reserved", "<H"),
        ("Length", "<L"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", ":"),
        ("PreviousPassword", ":"),
        ("QueryPasswordInterval", ":"),
        ("UnchangedPasswordInterval", ":"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)

        endData = self["QueryPasswordIntervalOffset"] if self["PreviousPasswordOffset"] == 0 else self["PreviousPasswordOffset"]

        self["CurrentPassword"] = self.rawData[self["CurrentPasswordOffset"]:][: endData - self["CurrentPasswordOffset"]]
        if self["PreviousPasswordOffset"] != 0:
            self["PreviousPassword"] = self.rawData[self["PreviousPasswordOffset"]:][: self["QueryPasswordIntervalOffset"] - self["PreviousPasswordOffset"]]

        self["QueryPasswordInterval"] = self.rawData[self["QueryPasswordIntervalOffset"]:][: self["UnchangedPasswordIntervalOffset"] - self["QueryPasswordIntervalOffset"]]
        self["UnchangedPasswordInterval"] = self.rawData[self["UnchangedPasswordIntervalOffset"]:]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Offline gMSA managed-password blob parser. Derives NT hash and optionally Kerberos AES keys."
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--integers", metavar="CSV",
        help="Comma-separated integers (from PowerShell Get-ADServiceAccount msDS-ManagedPassword)")
    input_group.add_argument("--hex", metavar="HEX",
        help="Hex-encoded blob (from impacket-secretsdump _SC_GMSA_ LSA secret)")
    parser.add_argument("--salt", metavar="SALT",
        help="Kerberos salt for AES key derivation (e.g. DOMAIN.LOCALhostaccount.domain.local)")
    return parser.parse_args()


def extract_password(blob_bytes):
    blob = MSDS_MANAGEDPASSWORD_BLOB()
    blob.fromString(blob_bytes)
    current_password = blob["CurrentPassword"]
    if current_password.endswith(b"\x00\x00"):
        current_password = current_password[:-2]
    return current_password


def compute_nt_hash(password_bytes):
    return hexlify(MD4.new(password_bytes).digest()).decode("utf-8")


def compute_aes_keys(password_bytes, salt):
    from impacket.krb5.crypto import Enctype, string_to_key
    pwd_str = password_bytes.decode("utf-16-le", errors="replace")
    aes256 = string_to_key(Enctype.AES256, pwd_str, salt.encode()).contents
    aes128 = string_to_key(Enctype.AES128, pwd_str, salt.encode()).contents
    return hexlify(aes256).decode(), hexlify(aes128).decode()


if __name__ == "__main__":
    args = parse_args()

    if args.integers:
        blob_bytes = bytes(int(x.strip()) for x in args.integers.split(","))
    else:
        blob_bytes = bytes.fromhex(args.hex.strip())

    current_password = extract_password(blob_bytes)
    print(f"NT hash : {compute_nt_hash(current_password)}")

    if args.salt:
        aes256, aes128 = compute_aes_keys(current_password, args.salt)
        print(f"AES256  : {aes256}")
        print(f"AES128  : {aes128}")
