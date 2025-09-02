from impacket.structure import Structure
from Cryptodome.Hash import MD4
import random
from binascii import hexlify

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



blob = MSDS_MANAGEDPASSWORD_BLOB()
s = "1,0,0,0,34,1,0,..."
int_list = [int(x) for x in s.split(',')]

# Step 2: Convert the list of integers to a bytes object
byte_result = bytes(int_list)

blob.fromString(byte_result)
currentPassword = blob["CurrentPassword"][:-2]
ntlm_hash = MD4.new()
ntlm_hash.update(currentPassword)
NT_hash = hexlify(ntlm_hash.digest()).decode("utf-8")
print(f"{NT_hash = }")
