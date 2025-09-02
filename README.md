# gmsaOfflineParser.py
Small script designed to parse offline msDs-managedPassword attribute of gMSA accounts, and build their NT hash.

# Installation
```zsh
git clone https://github.com/mael91620/gmsaOfflineParser.py.git
cd gmsaOfflineParser.py
python3 -m venv venv
source venv/bin/activate
pip3 install impacket
pip3 install pycryptodome
pip3 install random
pip3 install binascii
```

# Usage
Edit the value of the *s* variable using the integers obtained from the following powershell command
```powershell
Get-AdServiceAccount -Identity "gMSA-account$" -Properties "msDs-managedPassword"
```

Just run the script and voila.