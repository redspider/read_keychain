## Read your keychain

This script will read an OSX keychain and provide either a scathing analysis of your password strength and duplication
or a CSV export of the account, server and plain text password.

_Under no fucking circumstances_ should you run this blindly. Read the god damn thing from head to toe, there are
instructions in the header you must follow in order to get the dependencies, and I won't replicate them here.

Do not share this script with anyone who can't read python enough to be certain they're running something safe.

Actually, scratch that, don't share it. Just don't.

## Usage

python read_keychain.py --evaluate /path/to/keychain

This will tell you just how abominably shit you are at having unique, strong passwords for each site.

--export will give you a CSV export to stdout.