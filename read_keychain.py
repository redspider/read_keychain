"""
This script reads a given keychain, assuming the user knows the password, and optionally:

A) evaluates the passwords for non-shittyness/sharing
B) exports the passwords via CSV

This script, deliberately, requires you to install pbkdf2 and pycrypto using:

pip install pbkdf2 pycrypto

This means you need the Xcode command line developer tools installed (for gcc for pycrypto) and most likely a virtualenv.

This is intentional because you should be familiar enough with python to read every single line in this codebase and
be certain I'm not doing something dodgy with your password. If you can't do that, you have no business running this
script at all, find a good reliable python friend to evaluate for you.

This script was written on the 7th of September, 2012. Apple probably will change their keychain format at some point
and cause it to start failing. It won't do any harm, it never writes to any files, but it will stop working.

This script will not retrieve certificates, only website passwords and similar.

Credit to
    https://github.com/juuso/keychaindump
    Matt Johnston

    for figuring out the formats and writing some vaguely readable code to build this from.
"""

from binascii import unhexlify, hexlify
import re
import struct
import sys, logging
from optparse import OptionParser
from getpass import getpass
from collections import namedtuple
import pbkdf2
import csv
from Crypto.Cipher import DES3

logging.basicConfig(level=logging.WARN)
log = logging.getLogger('read_keychain')

class InvalidKeychainFile(Exception):
    pass

class BadPaddingValue(Exception):
    pass

class NotAKeychainFile(Exception):
    pass

def pbkdf2_wrap(key, salt, iterations, size):
    return pbkdf2.PBKDF2(key, salt, iterations).read(size)

def des3_wrap(key, iv, data):
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(data)

def decrypt_and_strip(key, iv, data):
    """
    DES3 decrypt and then remove padding information
    """
    plaintext = des3_wrap(key, iv, data)

    # The last byte is the number of bytes to strip, it is never more than 8 bytes (because the block size is 8 bytes)
    padding_count = ord(plaintext[-1])
    if padding_count > 8:
        raise BadPaddingValue("Bad padding value %d in %s" % (padding_count, hexlify(plaintext)))

    return plaintext[:-padding_count]

def atom32(fh, pos):
    """
    Retrieve a 32bit big-endian int from the file handle at given position
    """
    fh.seek(pos)
    return struct.unpack(">I", fh.read(4))[0]

def atomstr(fh, pos, size):
    """
    Retrieve a string from the file handle at the given position
    """
    fh.seek(pos)
    return fh.read(size)

class Keychain(object):
    DB_BLOB_MAGIC = unhexlify('fade0711')
    KEY_MAGIC = 0xfade0711
    CRED_MAGIC = 0x73736770
    MAGIC_IV = "\x4a\xdd\xa2\x2c\x79\xe8\x21\x05"

    def __init__(self, path, key):
        self.path = path
        self.key = key
        self.keys = {}
        self.credentials = []

        self._parse()

    def _get_db_key(self):
        """
        Obtain the database key
        """
        fh = open(self.path, "r")

        # First we jump to the end of the file
        fh.seek(0, 2)

        # Then scan backwards looking for the magic number that identifies the DB blob
        while True:
            # Skip back 4 from current
            fh.seek(-4, 1)
            # Read those 4 bytes
            word = fh.read(4)

            # End of file? oh well, fubar
            if not len(word):
                raise InvalidKeychainFile("Keychain file does not contain DB blob magic")

            # Back up so that if we find the magic we're at the right place
            fh.seek(-4, 1)

            # Matches our magic? we're done searching
            if word == self.DB_BLOB_MAGIC:
                break

        # Store the DB blob position for later use
        self.db_blob_position = fh.tell()

        # Interpret the fixed structure
        dbblob_struct = struct.Struct(">IIII16sIII20s8s20s")
        DBBlob = namedtuple('DBBlob', 'magic version crypto_offset length signature sequence idle_timeout lock_on_sleep salt iv blob_signature')
        db_blob = DBBlob._make(dbblob_struct.unpack(fh.read(dbblob_struct.size)))
        log.debug("DB Blob position: @%d bytes" % self.db_blob_position)
        log.debug("DB Crypto offset: @%d bytes" % db_blob.crypto_offset)
        log.debug("DB IV: %s" % hexlify(db_blob.iv))
        log.debug("DB Salt: %s" % hexlify(db_blob.salt))

        # Obtain the crypto component (sites at a dynamic position)
        fh.seek(self.db_blob_position + db_blob.crypto_offset, 0)
        ciphertext = fh.read(48)
        log.debug("DB ciphertext: %s" % hexlify(ciphertext))

        # Build master key from password
        master = pbkdf2_wrap(self.key, salt=db_blob.salt, iterations=1000, size=24)
        log.debug("DB master: %s" % hexlify(master))

        # Use master key to decrypt ciphertext to obtain db key
        db_key = decrypt_and_strip(master, db_blob.iv, ciphertext)[:24]
        log.debug("DB key: %s" % hexlify(db_key))

        fh.close()

        return db_key

    def _parse_key_record(self, key, fh, offset):
        """
        Parse a key record from the given offset and put it in the keys list

        Aren't entire
        """
        ciphertext_offset = atom32(fh, offset+8)
        length = atom32(fh, offset+12)
        log.debug("Key record @%d bytes, len %d" % (offset, length))

        iv = atomstr(fh, offset+16, 8)
        log.debug("Key IV %s" % hexlify(iv))
        label = atomstr(fh, offset+length+8, 20)
        log.debug("Key Label %s" % hexlify(label))

        ciphertext_length = length - ciphertext_offset
        if ciphertext_length != 48:
            log.debug("Uninteresting ciphertext length %d bytes" % ciphertext_length)
            return

        # First we have to decrypt the data using a fixed IV
        pre_ciphertext = atomstr(fh, offset+ciphertext_offset, 48)
        log.debug("Pre-ciphertext %s" % hexlify(pre_ciphertext))
        ciphertext_1 = des3_wrap(key, self.MAGIC_IV, pre_ciphertext)
        log.debug("Ciphertext round 1 %s" % hexlify(ciphertext_1))

        # Reverse the first 32 bytes (WTF apple srsly)
        ciphertext_2 = ciphertext_1[:32]
        ciphertext_2 = ciphertext_2[::-1]
        log.debug("Ciphertext round 2 %s" % hexlify(ciphertext_2))

        # Decrypt properly
        try:
            plaintext = decrypt_and_strip(key, iv, ciphertext_2)
        except BadPaddingValue:
            # Don't know why, but some aren't meant to be decoded this way
            return
        log.debug("Plaintext %s (%d bytes)" % (hexlify(plaintext), len(plaintext)))
        if len(plaintext) != 28:
            # No idea here either
            return

        self.keys[label] = plaintext[4:]

    def _retrieve_attribute(self, fh, offset, attr):
        """
        Retrieve an attribute from a given credential record
        """
        attr_offset = atom32(fh, offset+24+attr*4) & 0xfffffffe
        attr_len = atom32(fh, offset + attr_offset)
        return atomstr(fh, offset + attr_offset + 4, attr_len)

    def _parse_credential_record(self, key, fh, offset):
        """
        Parse a credentials record
        """
        record_size = atom32(fh, offset + 0)
        data_size = atom32(fh, offset + 16)
        log.debug("Record size %d, data size %d" % (record_size, data_size))

        if record_size == data_size + 24:
            log.debug("Record has no attributes, ignoring")

        first_attr_offset = atom32(fh, offset + 24) & 0xfffffffe
        data_offset = first_attr_offset - data_size
        attr_count = (data_offset - 24) / 4

        log.debug("1st attr @%d bytes, data @%d bytes, attr count %d" % (first_attr_offset, data_offset, attr_count))
        if attr_count != 20:
            log.debug("Attribute count != 20, not an interesting record, ignoring")
            return

        data_abs = offset + data_offset
        ciphertext_len = data_size - 20 - 8
        if ciphertext_len < 8 or (ciphertext_len % 8 != 0):
            # I have no idea why this is bad.
            log.debug("Ciphertext length is weird, not an interesting record, ignoring")
            return

        label = atomstr(fh, data_abs, 20)

        if not self.keys[label]:
            log.debug("No key for label %s, ignoring" % hexlify(label))
            return

        cred = {
            'label': label,
            'iv': atomstr(fh, data_abs + 20, 8),
            'ciphertext': atomstr(fh, data_abs + 28, ciphertext_len),
            'key': self.keys[label],
            'server': self._retrieve_attribute(fh, offset, 15),
            'account': self._retrieve_attribute(fh, offset, 13)
        }

        log.debug("Retrieved credential for server/account %s/%s" % (cred['server'],cred['account']))

        self.credentials.append(cred)


    def _obtain_keys(self):
        """
        Attempt to obtain all the keys in the file
        """
        fh = open(self.path, "r")

        # We need the schema offset, at byte 12
        schema_offset = atom32(fh, 12)
        log.debug("Schema offset @%d bytes" % schema_offset)

        # Obtain the count of tables
        table_count = atom32(fh, schema_offset+4)
        log.debug("Table count %d" % table_count)

        for table in range(0,table_count):
            # Get byte offset to table
            table_offset = atom32(fh, schema_offset+8+table*4)
            table_abs = schema_offset + table_offset
            log.debug("Table %d offset @%d bytes" % (table,table_offset))

            record_count = atom32(fh, table_abs+8)
            log.debug("Record count %d" % record_count)

            # Read records
            for record in range(0, record_count):
                record_offset = atom32(fh, schema_offset + table_offset + 28 + record * 4)
                record_abs = table_abs + record_offset
                record_size = atom32(fh, record_abs + 0)
                data_size = atom32(fh, record_abs + 16)
                log.debug("Record details: @%d bytes, %d bytes long, data %d bytes" % (record_offset, record_size, data_size))

                # Calculate the start of the data section
                data_offset = 24
                if record_size > 24 + data_size:
                    # No idea what this is about
                    first_attr_offset = atom32(fh, record_abs + 24) & 0xfffffffe
                    data_offset = first_attr_offset - data_size

                data_abs = record_abs + data_offset

                record_magic = atom32(fh, data_abs + 0)
                if record_magic == self.KEY_MAGIC:
                    log.debug("This is a key record")
                    self._parse_key_record(self.db_key, fh, data_abs)
                elif record_magic == self.CRED_MAGIC:
                    log.debug("This is a credentials record")
                    self._parse_credential_record(self.db_key, fh, record_abs)
                else:
                    log.debug("This is a WTF record")

        fh.close()

        for cred in self.credentials:
            cred['plaintext'] = des3_wrap(cred['key'], cred['iv'], cred['ciphertext'])


    def _parse(self):
        """
        Parse the keychain file.
        """

        fh = open(self.path,"r")
        if fh.read(4) != 'kych':
            raise NotAKeychainFile()

        self.db_key = self._get_db_key()
        self._obtain_keys()

def is_weak(password):
    """
    Decides whether you have a shit password
    """
    if len(password) < 9:
        return True
    if len(password) > 16:
        return False
    if re.match(r'^[a-z]+$',password):
        return True
    return False

def read_keychain(path, evaluate=False, export=False):
    """
    Read a keychain file after prompting for password

    Evaluate will judge you on the security of your password choices
    Export will produce a CSV export to STDOUT of your passwords
    """

    password = getpass("Keychain password:")

    try:
        kc = Keychain(path, password)
    except BadPaddingValue:
        print "You got your password wrong, most likely. Try again"
        return

    if export:
        cw = csv.writer(sys.stdout)
        cw.writerow(['Server','Account','Password'])
        for cred in kc.credentials:
            cw.writerow([cred['server'], cred['account'], cred['plaintext']])

    if evaluate:
        pass_count = {}
        for cred in kc.credentials:
            pass_count[cred['plaintext']] = pass_count.get(cred['plaintext'],0) + 1

        for cred in kc.credentials:
            if is_weak(cred['plaintext']):
                print "%s @ %s has a weak password" % (cred['account'], cred['server'])
            if pass_count[cred['plaintext']] > 1:
                print "%s @ %s shares a password with %d other accounts" % (cred['account'], cred['server'], pass_count[cred['plaintext']])

if __name__ == "__main__":
    usage = "usage: %prog [options] filename"
    parser = OptionParser(usage="usage: %prog [options] filename")
    parser.add_option("--verbose","-v",
        help = "print debugging output",
        action = "store_true")
    parser.add_option("--evaluate","-e",
        help = "evaluate security of passwords",
        action = "store_true")
    parser.add_option("--export","-x",
        help = "export as CSV",
        action = "store_true")
    (options, args) = parser.parse_args()
    if options.verbose:
        log.setLevel(logging.DEBUG)

    log.debug("Verbose mode: %s" % options.verbose)
    log.debug("Keychain: %s" % args[0])

    if not (options.evaluate or options.export):
        parser.error("You must specify either --evaluate or --export")
        sys.exit(-1)

    if len(args) > 0 and args[0] != '-':
        read_keychain(args[0], evaluate=options.evaluate, export=options.export)
    else:
        parser.error("You must specify the filename of your keychain")
        sys.exit(-1)
