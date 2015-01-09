#!/usr/bin/env python
# coding: utf-8

import argparse
import cPickle as pickle
import cStringIO as StringIO
import datetime
import getpass
import os
import readline
import string
import subprocess
import sys

from Crypto.Cipher import Blowfish
from Crypto.Hash   import SHA512
from Crypto.Random import random

program_name    = "gumpswd"
program_version = "v0.2"

key_info        = "setting_00_02_00_01"
key_data        = "data_00_02_00_01"

def print_command_usage():
    print \
"""Command action
    d               delete the item
    e               edit the item
    export <file>   export the items to the <file>
    import <file>   import the items from the <file>
    m               print this menu
    n               add a new item
    p               list all items
    p <str>         list all matching items
    p <str> copy    copy the password of the matching item
    p <str> show    show the password of the matching item
    pid <id>        list the specified item
    pid <id> copy   copy the password of the specified item
    pid <id> show   show the password of the specified item
    q               quit without saving changes
    w               write data changes and exit
    X               change the main password
"""

BS = Blowfish.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def panic(str):
    print "[ERROR]: %s\n" % (str)
    sys.exit(1)

def info(str):
    print "[WRONG]: %s\n" % (str)

def save_text_to_clipboard(str):
    import pyperclip
    pyperclip.setcb(str)

def generate_key_and_iv(pwd):
    hash = SHA512.new()
    hash.update(pwd)
    a = hash.digest()
    return a[BS:], a[:BS]

def encrypt_data(data, pwd):
    key, iv = generate_key_and_iv(pwd)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    data = pad(data)
    return cipher.encrypt(data)

def decrypt_data(data, pwd):
    key, iv = generate_key_and_iv(pwd)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    data = cipher.decrypt(data)
    return unpad(data)

def generate_password(range=None, size=16):
    if not range:
        range = string.digits + string.ascii_letters + string.digits
    a = []
    while len(a) < size - 4:
        a.append(random.choice(range))
    while len(a) < size - 2:
        a.append(random.choice(r"+=-@#~,.[]()!%^*$"))
    random.shuffle(a)
    return random.choice(string.ascii_letters) + \
           ''.join(a) + \
           random.choice(string.ascii_letters)

def less(filename=None, data=None):
    if filename:
        expression = r"less %s" % (filename)
        p = subprocess.Popen(expression)
    elif data:
        expression = r"less"
        p = subprocess.Popen(expression, stdin=subprocess.PIPE)
        p.communicate(data)
    p.wait()

def check_user_input_id(db, id):
    return id in xrange(0, len(db[key_data]))

def print_item(db, index, file, show=False):
    item = db[key_data][index].items()
    file.write("+-- %d%s" % (index, os.linesep))
    if show is True:
        for k, v in item:
            if k in ("c", "u", "p", "t"):
                file.write("|   +-- %s: %s%s" % (k, v, os.linesep))
    else:
        for k, v in item:
            if k in ("c", "u", "t"):
                file.write("|   +-- %s: %s%s" % (k, v, os.linesep))
            else:
                file.write("|   +-- %s: %s%s" % (k, "***", os.linesep))

def print_id_db(db, index, show=False, copy=False):
    if check_user_input_id(db, index):
        if copy is True:
            save_text_to_clipboard(db[key_data][index]["p"])
        print_item(db, index, sys.stdout, show)
    else:
        print "invalid id (%d)." % (index)

def print_db(db, str=None, show=False, copy=False):
    index = 0
    result = []
    for i in db[key_data]:
        if str is None or str in i["c"]:
            result.append(index)
        index = index + 1

    if len(result) == 0:
        info("no match.")
        return

    if show is False and copy is False:
        s = StringIO.StringIO()
        for index in result:
            print_item(db, index, s)
        less(data=s.getvalue())
        s.close()
    else:
        if len(result) > 1:
            info("too many match.")
            return

        index = result[0]

        if copy is True:
            save_text_to_clipboard(db[key_data][index]["p"])
        print_item(db, index, sys.stdout, show)
    print ""

def get_pass_strip(prompt):
    try:
        if not prompt:
            str = getpass.getpass()
        else:
            str = getpass.getpass(prompt)
        return str.strip()
    except KeyboardInterrupt:
        print ""
        panic("interrupted!")

def get_non_empty_raw_input_unsafe(prompt):
    while True:
        str = raw_input(prompt).strip()
        if len(str) != 0:
            return str

def get_non_empty_raw_input(prompt):
    while True:
        try:
            return get_non_empty_raw_input_unsafe(prompt)
        except KeyboardInterrupt:
            print ""
            panic("interrupted!")
        except EOFError:
            print ""

def get_non_empty_password():
    while True:
        pwd1 = get_pass_strip("Enter encryption key:")
        pwd2 = get_pass_strip("Enter same key again:")
        if (len(pwd1) != 0) and (pwd1 == pwd2):
            return pwd1
        else:
            print "Passwords don't match - try again."

def add_new_item(db, c, u, p, t):
    item = {"c": c, "u": u, "p": p, "t": t}
    db[key_data].append(item)

def export_to_file(db, filename):
    try:
        f = open(filename, "wb")
    except:
        info("%s: open file error." % (filename))
        return

    for i in db[key_data]:
        f.write("{{{" + os.linesep)
        f.write(i["c"] + os.linesep)
        f.write(i["u"] + os.linesep)
        f.write(i["p"] + os.linesep)
        f.write(i["t"] + os.linesep)
        f.write("}}}" + os.linesep * 2)
    f.close()

def import_from_file(db, filename):
    try:
        f = open(filename, "r")
    except:
        info("%s: file not found." % (filename))
        return

    a = list()
    for line in f:
        str = line.strip()
        if len(str) != 0:
            a.append(str)
    f.close()

    i = 0
    while i < len(a) / 4:
        add_new_item(db, a[4 * i], a[4 * i + 1], a[4 * i + 2], a[4 * i + 3])
        i += 1

def load_db_from_file(file, pwd):
    # Read the file.
    f = open(file, "rb")
    data = f.read()
    f.close()

    # decrypt the data
    data = decrypt_data(data, pwd)

    # Read the object from data
    try:
        db = pickle.loads(data)
        return db
    except:
        panic("Wrong encryption key?")

def save_db_to_file(db, file, pwd):
    # Update the modification time
    db[key_info]["update"] = str(datetime.datetime.now())

    # Dump the object to data
    data = pickle.dumps(db, pickle.HIGHEST_PROTOCOL)

    # encrypt the data
    data = encrypt_data(data, pwd)

    # Write the string to the file
    f = open(file, "wb")
    f.write(data)
    f.close()

def main():

    # Parse the command line options
    parser = argparse.ArgumentParser(description="simple password manager. %s" % (program_version))
    parser.add_argument("-f", "--file", help="specify the db file")
    parser.add_argument("-g", "--generate", help="generate one password in <N> characters", type=int, metavar="N")
    version_string = program_name + " " + program_version
    parser.add_argument("-v", "--version", action="version", version=version_string)
    args = parser.parse_args()

    # generate one password
    if args.generate is not None:
        if args.generate in xrange(4, 128):
            print generate_password(range=None, size=args.generate)
            sys.exit(0)
        else:
            panic("invalid choice: %d (choose from 4 to 128)" % (args.generate))

    # configure the db file path
    if args.file is not None:
        dbpath = args.file
    else:
        dbpath = "%s.db" % (program_name.lower())
        dbpath = os.path.join(os.path.expanduser("~"), dbpath)

    # The db data tree
    db = { \
            key_info: { \
                "create": "", \
                "update": "" \
            }, \
            \
            key_data: [] \
            }

    # Check if the file exists.
    if not os.path.exists(dbpath):

        # Setup the main password.
        pwd = get_non_empty_password()

        # Init the info.
        db[key_info]["create"] = str(datetime.datetime.now())
    else:

        pwd = get_pass_strip("Enter encryption key:")

        db = load_db_from_file(dbpath, pwd)

        if not db.has_key(key_info):
            panic("File format error!")

    # Print the db info.
    print ">> file: %s" % (dbpath)
    print "Created: %s" % (db[key_info]["create"])
    if db[key_info].has_key("update"):
        print "Updated: %s" % (db[key_info]["update"])
    print ""

    # Tune the C-u
    readline.parse_and_bind(r"\C-u: kill-whole-line")

    # Main loop.
    while True:

        # Get the input command.
        try:
            cmd = get_non_empty_raw_input_unsafe("Command (m for help): ")
        except:
            sys.exit(0)

        # Print
        if cmd.startswith("p"):
            args = cmd.split()

            if args[0] == "p":
                if len(args) == 1:
                    print_db(db)
                elif len(args) == 2:
                    print_db(db, args[1])
                elif len(args) == 3:
                    if args[2] == "show":
                        print_db(db, args[1], show=True)
                    elif args[2] == "copy":
                        print_db(db, args[1], copy=True)
                    else:
                        info("%s: invalid input." % (args[2]))

            elif args[0] == "pid":
                if len(args) == 1:
                    print_db(db)
                elif len(args) == 2:
                    print_id_db(db, int(args[1]))
                elif len(args) == 3:
                    if args[2] == "show":
                        print_id_db(db, int(args[1]), show=True)
                    elif args[2] == "copy":
                        print_id_db(db, int(args[1]), copy=True)
                    else:
                        info("%s: invalid input." % (args[2]))
            else:
                info("%s: unknown command." % (cmd))

        # Delete.
        elif cmd == "d":
            id = get_non_empty_raw_input("[id]: ")
            id = int(id)

            if check_user_input_id(db, id):
                del db[key_data][id]
            else:
                print "invalid id (%d)." % (id)

        # Debug.
        elif cmd == "debug":
            while True:
                try:
                    # Get the input command.
                    debugcmd = get_non_empty_raw_input_unsafe("Command (#): ")
                    try:
                        exec(debugcmd)
                    except:
                        info("%s: invalid input." % (debugcmd))
                except:
                    print ""
                    break

        # Edit.
        elif cmd == "e":

            # user input id
            id = get_non_empty_raw_input("[id]: ")
            id = int(id)

            if check_user_input_id(db, id):

                op = get_non_empty_raw_input("[c/u/p/t]: ")
                if op in ("c", "u", "p", "t"):
                    if op == "c":
                        value = get_non_empty_raw_input("[caption]: ")
                    elif op == "u":
                        value = get_non_empty_raw_input("[username]: ")
                    elif op == "p":
                        value = get_non_empty_password()
                    else:
                        value = get_non_empty_raw_input("[text]: ")

                    # update the values
                    db[key_data][id][op] = value

                else:
                    info("%s: invalid input." % (op))
            else:
                info("invalid id (%d)." % (id))

        # Export.
        elif cmd.startswith("export"):
            args = cmd.split()
            if args[0] == "export" and len(args) == 2:
                export_to_file(db, args[1])
            else:
                info("%s: unknown command." % (cmd))

        # Import.
        elif cmd.startswith("import"):
            args = cmd.split()
            if args[0] == "import" and len(args) == 2:
                import_from_file(db, args[1])
            else:
                info("%s: unknown command." % (cmd))

        # New.
        elif cmd == "n":
            c = get_non_empty_raw_input("[caption]: ")
            u = get_non_empty_raw_input("[username]: ")
            p = get_non_empty_password()
            t = get_non_empty_raw_input("[text]: ")

            add_new_item(db, c, u, p, t)

        # Help.
        elif cmd == "m":
            print_command_usage()

        # Quit.
        elif cmd == "q":
            sys.exit(0)

        # Write.
        elif cmd == "w":
            save_db_to_file(db, dbpath, pwd)
            sys.exit(0)

        # Change the main password.
        elif cmd == "X":
            pwd = get_non_empty_password()

        # Unknown command.
        else:
            info("%s: unknown command." % (cmd))

if __name__ == "__main__":
    main()
