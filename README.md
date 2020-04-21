## Information:
This is a super simple unix password cracker developed in a day after initally reading [TJ O'Connor's Violent Python](https://www.amazon.co.uk/Violent-Python-Cookbook-Penetration-Engineers/dp/1597499579). A simplistic, threaded python version is also provided.

## Setup:
* Must be using a UNIX system with [GNU libc (glibc)](https://www.gnu.org/software/libc/).
* Write a new temporary user with a known pass-phrase within 'src/wordlist.txt' using `sudo useradd <username>`.

## Running:
1. Pull from github.
2. Compile using `gcc crypt_example.c -lnsl -lcrypt -o crypt`
3. Run `sudo ./crypt "<username>"`
