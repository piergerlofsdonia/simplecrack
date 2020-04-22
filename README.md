## Information:
This is a super simple unix password cracker developed in a day after initally reading [TJ O'Connor's Violent Python](https://www.amazon.co.uk/Violent-Python-Cookbook-Penetration-Engineers/dp/1597499579). A concurrent C and simplistic, threaded python version is also provided.

## Setup:
* Must be using a UNIX system with [GNU libc (glibc)](https://www.gnu.org/software/libc/).
* Write a new temporary user with a known pass-phrase within 'src/wordlist.txt' using `sudo useradd <username>`.

## Running:
1. Pull from github.
2. Compile using `gcc crypt_example.c -lnsl -lcrypt -o crypt`
3. (Optional) If using concurrent version, compile using `gcc crypt_example_concurrent.c -pthread -lnsl -lcrypt -o crypt`.
4. Run `sudo ./crypt "<username>"`
5. (Optional) Run a timed comparison between "crypt\_example" and "crypt\_example\_concurrent" using `date && sudo ./crypt <username> >/dev/null && date`

## Known Issues:
* The concurrent version has the potential to break if a password is in the last entries of the wordlist and the number of threads is greater than the number of lines remaining in the wordlist (_Added a TODO to fix this_). 
