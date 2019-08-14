#! /bin/bash

echo
echo System info:
uname -a
echo
echo Verze samby:
samba --version
echo
echo Prihlaseny uzivatel:
whoami
echo
echo Uzivatele s pravy root a nobody
grep '^root\|^nobody' /etc/passwd
echo
echo Vypis slozky root
sudo ls -la /root
echo
