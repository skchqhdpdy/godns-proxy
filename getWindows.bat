scp -i "C:\Users\skchqhdpdy\.ssh\oracle.key" "C:\godns\godns.go"  ubuntu@ns3.aodd.xyz:/home/ubuntu/
scp -i "C:\Users\skchqhdpdy\.ssh\oracle.key" "C:\godns\godns.exe" ubuntu@ns3.aodd.xyz:/home/ubuntu/
scp -i "C:\Users\skchqhdpdy\.ssh\oracle.key" "C:\godns\godns"     ubuntu@ns3.aodd.xyz:/home/ubuntu/
ssh -i "C:\Users\skchqhdpdy\.ssh\oracle.key" ubuntu@ns3.aodd.xyz "sudo mv /home/ubuntu/godns.go /etc/godns/godns.go && sudo mv /home/ubuntu/godns.exe /etc/godns/godns.exe && sudo mv /home/ubuntu/godns /etc/godns/godns && sudo chmod 777 /etc/godns/godns.go /etc/godns/godns.exe /etc/godns/godns"
pause
