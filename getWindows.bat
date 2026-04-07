scp -i "C:\Users\skchqhdpdy\.ssh\oracle.key" "C:\godns\godns.go"  ubuntu@ns3.aodd.xyz:/home/ubuntu/
scp -i "C:\Users\skchqhdpdy\.ssh\oracle.key" "C:\godns\godns.exe" ubuntu@ns3.aodd.xyz:/home/ubuntu/
scp -i "C:\Users\skchqhdpdy\.ssh\oracle.key" "C:\godns\godns"     ubuntu@ns3.aodd.xyz:/home/ubuntu/
ssh -i "C:\Users\skchqhdpdy\.ssh\oracle.key" ubuntu@ns3.aodd.xyz "sudo chmod 777 /home/ubuntu/godns.go /home/ubuntu/godns.exe /home/ubuntu/godns"
pause