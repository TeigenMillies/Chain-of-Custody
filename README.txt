Chain of Custody Blockchain Project

Names:
Teigen Millies - 1221276667
Sisir Doppalapudy - 1224798042
Zakary Cea - 1214468021

How it works:
This program is a blockchain based chain of custody system used to track a piece of evidence throughout it's entire lifecycle. By using a cryptographically linked list of transactions or blocks by using a SHA-256 hash linking,
our program ensures that a piece of evidence is traceable at every point. Only specidic roles will be able to perform actions to a piece of evidence given you have the right password. To ensure case ids and evidence ids are encrypted an AES encryption
is used to store the information encrypted. If any of the blocks are changed then verify will detect the mismatch in hash links. 

To start a new blockchain we initialize with
./bchoc init

To check in or add a piece of evidence you will use
./bchoc add -c <case_id> -i <item_id> -g <creator_name> -p <creator_password>

Evidence can only be checked out or back in by authorized people with the password by using 
./bchoc checkout -i <item_id> -p <role_password>
./bchoc checkin  -i <item_id> -p <role_password>

Evidence can be removed by using
./bchoc remove -i <item_id> -y <reason> -o <owner_role> -p <creator_password>

In order to see all actions done to a case or item use
./bchoc show history -c <case_id> -i <item_id> -p <role_password>

Summarize item counts with 
./bchoc summary -c <case_id>

Ensure the blockchain is still correctly liked and valid with 
./bchoc verify
