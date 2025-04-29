import argparse #for parsing arguments
import uuid
import hashlib
import time
from Crypto.Cipher import AES #for encryption and decryption
from Crypto.Util.Padding import pad, unpad #padding for hash
import os

AES_KEY = b"R0chLi4uLi4uLi4="

class Block: #Block class to show every data/info for a block in the chain
    def __init__(self, prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data, data_length): #initalizing all parameters in the block
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data = data
        self.data_length = data_length
        self.hash = self.hash_calculate()

    def hash_calculate(self):
        #retrives data from the block and calculates the hash in hex, then returns it
        block_info = f"{self.prev_hash}{self.timestamp}{self.case_id}{self.evidence_id}{self.state}{self.creator}{self.owner}{self.data}{self.data_length}".encode('utf-8')
        return hashlib.sha256(block_info).hexdigest()


# Blockchain class to handle all operations of blockchain
class Blockchain: #sanity check
    def __init__(self):
        self.chain = []
        self.generate_genesis_block()

    def generate_genesis_block(self):
        #Creates the first block
        genesis_block = Block(
            prev_hash="0" * 64,  #Genesis block has no previous hash so default to 64 bytes
            timestamp=int(time.time()),
            case_id=self.encrypt_data("0" * 32),  #Encrypt case ID (UUID), default to 32 bytes
            evidence_id=self.encrypt_data("0" * 32),  
            state="INITIAL", 
            creator="0" * 12,  #padded with 12 zeros
            owner="0" * 12,  
            data="Initial block",
            data_length=14  # Length of the data
        )
        self.chain.append(genesis_block)

    def encrypt_data(self, data): #encryption Function
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        return cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

    def decrypt_data(self, encrypted_data): #decryption function
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-8')
        return decrypted

    def add(self, case_id, evidence_id, state, creator, owner, data): #adds new block in the chain
        prev_block = self.chain[-1] #Redirects from previous block
        new_block = Block(
            #Each parameter is set to itself when a new block with new data is added in the chain
            prev_hash=prev_block.hash,
            timestamp=int(time.time()),
            case_id=self.encrypt_data(case_id),
            evidence_id=self.encrypt_data(str(evidence_id)),
            state=state,
            creator=creator,
            owner=owner,
            data=data,
            data_length=len(data)
        )
        self.chain.append(new_block) #data is appened after being added

    def show_cases(self):
        print("List of every cases:")
        cases = set()
        for block in self.chain: #for loop is used to ensure all cases are shown
            case_id = self.decrypt_data(block.case_id)
            cases.add(case_id)
        for case_id in cases:
            print(f"Case ID: {case_id}")

    def show_items(self, case_id): #same as above but for the items in the chain
        print(f"Items for Case {case_id}:")
        for block in self.chain:
            if self.decrypt_data(block.case_id) == case_id:
                print(f"Evidence ID: {self.decrypt_data(block.evidence_id)}, State: {block.state}")

    def validate_password(self, password, block):
        #Checks if the password matches either the creator or the owner of the block/item
        valid_passwords = [os.getenv(f'BCHOC_PASSWORD_{role.upper()}') for role in ['creator', 'owner']]
        if password not in valid_passwords: #returns false if password doesn't match
            print(f"Invalid password or you don't have permission to perform this command.")
            return False
        return True

    def checkin(self, evidence_id, case_id, password):
        for block in self.chain:
            if block.evidence_id == self.encrypt_data(str(evidence_id)) and block.state == "CHECKEDOUT":
                if not self.validate_password(password, block):
                    return

                #Adds check-in block if password is validated
                self.add_block(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    state="CHECKEDIN",
                    creator=block.creator,
                    owner=block.owner,
                    data="Evidence checked in"
                )
                print(f"Item {evidence_id} has been checked in.")
                return
        print(f"Item can not be found or not in CHECKEDOUT state.")

    def checkout(self, evidence_id, case_id, password):
        for block in self.chain:
            if block.evidence_id == self.encrypt_data(str(evidence_id)) and block.state == "CHECKEDIN":
                if not self.validate_password(password, block):
                    return

                #Adds checkout block if password is validated
                self.add_block(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    state="CHECKEDOUT",
                    creator=block.creator,
                    owner=block.owner,
                    data="Evidence checked out"
                )
                print(f"Item {evidence_id} has been checked out.")
                return
        print(f"Item can not be found or not in CHECKEDIN state.")

    def remove(self, evidence_id, password):
        for block in self.chain:
            if block.evidence_id == self.encrypt_data(str(evidence_id)):
                if not self.validate_password(password, block):
                    return

                #Marks the evidence item as removed is password isn't validated
                block.state = "REMOVED"
                print(f"Item {evidence_id} was removed.")
                return
        print(f"Item {evidence_id} was not found.")

    def verify(self):
        print("Verifying the blockchain integrity...")
        for i in range(1, len(self.chain)): #checks all cases in the chain for integrety of blockchain
            prev_block = self.chain[i-1]
            curr_block = self.chain[i]
            #Checks to ensure the current block's previous hash matches the previous block's hash
            if curr_block.prev_hash != prev_block.hash:
                print(f"Blockchain is corrupted at block {i}.")
                return
        print("Blockchain is verified and intact.") #prints of blockchain is not corrupted

    def summary(self): #summarizes state of blockchain and it's states
        state_counts = {"CHECKEDIN": 0, "CHECKEDOUT": 0, "REMOVED": 0, "INITIAL": 0}
        unique_item_ids = set()
        for block in self.chain:
            state_counts[block.state] += 1
            unique_item_ids.add(self.decrypt_data(block.evidence_id))

        print("Blockchain Summary:")
        print(f"Unique Item IDs: {len(unique_item_ids)}")
        for state, count in state_counts.items():
            print(f"State {state}: {count} items")


#Command handling functions
def handle_show_cases(args, blockchain):
    blockchain.show_cases()

def handle_show_items(args, blockchain):
    blockchain.show_items(args.case_id)

def handle_remove(args, blockchain):
    blockchain.remove(args.item_id, args.password)

def handle_verify(args, blockchain):
    blockchain.verify()

def handle_summary(args, blockchain):
    blockchain.summary()


# Argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="Blockchain Chain of Custody")
    subparsers = parser.add_subparsers(help="Commands")

    #Show Cases parser
    show_cases_parser = subparsers.add_parser('show_cases', help="Show all cases in blockchain")
    show_cases_parser.set_defaults(func=handle_show_cases)

    #Show Items parser
    show_items_parser = subparsers.add_parser('show_items', help="Show items for a case")
    show_items_parser.add_argument('-c', '--case_id', required=True, help="Case ID")
    show_items_parser.set_defaults(func=handle_show_items)

    #Remove command parser
    remove_parser = subparsers.add_parser('remove', help="Remove an item")
    remove_parser.add_argument('-i', '--item_id', required=True, type=int, help="Item ID")
    remove_parser.add_argument('-p', '--password', required=True, help="Password")
    remove_parser.set_defaults(func=handle_remove)

    #Verify Blockchain parser
    verify_parser = subparsers.add_parser('verify', help="Verify blockchain integrity")
    verify_parser.set_defaults(func=handle_verify)

    #Summary command parser
    summary_parser = subparsers.add_parser('summary', help="Show blockchain summary")
    summary_parser.set_defaults(func=handle_summary)

    return parser


# Main function to parse arguments and call the appropriate function
def main():
    #calls the blockchain class, arguments, and parsers for handiling
    blockchain = Blockchain()
    parser = parse_arguments()
    args = parser.parse_args()
    args.func(args, blockchain)


if __name__ == "__main__":
    main()

