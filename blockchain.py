import os
import struct
import time
import hashlib
from Crypto.Cipher import AES

# Password roles loaded via env
CREATOR_PW = os.getenv('BCHOC_PASSWORD_CREATOR')
OWNERS_PW = [
    os.getenv('BCHOC_PASSWORD_CREATOR'),
    os.getenv('BCHOC_PASSWORD_LAWYER'),
    os.getenv('BCHOC_PASSWORD_POLICE'),
    os.getenv('BCHOC_PASSWORD_ANALYST'),
    os.getenv('BCHOC_PASSWORD_EXECUTIVE'),
]

# Little-endian, no padding between fields; timestamp as IEEE 754 double
HEADER_FMT = '<32sd32s32s12s12s12sI'
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# AES key for ECB encryption (ASCII bytes)
AES_KEY = b"R0chLi4uLi4uLi4="


def pad_bytes(b: bytes, length: int) -> bytes:
    if len(b) > length:
        return b[:length]
    return b + b'\x00' * (length - len(b))


class Block:
    def __init__(self, prev_hash, timestamp, case_id, evidence_id,
                 state, creator, owner, data):
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id      # raw ID (hex string for case, decimal string for evidence)
        self.evidence_id = evidence_id
        self.state = state
        self.creator = creator
        self.owner = owner or ''
        # Data handling: no extra data for normal operations
        self.data = data or ''
        # D_length: include null only if data present
        if self.data:
            self.data_length = len(self.data.encode()) + 1
        else:
            self.data_length = 0

    def pack(self) -> bytes:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        # Case ID field
        if self.state == 'INITIAL':
            case_src = self.case_id.encode()
            case_bytes = pad_bytes(case_src, 32)
        else:
            case_hex = self.case_id.replace('-', '')
            raw_case = bytes.fromhex(case_hex)
            enc_case = cipher.encrypt(raw_case)
            enc_hex = enc_case.hex().encode()
            case_bytes = pad_bytes(enc_hex, 32)
        # Evidence ID field
        if self.state == 'INITIAL':
            evid_src = self.evidence_id.encode()
            evid_bytes = pad_bytes(evid_src, 32)
        else:
            ev_int = int(self.evidence_id)
            raw_evi = b'\x00' * 12 + struct.pack('>I', ev_int)
            enc_evi = cipher.encrypt(raw_evi)
            enc_hex = enc_evi.hex().encode()
            evid_bytes = pad_bytes(enc_hex, 32)
        state_bytes = pad_bytes(self.state.encode(), 12)
        creator_bytes = pad_bytes(self.creator.encode(), 12)
        owner_bytes = pad_bytes(self.owner.encode(), 12)
        if self.data_length > 0:
            data_bytes = self.data.encode() + b'\x00'
        else:
            data_bytes = b''
        header = struct.pack(
            HEADER_FMT,
            self.prev_hash,
            float(self.timestamp),
            case_bytes,
            evid_bytes,
            state_bytes,
            creator_bytes,
            owner_bytes,
            self.data_length
        )
        return header + data_bytes

    @classmethod
    def unpack(cls, buf: bytes) -> 'Block':
        hdr = buf[:HEADER_SIZE]
        fields = struct.unpack(HEADER_FMT, hdr)
        prev_hash = fields[0]
        timestamp = fields[1]
        case_bytes = fields[2]
        evid_bytes = fields[3]
        state_bytes = fields[4]
        creator_bytes = fields[5]
        owner_bytes = fields[6]
        data_length = fields[7]
        data_bytes = buf[HEADER_SIZE:HEADER_SIZE + data_length]
        raw_case_hex = case_bytes.rstrip(b'\x00')
        raw_evid_hex = evid_bytes.rstrip(b'\x00')
        state = state_bytes.rstrip(b'\x00').decode()
        creator = creator_bytes.rstrip(b'\x00').decode()
        owner = owner_bytes.rstrip(b'\x00').decode()
        data = data_bytes.rstrip(b'\x00').decode()
        if state == 'INITIAL':
            case_id = raw_case_hex.decode()
            evidence_id = raw_evid_hex.decode()
        else:
            cipher = AES.new(AES_KEY, AES.MODE_ECB)
            enc_case = bytes.fromhex(raw_case_hex.decode())
            dec_case = cipher.decrypt(enc_case)
            case_id = dec_case.hex()
            enc_evi = bytes.fromhex(raw_evid_hex.decode())
            dec_evi = cipher.decrypt(enc_evi)
            ev_int = struct.unpack('>I', dec_evi[-4:])[0]
            evidence_id = str(ev_int)
        return cls(prev_hash, timestamp, case_id, evidence_id,
                   state, creator, owner, data)


class Blockchain:
    def __init__(self, path: str):
        self.path = path
        self.chain = []
        if os.path.exists(self.path):
            self.load()

    def create_genesis(self) -> Block:
        zero32 = '0' * 32
        genesis = Block(
            prev_hash=b'\x00' * 32,
            timestamp=time.time(),
            case_id=zero32,
            evidence_id=zero32,
            state='INITIAL',
            creator='',
            owner='',
            data='Initial block'
        )
        self.chain = [genesis]
        return genesis

    def load(self) -> None:
        with open(self.path, 'rb') as f:
            raw = f.read()
        offset = 0
        self.chain = []
        while offset + HEADER_SIZE <= len(raw):
            hdr = raw[offset:offset + HEADER_SIZE]
            data_length = struct.unpack(HEADER_FMT, hdr)[7]
            block_buf = raw[offset:offset + HEADER_SIZE + data_length]
            blk = Block.unpack(block_buf)
            self.chain.append(blk)
            offset += HEADER_SIZE + data_length

    def save(self) -> None:
        with open(self.path, 'wb') as f:
            for blk in self.chain:
                f.write(blk.pack())

    def exists(self, evidence_id) -> bool:
        key = str(evidence_id)
        return any(b.evidence_id == key for b in self.chain)

    def add(self, case_id, evidence_id, state, creator, owner, data) -> Block:
        case_hex = case_id.replace('-', '')
        if not self.chain:
            self.create_genesis()
        prev = self.chain[-1]
        new_block = Block(
            prev_hash=hashlib.sha256(prev.pack()).digest(),
            timestamp=time.time(),
            case_id=case_hex,
            evidence_id=str(evidence_id),
            state=state,
            creator=creator,
            owner='',
            data=''
        )
        self.chain.append(new_block)
        return new_block

    def checkout(self, evidence_id, password):
        key = str(evidence_id)
        blk = next((b for b in reversed(self.chain) if b.evidence_id == key), None)
        if not blk or blk.state != 'CHECKEDIN':
            raise Exception("Cannot checkout: not in CHECKEDIN state or not found.")
        if password not in OWNERS_PW:
            raise Exception("Invalid password")
        new = self.add(blk.case_id, key, 'CHECKEDOUT', blk.creator, '', '')
        self.save()
        return new

    def checkin(self, evidence_id, password):
        key = str(evidence_id)
        blk = next((b for b in reversed(self.chain) if b.evidence_id == key), None)
        if not blk or blk.state != 'CHECKEDOUT':
            raise Exception("Cannot checkin: not in CHECKEDOUT state or not found.")
        if password not in OWNERS_PW:
            raise Exception("Invalid password")
        new = self.add(blk.case_id, key, 'CHECKEDIN', blk.creator, '', '')
        self.save()
        return new

    def show_cases(self) -> list:
        return sorted({blk.case_id for blk in self.chain[1:]})

    def show_items(self, case_id) -> list:
        latest = {}
        for blk in self.chain:
            if blk.case_id == case_id:
                latest[blk.evidence_id] = blk.state
        return sorted(latest.items())

    def show_history(self, case_id=None, item_id=None, num_entries=None, reverse=False, password=None):
        if password and password not in OWNERS_PW:
            raise Exception("Invalid password")
        key_case = case_id.replace('-', '') if case_id else None
        key_item = str(item_id) if item_id else None
        entries = []
        for blk in self.chain:
            if (key_case is None or blk.case_id == key_case) and (key_item is None or blk.evidence_id == key_item):
                entries.append(f"{int(blk.timestamp)}\t{blk.state}")
        if reverse:
            entries = list(reversed(entries))
        if num_entries is not None:
            entries = entries[:num_entries]
        return entries

    def remove(self, evidence_id, reason, password, owner=None):
        key = str(evidence_id)
        blk = next((b for b in reversed(self.chain) if b.evidence_id == key), None)
        if not blk:
            raise Exception("Item not found.")
        if blk.state != 'CHECKEDIN':
            raise Exception("Cannot remove: item not CHECKEDIN")
        if password != CREATOR_PW:
            raise Exception("Invalid password")
        new = self.add(blk.case_id, key, reason, blk.creator, owner or '', '')
        self.save()
        return new

    def verify(self) -> bool:
        if not self.chain or self.chain[0].timestamp != 0 or self.chain[0].prev_hash != b'\x00'*32:
            return False
        for prev_blk, curr_blk in zip(self.chain, self.chain[1:]):
            if curr_blk.prev_hash != hashlib.sha256(prev_blk.pack()).digest():
                return False
        return True

    def summary(self, case_id) -> list:
        related = [b for b in self.chain if b.case_id == case_id.replace('-', '')]
        unique_ids = set(b.evidence_id for b in related)
        counts = {s: 0 for s in ['CHECKEDIN','CHECKEDOUT','DISPOSED','DESTROYED','RELEASED']}
        for b in related:
            if b.state in counts:
                counts[b.state] += 1
        return [
            str(len(unique_ids)),
            str(counts['CHECKEDIN']),
            str(counts['CHECKEDOUT']),
            str(counts['DISPOSED']),
            str(counts['DESTROYED']),
            str(counts['RELEASED']),
        ]
