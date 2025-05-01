#!/usr/bin/env python3
import os
import sys
import argparse
import time
import uuid
import datetime
from blockchain import Blockchain, OWNERS_PW  # Import OWNERS_PW from blockchain

# Persistence file path (or override via env)
CHAIN_FILE = os.getenv('BCHOC_FILE_PATH', 'chain.dat')
# Creator password
CREATOR_PW = os.getenv('BCHOC_PASSWORD_CREATOR')

def handle_init(args):
    # Initialize or validate the genesis block
    if os.path.exists(CHAIN_FILE):
        bc = Blockchain(CHAIN_FILE)
        gen = bc.chain[0] if bc.chain else None
        if not gen or gen.timestamp != 0 or gen.prev_hash != b"\x00" * 32:
            print("> Invalid genesis block")
            sys.exit(1)
        print("> Blockchain file found with INITIAL block.")
    else:
        bc = Blockchain(CHAIN_FILE)
        bc.create_genesis()
        bc.save()
        print("> Blockchain file not found. Created INITIAL block.")
    return bc


def handle_add(args):
    if args.password != CREATOR_PW:
        print("> Invalid password")
        sys.exit(1)
    bc = Blockchain(CHAIN_FILE)
    if not os.path.exists(CHAIN_FILE) or not bc.chain:
        bc.create_genesis()
        bc.save()
    try:
        case_hex = uuid.UUID(args.case_id).hex
    except Exception:
        case_hex = args.case_id.replace('-', '')
    for iid in args.item_id:
        if bc.exists(iid):
            print("> Duplicate item ID")
            sys.exit(1)
    for iid in args.item_id:
        blk = bc.add(
            case_id=case_hex,
            evidence_id=iid,
            state="CHECKEDIN",
            creator=args.creator,
            owner=args.creator,
            data="Added to chain"
        )
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(blk.timestamp))
        print(f"> Added item: {iid}")
        print("> Status: CHECKEDIN")
        print(f"> Time of action: {ts}")
    bc.save()
    return bc


def handle_checkout(args):
    bc = Blockchain(CHAIN_FILE)
    try:
        new_blk = bc.checkout(evidence_id=args.item_id, password=args.password)
    except Exception as e:
        print(f"> {e}")
        sys.exit(1)
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(new_blk.timestamp))
    try:
        case_str = str(uuid.UUID(new_blk.case_id))
    except Exception:
        case_str = new_blk.case_id
    print(f"> Case: {case_str}")
    print(f"> Checked out item: {args.item_id}")
    print("> Status: CHECKEDOUT")
    print(f"> Time of action: {ts}")
    return bc


def handle_checkin(args):
    bc = Blockchain(CHAIN_FILE)
    try:
        new_blk = bc.checkin(evidence_id=args.item_id, password=args.password)
    except Exception as e:
        print(f"> {e}")
        sys.exit(1)
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(new_blk.timestamp))
    try:
        case_str = str(uuid.UUID(new_blk.case_id))
    except Exception:
        case_str = new_blk.case_id
    print(f"> Case: {case_str}")
    print(f"> Checked in item: {args.item_id}")
    print("> Status: CHECKEDIN")
    print(f"> Time of action: {ts}")
    return bc


def handle_show_cases(args):
    bc = Blockchain(CHAIN_FILE)
    for cid in bc.show_cases():
        print(cid)
    return bc


def handle_show_items(args):
    bc = Blockchain(CHAIN_FILE)
    try:
        case_hex = uuid.UUID(args.case_id).hex
    except Exception:
        case_hex = args.case_id.replace('-', '')
    for eid, _ in bc.show_items(case_id=case_hex):
        print(eid)
    return bc


def handle_show_history(args):
    bc = Blockchain(CHAIN_FILE)
    try:
        if args.password not in OWNERS_PW:
            print("> Invalid password")
            sys.exit(1)
        # Prepare filters
        key_case = args.case_id.replace('-', '') if args.case_id else None
        key_item = str(args.item_id) if args.item_id else None
        # Collect matching blocks
        blocks = []
        for blk in bc.chain:
            if (key_case is None or blk.case_id == key_case) and \
               (key_item is None or blk.evidence_id == key_item):
                blocks.append(blk)
        # Apply reverse if requested
        if args.reverse:
            blocks = list(reversed(blocks))
        # Limit number of entries if requested
        if args.num_entries is not None:
            blocks = blocks[:args.num_entries]
        # Print each block in full detail
        for idx, blk in enumerate(blocks):
            # Format case UUID with dashes
            try:
                case_str = str(uuid.UUID(blk.case_id))
            except Exception:
                case_str = blk.case_id
            print(f"> Case: {case_str}")
            # Use single '0' for INITIAL block evidence ID
            evid_str = '0' if blk.state == 'INITIAL' else blk.evidence_id
            print(f"> Item: {evid_str}")
            print(f"> Action: {blk.state}")
            # Format timestamp with microseconds
            dt = datetime.datetime.utcfromtimestamp(blk.timestamp)
            ts = dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            print(f"> Time: {ts}")
            if idx < len(blocks) - 1:
                print()
    except Exception as e:
        print(f"> {e}")
        sys.exit(1)
    return bc


def handle_summary(args):
    bc = Blockchain(CHAIN_FILE)
    formatted = args.case_id
    try:
        case_hex = uuid.UUID(args.case_id).hex
    except Exception:
        case_hex = args.case_id.replace('-', '')
    total, cin, cout, disp, dest, rel = bc.summary(case_id=case_hex)
    print(f"Case Summary for Case ID: {formatted}")
    print(f"Total Evidence Items: {total}")
    print(f"Checked In: {cin}")
    print(f"Checked Out: {cout}")
    print(f"Disposed: {disp}")
    print(f"Destroyed: {dest}")
    print(f"Released: {rel}")
    return bc


def handle_remove(args):
    bc = Blockchain(CHAIN_FILE)
    try:
        bc.remove(
            evidence_id=args.item_id,
            reason=args.why,
            password=args.password,
            owner=args.owner
        )
    except Exception as e:
        print(f"> {e}")
        sys.exit(1)
    return bc


def handle_verify(args):
    bc = Blockchain(CHAIN_FILE)
    ok = bc.verify()
    sys.exit(0 if ok else 1)


def parse_args():
    parser = argparse.ArgumentParser(prog='bchoc')
    subs = parser.add_subparsers(dest='cmd', required=True)

    subs.add_parser('init').set_defaults(func=handle_init)

    p = subs.add_parser('add')
    p.add_argument('-c', '--case_id', required=True)
    p.add_argument('-i', '--item_id', required=True, action='append', type=int)
    p.add_argument('-g', '--creator', required=True)
    p.add_argument('-p', '--password', required=True)
    p.set_defaults(func=handle_add)

    p = subs.add_parser('checkout')
    p.add_argument('-i', '--item_id', required=True, type=int)
    p.add_argument('-p', '--password', required=True)
    p.set_defaults(func=handle_checkout)

    p = subs.add_parser('checkin')
    p.add_argument('-i', '--item_id', required=True, type=int)
    p.add_argument('-p', '--password', required=True)
    p.set_defaults(func=handle_checkin)

    p_show = subs.add_parser('show')
    show_sub = p_show.add_subparsers(dest='show_cmd', required=True)

    sc = show_sub.add_parser('cases')
    sc.set_defaults(func=handle_show_cases)

    si = show_sub.add_parser('items')
    si.add_argument('-c', '--case_id', required=True)
    si.set_defaults(func=handle_show_items)

    sh = show_sub.add_parser('history')
    sh.add_argument('-c', '--case_id')
    sh.add_argument('-i', '--item_id', type=int)
    sh.add_argument('-n', '--num_entries', type=int)
    sh.add_argument('-r', '--reverse', action='store_true')
    sh.add_argument('-p', '--password', required=True)
    sh.set_defaults(func=handle_show_history)

    p = subs.add_parser('summary')
    p.add_argument('-c', '--case_id', required=True)
    p.set_defaults(func=handle_summary)

    p = subs.add_parser('remove')
    p.add_argument('-i', '--item_id', required=True, type=int)
    p.add_argument('-y', '--why', required=True, choices=['DISPOSED','DESTROYED','RELEASED'])
    p.add_argument('-o', '--owner')
    p.add_argument('-p', '--password', required=True)
    p.set_defaults(func=handle_remove)

    p = subs.add_parser('verify')
    p.set_defaults(func=handle_verify)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(args)


if __name__ == '__main__':
    main()