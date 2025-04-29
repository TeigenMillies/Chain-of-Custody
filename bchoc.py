#!/usr/bin/env python3
import os
import sys
import argparse
import pickle
import time
from blockchain import Blockchain

# Persistence file path (or override via env)
CHAIN_FILE = os.getenv('BCHOC_FILE_PATH', 'chain.pkl')

# Load existing blockchain or create new
def load_chain() -> Blockchain:
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE, 'rb') as f:
            return pickle.load(f)
    return Blockchain()

# Save blockchain back to disk
def save_chain(bc: Blockchain):
    with open(CHAIN_FILE, 'wb') as f:
        pickle.dump(bc, f)

# Command handlers

def handle_init(args, bc):
    if os.path.exists(CHAIN_FILE):
        print("> Blockchain file found with INITIAL block.")
    else:
        bc = Blockchain()
        save_chain(bc)
        print("> Blockchain file not found. Created INITIAL block.")
    return bc


def handle_verify(args, bc):
    bc.verify()
    return bc


def handle_add(args, bc):
    for iid in args.item_id:
        bc.add(
            case_id=args.case_id,
            evidence_id=iid,
            state="CHECKEDIN",
            creator=args.creator,
            owner=args.creator,
            data="Added to chain"
        )
        blk = bc.chain[-1]
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(blk.timestamp))
        print(f"> Added item: {iid}")
        print("> Status: CHECKEDIN")
        print(f"> Time of action: {ts}")
    return bc


def handle_checkout(args, bc):
    bc.checkout(
        evidence_id=args.item_id,
        case_id=args.case_id,
        password=args.password
    )
    return bc


def handle_checkin(args, bc):
    bc.checkin(
        evidence_id=args.item_id,
        case_id=args.case_id,
        password=args.password
    )
    return bc


def handle_show_cases(args, bc):
    bc.show_cases(password=args.password)
    return bc


def handle_show_items(args, bc):
    # Display each unique item’s latest state for the given case
    latest_states = {}
    for blk in bc.chain:
        try:
            cid = bc.decrypt_data(blk.case_id)
        except Exception:
            cid = blk.case_id
        if cid == args.case_id:
            try:
                eid = bc.decrypt_data(blk.evidence_id)
            except Exception:
                eid = blk.evidence_id
            latest_states[eid] = blk.state
    for eid, state in latest_states.items():
        print(f"{eid}	{state}")
    return bc


def handle_show_history(args, bc):
    bc.show_history(
        case_id    = args.case_id,
        item_id    = args.item_id,
        num_entries= args.num_entries,
        reverse    = args.reverse,
        password   = args.password
    )
    return bc


def handle_summary(args, bc):
    bc.summary(case_id=args.case_id)
    return bc


def handle_remove(args, bc):
    bc.remove(
        evidence_id=args.item_id,
        password=args.password
    )
    return bc

# Argument parsing

def parse_args():
    parser = argparse.ArgumentParser(prog='bchoc')
    subs = parser.add_subparsers(dest='cmd', required=True)

    subs.add_parser('init').set_defaults(func=handle_init)
    subs.add_parser('verify').set_defaults(func=handle_verify)

    p = subs.add_parser('add')
    p.add_argument('-c','--case_id', required=True)
    p.add_argument('-i','--item_id', required=True, action='append', type=int)
    p.add_argument('-g','--creator', required=True)
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_add)

    p = subs.add_parser('checkout')
    p.add_argument('-c','--case_id', required=True)
    p.add_argument('-i','--item_id', required=True, type=int)
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_checkout)

    p = subs.add_parser('checkin')
    p.add_argument('-c','--case_id', required=True)
    p.add_argument('-i','--item_id', required=True, type=int)
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_checkin)

    p = subs.add_parser('show_cases')
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_show_cases)

    p = subs.add_parser('show_items')
    p.add_argument('-c','--case_id', required=True)
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_show_items)

    p = subs.add_parser('show_history')
    p.add_argument('-c','--case_id')
    p.add_argument('-i','--item_id', type=int)
    p.add_argument('-n','--num_entries', type=int)
    p.add_argument('-r','--reverse', action='store_true')
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_show_history)

    p = subs.add_parser('summary')
    p.add_argument('-c','--case_id')
    p.set_defaults(func=handle_summary)

    p = subs.add_parser('remove')
    p.add_argument('-i','--item_id', required=True, type=int)
    p.add_argument('-p','--password', required=True)
    p.set_defaults(func=handle_remove)

    return parser.parse_args()

# Main entry

def main():
    args = parse_args()
    bc = load_chain()
    try:
        bc = args.func(args, bc)
        save_chain(bc)
        sys.exit(0)
    except Exception as e:
        print(f"> {e}")
        sys.exit(1)

if __name__=='__main__':
    main()
