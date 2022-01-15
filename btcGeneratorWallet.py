import argparse
import hashlib
import os
from binascii import hexlify, unhexlify
from struct import Struct
from utils import g, b58encode, b58decode
import blockcypher
from moneywagon import AddressBalance
import requests
from urllib.request import urlopen
from urllib.request import Request
import satoshi
import re

PACKER = Struct(">QQQQ")


def count_leading_zeroes(s):
    count = 0
    for c in s:
        if c == "\0":
            count += 1
        else:
            break
    return count


def base58_check_encode(prefix, payload, compressed=False):
    # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    s = prefix + payload
    if compressed:
        s = prefix + payload + b"\x01"
    # Add the 4 checksum bytes at the end of extended RIPEMD-160 hash. This is the 25-byte binary Bitcoin Address.
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    return "1" * count_leading_zeroes(result) + b58encode(result).decode()


def pub_key_to_addr(s):
    ripemd160 = hashlib.new("ripemd160")
    hash_sha256 = hashlib.new("SHA256")
    # Perform SHA-256 hashing on the public key
    hash_sha256.update(bytes.fromhex(s))
    # Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160.update(hash_sha256.digest())
    return base58_check_encode(b"\0", ripemd160.digest())


def btcwb(number):
    number0 = number >> 192
    number1 = (number >> 128) & 0xFFFFFFFFFFFFFFFF
    number2 = (number >> 64) & 0xFFFFFFFFFFFFFFFF
    number3 = number & 0xFFFFFFFFFFFFFFFF

    private_key = hexlify(PACKER.pack(number0, number1, number2, number3)).decode(
        "utf-8"
    )

    ###############################################
    print("Converting from: " + str(int(private_key, 16)))
    ###############################################

    compressed_key = base58_check_encode(b"\x80", unhexlify(private_key), True)

    ###############################################
    print("Private key    : " + compressed_key)
    ###############################################

    # address
    x, y = str(g * int(private_key, 16)).split()
    len1 = len(x)
    len2 = len(y)
    if len1 != 64:
        z = 64 - len1
        x = "0" * z + x
    if len2 != 64:
        z = 64 - len2
        y = "0" * z + y
    compressed_public_key_with_out_prefix = x + y
    pk_prefix = "02"
    if not int(compressed_public_key_with_out_prefix[64:], 16) % 2 == 0:
        pk_prefix = "03"
    compressed_public_key = pk_prefix + compressed_public_key_with_out_prefix[:64]

    ###############################################

    print("Public key     : " + compressed_public_key)
    print("Bitcoin address: " + pub_key_to_addr(compressed_public_key))
    with open("wallet.txt", "a") as f:
        f.write(
            "Converting from: "
            + str(int(private_key, 16))
            + "\nPrivate key: "
            + compressed_key
            + "\nPublic key: "
            + compressed_public_key
            + "\nBitcoin address: "
            + pub_key_to_addr(compressed_public_key)
            + "\n#####################################################################\n\n\n\n"
        )


def int_to_address(number):
    number0 = number >> 192
    number1 = (number >> 128) & 0xFFFFFFFFFFFFFFFF
    number2 = (number >> 64) & 0xFFFFFFFFFFFFFFFF
    number3 = number & 0xFFFFFFFFFFFFFFFF

    private_key = hexlify(PACKER.pack(number0, number1, number2, number3)).decode(
        "utf-8"
    )

    ###############################################
    print("Converting from: " + str(int(private_key, 16)))
    ###############################################

    compressed_key = base58_check_encode(b"\x80", unhexlify(private_key), True)

    ###############################################
    print("Private key    : " + compressed_key)
    ###############################################

    # address
    x, y = str(g * int(private_key, 16)).split()
    len1 = len(x)
    len2 = len(y)
    if len1 != 64:
        z = 64 - len1
        x = "0" * z + x
    if len2 != 64:
        z = 64 - len2
        y = "0" * z + y
    compressed_public_key_with_out_prefix = x + y
    pk_prefix = "02"
    if not int(compressed_public_key_with_out_prefix[64:], 16) % 2 == 0:
        pk_prefix = "03"
    compressed_public_key = pk_prefix + compressed_public_key_with_out_prefix[:64]

    ###############################################

    print("Public key     : " + compressed_public_key)
    ###############################################

    ###############################################
    print("Bitcoin address: " + pub_key_to_addr(compressed_public_key))
    try:
        total = blockcypher.get_total_balance(pub_key_to_addr(compressed_public_key))
    except:
        total = AddressBalance().action("btc", pub_key_to_addr(compressed_public_key))
    total_fiat = satoshi.to_fiat(int(total))
    # r = requests.get("https://blockchain.infor/rawaddr/{}".format(pub_key_to_addr(compressed_public_key)))
    tr = Request(
        "https://blockchain.info/q/getreceivedbyaddress/"
        + pub_key_to_addr(compressed_public_key)
    )
    total_received = str(urlopen(tr).read())
    trr = total_received[2:][:-1]
    total_fiat_received = satoshi.to_fiat(int(trr))

    ts = Request(
        "https://blockchain.info/q/getsentbyaddress/"
        + pub_key_to_addr(compressed_public_key)
    )
    total_sent = str(urlopen(ts).read())
    tsr = total_sent[2:][:-1]
    total_fiat_sent = satoshi.to_fiat(int(tsr))
    # print('$'+str(s))
    print("Total Sent     : " + str(tsr) + " || $" + str(total_fiat_sent))
    print("Total Received : " + str(trr) + " || $" + str(total_fiat_received))
    print("Final Balance  : " + str(total) + " || $" + str(total_fiat) + "\n")
    # stotal = blockcypher.from_satoshis(total, 'btc')
    with open("walletb.txt", "a") as f:
        f.write(
            "Converting from: "
            + str(int(private_key, 16))
            + "\nPrivate key: "
            + compressed_key
            + "\nPublic key: "
            + compressed_public_key
            + "\nBitcoin address: "
            + pub_key_to_addr(compressed_public_key)
            + "\nFianl Balance: "
            + str(total)
            + "\nTotal Received : "
            + str(trr)
            + " || $"
            + str(total_fiat_received)
            + "\nTotal Sent     : "
            + str(tsr)
            + " || $"
            + str(total_fiat_sent)
            + "\n#####################################################################\n\n\n\n"
        )
    if 0 < total:
        print(pub_key_to_addr(compressed_public_key) + " : " + total)
        with open("wallet_with_money.txt", "a") as m:
            m.write(
                "Converting from: "
                + str(int(private_key, 16))
                + "\nPrivate key: "
                + compressed_key
                + "\nPublic key: "
                + compressed_public_key
                + "\nBitcoin address: "
                + pub_key_to_addr(compressed_public_key)
                + "\nBitcoin Balance: "
                + str(total)
                + "\n#####################################################################\n\n\n\n"
            )
    else:
        pass
    ###############################################


def wif_to_key(wif):
    slicer = 4
    if wif[0] in ["K", "L"]:
        slicer = 5
    return hexlify(b58decode(wif)[1:-slicer]).decode("utf-8")


def main():
    try:
        os.system(r"cls")
    except:
        os.system(r"clear")
    print(
        """
 ____ _____ ____  __        __    _ _      _      ____                           _             
| __ )_   _/ ___| \ \      / /_ _| | | ___| |_   / ___| ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
|  _ \ | || |      \ \ /\ / / _` | | |/ _ \ __| | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
| |_) || || |___    \ V  V / (_| | | |  __/ |_  | |_| |  __/ | | |  __/ | | (_| | || (_) | |   
|____/ |_| \____|    \_/\_/ \__,_|_|_|\___|\__|  \____|\___|_| |_|\___|_|  \__,_|\__\___/|_|  
    Author    : Mohammadreza (MMDRZA.COM)
    Github    : https://mmdrza.com                                                                                                                                                                                                    
[1] Generate a List of Wallets with a Range [with Balances]
[2] Generate a List of Wallets with a Range [without Balances]
[3] Guess a Number List to Generate a Wallet
'q' for quit
	 """
    )

    x = input(">>> ")
    if x == "q":
        try:
            quit()
        except:
            exit()
    elif x == "1":
        r1 = int(input("Input Starting Range :> "))
        r2 = int(input("Input Ending Range   :> "))
        for x in range(r1, r2):
            int_to_address(x)
    elif x == "2":
        r1 = int(input("Input Starting Range :> "))
        r2 = int(input("Input Ending Range   :> "))
        for x in range(r1, r2):
            btcwb(x)
    elif x == "3":
        print("Enter your lucky number in the following format:")
        print("ex: 1 2 456 788 123 657 11 66 234 68 23\n")
        array = map(int, input("Enter Numbers by Keeping Space : ").split())
        for i in array:
            int_to_address(i)
            i += 1
    else:
        print("Command not Recognized")


main()
