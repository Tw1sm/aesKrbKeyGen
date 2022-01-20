#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
import argparse


# Constants
AES256_CONSTANT = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4]
AES128_CONSTANT = AES256_CONSTANT[:16]
IV = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
ITERATION = 4096 # Active Directory default


def do_aes_256(aes_256_pbkdf2):
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_1 = cipher.encrypt(bytes(AES256_CONSTANT))
    
    cipher = AES.new(aes_256_pbkdf2, AES.MODE_CBC, bytes(IV))
    key_2 = cipher.encrypt(bytearray(key_1))
    
    aes_256_raw = key_1[:16] + key_2[:16]
    return aes_256_raw.hex().upper()


def do_aes_128(aes_128_pbkdf2):
    cipher = AES.new(aes_128_pbkdf2, AES.MODE_CBC, bytes(IV))
    aes_128_raw = cipher.encrypt(bytes(AES128_CONSTANT))
    return aes_128_raw.hex().upper()


def main():
    parser = argparse.ArgumentParser(description='Generate AES128/256 Kerberos keys for an AD account using a plaintext password', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-domain', type=str, help='FQDN', required=True)
    parser.add_argument('-user', type=str, help='sAMAccountName - this is case sensitive for AD user accounts', required=True)
    parser.add_argument('-pass', type=str, dest='password', help='Valid cleartext account password', required=True)
    parser.add_argument('-host', action='store_true', help='Target is a computer account', required=False)

    args = parser.parse_args()

    domain = args.domain.upper()
    if args.host:
        host = args.user.replace('$', '') # ensure $ is not present in hostname
        salt = f'{domain}host{host}.{domain.lower()}'
    else:
        salt = f'{domain}{args.user}'

    print(f'[*] Salt: {salt}')    

    password_bytes = args.password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    aes_256_pbkdf2 = KDF.PBKDF2(password_bytes, salt_bytes, 32, ITERATION)
    aes_128_pbkdf2 = aes_256_pbkdf2[:16]

    
    aes_256_key = do_aes_256(aes_256_pbkdf2)
    aes_128_key = do_aes_128(aes_128_pbkdf2)
    
    print()
    print(f'[+] AES256 Key: {aes_256_key}')
    print(f'[+] AES128 Key: {aes_128_key}')
    

if __name__ == '__main__':
    main()
