import argparse
from signer import generate_keys, sign_message, verify_signature

def main():
    parser = argparse.ArgumentParser(description="Simple Digital Signature System")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser("gen-key", help="Generate RSA key pair")
    gen.add_argument("--size", type=int, default=2048)
    gen.add_argument("--private", type=str, default="private_key.pem")
    gen.add_argument("--public", type=str, default="public_key.pem")

    sign = subparsers.add_parser("sign", help="Sign a message")
    sign.add_argument("--key", required=True)
    sign.add_argument("--infile", required=True)
    sign.add_argument("--out", default="signature.sig")

    verify = subparsers.add_parser("verify", help="Verify a signature")
    verify.add_argument("--key", required=True)
    verify.add_argument("--infile", required=True)
    verify.add_argument("--sig", required=True)

    args = parser.parse_args()

    if args.command == "gen-key":
        generate_keys(args.private, args.public, args.size)
    elif args.command == "sign":
        sign_message(args.key, args.infile, args.out)
    elif args.command == "verify":
        verify_signature(args.key, args.infile, args.sig)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
