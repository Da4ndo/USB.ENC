__title__ = "usb.enc"
__version__ = "0.3.0"

__author__ = "Da4ndo"
__discord__ = "Da4ndo#0934"
__github__ = "https://github.com/Mesteri05"
__licence__ = "MIT"

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os, sys
import argparse
import base64
from zipfile import ZipFile
import os
import win32api

class Cipher:
    class Type:
        PUBLIC_KEY = "public"
        PRIVATE_KEY = "private"

    def generate_keys(**options):
        private_key = rsa.generate_private_key(
            public_exponent=options.get("public_exponent", 65537),
            key_size=options.get("key_size", 2048),
            backend=options.get("backend", default_backend())
        )

        public_key = private_key.public_key()

        return private_key, public_key

    def import_from_bytes(text, key_type, **options):
        if key_type == "private":
            key = serialization.load_pem_private_key(text, **options)
        
        elif key_type == "public":
            key = serialization.load_pem_public_key(text, **options)
        
        return key
    
    def export_to_bytes(key, key_type, **options):
        if key_type == "private":
            pem = key.private_bytes(**options)
        
        elif key_type == "public":
            pem = key.public_bytes(**options)
        
        return pem

    def export_to_file(filename, key, key_type, **options):
        if key_type == "private":
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=options.get("encryption_algorithm", serialization.NoEncryption())
            )
        
        elif key_type == "public":
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        with open(filename, 'wb') as f:
            f.write(pem)

    def import_from_file(filename, key_type, **options):
        if key_type == "private":
            with open(filename, "rb") as key_file:
                key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=options.get("password", None),
                    backend=default_backend()
                )
        
        elif key_type == "public":
            with open(filename, "rb") as key_file:
                key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        
        return key

    def encrypt(public_key, bytes):
        encrypted = public_key.encrypt(
            bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt(private_key, encrypted_bytes):
        original_message = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message

    def get_private_key_location():
        dl = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        drives = ['%s:' % d for d in dl if os.path.exists('%s:' % d)]
        for drive in drives:
            res = win32api.GetVolumeInformation(drive + "\\")
            if res[0] == "ENC_PRIVATE":
                return drive + "\\private.key"
        return None
    
    def encrypt_file(public_key, filename, encrypted_filename, pk_lenght):
        with open(filename, 'rb') as f:
            file_bytes = f.read()

        erd = str(len(file_bytes) / pk_lenght).split(".")
        szam = int(erd[0])
        if erd[1] != "0":
            szam += 1

        bytes_list = []
        for x in range(szam):
            if x == 0:
                bytes_list.append(file_bytes[0 : pk_lenght])
            else: 
                bytes_list.append(file_bytes[x * pk_lenght : x * pk_lenght + pk_lenght])

        for x in bytes_list:
            if bytes_list.index(x) == 0:
                enc_bytes = Cipher.encrypt(public_key, base64.b64encode(f"FN:{os.path.basename(filename)}/0x34;".encode('utf-8') + x))
            else:
                enc_bytes = Cipher.encrypt(public_key, base64.b64encode(x))
        
            print("Encrypt data to", encrypted_filename.replace("{0}", str(bytes_list.index(x) + 1)))
            with open(encrypted_filename.replace("{0}", str(bytes_list.index(x) + 1)), 'wb') as f:
                f.write(enc_bytes)
        
        with ZipFile(encrypted_filename.replace("{0}", "") + ".zip", 'w') as zip:
            for x in range(len(bytes_list)):
                zip.write(encrypted_filename.replace("{0}", str(x + 1)))
                os.remove(encrypted_filename.replace("{0}", str(x + 1)))

        print("Finished. Encrypted file saved to", encrypted_filename.replace("{0}", "") + ".zip", "\n")

    def decrypt_file(private_key, filename):
        output_bytes = b''
        with ZipFile(filename, 'r') as zip:
            for x in zip.namelist():
                if "enc" not in x:
                    continue

                print("Decrypting " + x)
                with zip.open(x, mode='r') as f:
                    output_bytes += base64.b64decode(Cipher.decrypt(private_key, f.read()))
                
        enc_file_bytes = output_bytes.split(b"/0x34;")
        with open(os.path.dirname(filename) + enc_file_bytes[0].decode().split(":")[1], "wb") as f:
            f.write(enc_file_bytes[-1])
        
        print("Finished. Decrypted file saved to", os.path.dirname(filename) + enc_file_bytes[0].decode().split(":")[1], "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', "--generate-keys", nargs="+", help='Save private key to a USB and public key somwhere you specify. eg.: -g "C:\\asd\\" "YOUR_PASSWORD(optional)"', default=False)
    parser.add_argument('-e', "--encrypt", nargs="+", help='Encrypt file. eg.: "FileLoc" "PubKeyDirectoryLoc"', default=None)
    parser.add_argument('-d', "--decrypt", nargs="+", help='Decrypt file. eg.: "FileLoc" "YOUR_PASSWORD(optional)"', default=None)
    parser.add_argument('-p', "--public-key", nargs="+", help='Get public key, if you lost it. eg.: -p "PubKeyDirectoryLoc" "YOUR_PASSWORD(optional)"', default=None)
    options = parser.parse_args(sys.argv[1:])
    
    if options.generate_keys != False:
        options.generate_keys = list(options.generate_keys)

        try:
            options.generate_keys[0]
        except:
            print("Error: Public Key Directory Location must be specified.")
            os._exit(1)

        pk_path = Cipher.get_private_key_location()
        if pk_path == None:
            print("No USB connected to save private key or the USB name doesn't equal to 'ENC_PRIVATE'.")
        
        print("Generating keys started, please be patient. It will take about 5 minute.\n")
        private_key, public_key = Cipher.generate_keys(key_size=int(16384))

        if len(options.generate_keys) > 1:
            Cipher.export_to_file(pk_path, private_key, Cipher.Type.PRIVATE_KEY, encryption_algorithm=serialization.BestAvailableEncryption(options.generate_keys[1].encode()))
        else:
            Cipher.export_to_file(pk_path, private_key, Cipher.Type.PRIVATE_KEY)
        Cipher.export_to_file(options.generate_keys[0] + "public.key", public_key, Cipher.Type.PUBLIC_KEY)
        print("Private key saved to", os.path.abspath(pk_path))
        print("Public key saved to " + os.path.abspath(options.generate_keys[0] + "public.key"))
        print("")
    
    elif options.public_key:
        options.public_key = list(options.public_key)
        pk_path = Cipher.get_private_key_location()
        if pk_path == None:
            print("No USB connected to save private key or the USB name doesn't equal to 'ENC_PRIVATE'.")

        if len(options.public_key) > 1:
            private_key = Cipher.import_from_file(pk_path, Cipher.Type.PRIVATE_KEY, password=options.public_key[1].encode())
        else:
            private_key = Cipher.import_from_file(pk_path, Cipher.Type.PRIVATE_KEY)
        
        Cipher.export_to_file(options.public_key[0] + "public.key", private_key.public_key(), Cipher.Type.PUBLIC_KEY)
        print("Public key saved to " + os.path.abspath(options.public_key[0] + "public.key"))
        print("")

    else:
        if options.encrypt != None:
            options.encrypt = list(options.encrypt)
            public_key = Cipher.import_from_file(options.encrypt[1] + "public.key", Cipher.Type.PUBLIC_KEY)

            new_file_name = os.path.dirname(str(options.encrypt[0]))
            pp = os.path.basename(str(options.encrypt[0])).split(".")
            for x in pp:
                if pp.index(x) + 1 != len(pp):
                    new_file_name += x + "."
            new_file_name += "enc{0}"

            Cipher.encrypt_file(public_key, str(options.encrypt[0]), new_file_name, 1400)

        elif options.decrypt != None:
            options.decrypt = list(options.decrypt)

            try:
                options.decrypt[0]
            except:
                print("Error: Encrypted File Location must be specified.")
                os._exit(1)

            pk_path = Cipher.get_private_key_location()
            if pk_path == None:
                print("No USB connected to save private key or the USB name doesn't equal to 'ENC_PRIVATE'.")

            if len(options.decrypt) > 1:
                private_key = Cipher.import_from_file(pk_path, Cipher.Type.PRIVATE_KEY, password=options.decrypt[1].encode())
            else:
                private_key = Cipher.import_from_file(pk_path, Cipher.Type.PRIVATE_KEY)
            Cipher.decrypt_file(private_key, str(options.decrypt[0]))