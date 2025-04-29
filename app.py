from flask import Flask, request, render_template, send_file, flash, redirect
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as aes_padding
from stegano import lsb
import base64
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session and flash messages


# Caesar Cipher Encryption
def caesar_encrypt(message, shift):
    result = ""
    for i in message:
        if i.isalpha():
            shift_val = 65 if i.isupper() else 97
            result += chr((ord(i) + shift - shift_val) % 26 + shift_val)
        else:
            result += i
    return result


# Caesar Cipher Decryption
def caesar_decrypt(message, shift):
    result = ""
    for i in message:
        if i.isalpha():
            shift_val = 65 if i.isupper() else 97
            result += chr((ord(i) - shift - shift_val) % 26 + shift_val)
        else:
            result += i
    return result


# Function to hash the key to 256 bits for AES
def hash_key_for_aes(key):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.encode("utf-8"))
    return digest.finalize()

@app.route('/')
def home():
    return render_template('landing.html')  # Landing page for app introduction

@app.route("/encode")
def encode_page():
    return render_template("index.html")  # Page to encode messages

@app.route("/decode")
def decode_page():
    return render_template("decode.html")  # Page to decode messages


@app.route("/encode_message", methods=["POST"])
def encode_message():
    if request.method == "POST":
        # Get form data
        image = request.files["image"]
        message = request.form["message"]
        key = request.form["secret_key"]
        encryption_method = request.form["encryption"]

        # File Size Validation (5MB limit)
        if image and len(image.read()) > 5 * 1024 * 1024:  # 5MB limit
            flash("File is too large! Please upload a smaller image.")
            return redirect(request.url)

        # Encrypt the message
        if encryption_method == "AES":
            aes_key = hash_key_for_aes(key)

            padder = aes_padding.PKCS7(128).padder()
            padded_message = padder.update(message.encode("utf-8")) + padder.finalize()

            cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_message) + encryptor.finalize()
            encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

        elif encryption_method == "DES":
            if len(key) != 8:
                flash("For DES encryption, the secret key must be exactly 8 characters long!")
                return render_template("index.html")

            des_key = key.encode("utf-8")

            padded_message = pad(message.encode("utf-8"), 8)

            cipher = DES.new(des_key, DES.MODE_ECB)
            encrypted_data = cipher.encrypt(padded_message)
            encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

        elif encryption_method == "CEASER":
            try:
                shift = int(key)
            except ValueError:
                flash("For Caesar Cipher, secret key must be a number (shift value)!")
                return render_template("index.html")

            encrypted_data = caesar_encrypt(message, shift)

        else:
            flash("Invalid encryption method selected.")
            return render_template("index.html")

        # Hide the encrypted message in the image
        stego_image = lsb.hide(image, encrypted_data)
        stego_image_path = "static/stego_image.png"
        stego_image.save(stego_image_path)

        flash("Image encoded successfully with the encrypted message!")
        return send_file(stego_image_path, as_attachment=True)


@app.route("/decode_message", methods=["POST"])
def decode():
    if request.method == "POST":
        stego_image = request.files["stego_image"]
        secret_key = request.form["secret_key"]
        encryption_method = request.form["encryption"]

        hidden_message = lsb.reveal(stego_image)

        if not hidden_message:
            flash("Unable to extract hidden message!")
            return render_template("decode.html")

        # Decrypt the message
        if encryption_method == "AES":
            aes_key = hash_key_for_aes(secret_key)

            cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(base64.b64decode(hidden_message.encode("utf-8"))) + decryptor.finalize()

            unpadder = aes_padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
            decrypted_message = decrypted_data.decode("utf-8")

        elif encryption_method == "DES":
            if len(secret_key) != 8:
                flash("For DES decryption, the secret key must be exactly 8 characters long!")
                return render_template("decode.html")

            des_key = secret_key.encode("utf-8")

            cipher = DES.new(des_key, DES.MODE_ECB)
            decrypted_data = cipher.decrypt(base64.b64decode(hidden_message.encode("utf-8")))

            unpadded_data = unpad(decrypted_data, 8)
            decrypted_message = unpadded_data.decode("utf-8")

        elif encryption_method == "CEASER":
            try:
                shift = int(secret_key)
            except ValueError:
                flash("For Caesar Cipher, secret key must be a number (shift value)!")
                return render_template("decode.html")

            decrypted_message = caesar_decrypt(hidden_message, shift)

        else:
            flash("Invalid encryption method selected.")
            return render_template("decode.html")

        flash("Message decoded successfully!")
        return render_template("decode.html", decoded_message=decrypted_message)

    return render_template("decode.html")


if __name__ == "__main__":
    app.run(debug=True)
