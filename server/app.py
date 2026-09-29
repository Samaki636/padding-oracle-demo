from flask import Flask, jsonify, request

from server.crypto import decrypt


app = Flask(__name__)


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    """
    Vulnerable padding oracle.

    Receives:
        IV || ciphertext

    Responds:
        200 if the padding is valid
        400 if the padding is invalid
    """

    data = request.get_json()

    if not data or "ciphertext" not in data:
        return jsonify({
            "error": "missing ciphertext"
        }), 400

    try:
        raw = bytes.fromhex(data["ciphertext"])

        if len(raw) < 32:
            return jsonify({
                "error": "ciphertext too short"
            }), 400

        iv = raw[:16]
        ciphertext = raw[16:]

        decrypt(ciphertext, iv)

        # Valid padding
        return jsonify({
            "status": "valid"
        }), 200

    except ValueError:
        # Invalid padding
        return jsonify({
            "status": "invalid"
        }), 400


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )