#!/bin/env python3

from io import BytesIO
import os
import uuid
import crypto
import flask
from flask import Flask, redirect, request
from pygments import highlight, lexers, formatters
import base64
import base58
import json
from nacl.public import PrivateKey, Box, SealedBox
import nacl.bindings
import time
import argparse
import qrcode

parser = argparse.ArgumentParser()
parser.add_argument("ip", help="(Local IP) address, used to generate the callback URL")
args = parser.parse_args()

pk, sk = crypto.create_keypair()

app = Flask(__name__)

QR_EMBEDDED = {
    "name": "Proof request",
    "requested_predicates": {},
    "requested_attributes": {
        "masterId": {
            "names": [
                "Address city",
                "Address country",
                "Date of expiry",
                "Family name",
                "First name",
                "Birth name",
                "Address zip code",
                "Date of birth",
                "Academic title",
                "Address street",
                "Place of birth",
            ],
            "non_revoked": {"from": 0, "to": int(time.time()) + 420},
            "restrictions": [
                # https://webcache.googleusercontent.com/search?q=cache:BiBK6OBZBFwJ:https://idunion.esatus.com/tx/IDunion_Test/domain/5620
                {"cred_def_id": "XmfRzF36ViQg8W8pHot1FQ:3:CL:5614:Base-ID"}
            ],
        }
    },
    "version": "0.1",
    "nonce": "-502502227943056483688534",  # chosen by fair roll of dice
}
QR = {
    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0/request-presentation",
    # "@type":"did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0/request-presentation",
    # "@id":"8167b1bf-b6ed-4c0b-9449-5752c2345203",
    "@id": str(uuid.uuid4()),
    "request_presentations~attach": [
        {
            "@id": "libindy-request-presentation-0",
            "mime-type": "application/json",
            "data": {
                "base64": (base64.b64encode((json.dumps(QR_EMBEDDED)).encode())).decode(
                    "ascii"
                )
            },
        }
    ],
    "~service": {
        "recipientKeys": [(crypto.bytes_to_b58(pk))],
        "routingKeys": [],
        "serviceEndpoint": f"http://{args.ip}:9000/data",
        "endpointName": "Helge Braun",
    },
    "~thread": {"thid": str(uuid.uuid4()), "sender_order": 0, "received_orders": {}},
}


@app.route("/")
def hello():
    code = json.dumps(QR)
    b64 = base64.b64encode(code.encode())
    return redirect(f"didcomm://{args.ip}:9000?m={b64.decode('ascii')}", code=307)


@app.route("/qr")
def show_qr():
    code = json.dumps(QR)
    b64 = base64.b64encode(code.encode())
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(f"didcomm://example.org?m={b64.decode('ascii')}")
    qr.make(fit=True)
    buf = BytesIO()
    qr.make_image().save(buf)
    buf.seek(0)
    return flask.send_file(buf, mimetype="image/png")


@app.route("/data", methods=["POST"])
def data():
    data = json.loads(request.data)
    (unpacked_msg, sender_vk, recip_vk) = crypto.unpack_message(request.data, pk, sk)
    content = json.loads(unpacked_msg)
    data = json.loads(
        base64.b64decode(content["presentations~attach"][0]["data"]["base64"])
    )
    formatted_json = json.dumps(
        data["requested_proof"]["revealed_attr_groups"]["masterId"]["values"],
        sort_keys=True,
        indent=4,
    )
    colorful_json = highlight(
        formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter()
    )
    print(colorful_json)

    return json.dumps({"success": True}), 200, {"ContentType": "application/json"}


if __name__ == "__main__":
    print(f"With your browser, please open http://{args.ip}:9000/qr")
    app.run(host=args.ip, port=9000)
