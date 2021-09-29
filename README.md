# SSI PoC

This is a PoC implementation of the [DIDCOMM v1](https://identity.foundation/didcomm-messaging/spec/) messaging protocol.
It establishes a direct connection to an SSI wallet (agent) and asks for personal data.

> **This PoC demonstrates a conceptual flaw: Only one end in the communication is properly identified: The user, not the entity asking for digital identity proof**
> **The user cannot distinguish between a malicious and a valid QR**

Since the official documentation is terrible to read IMHO, here's a quick summary of what happens:

**Preconditions**:
1. *Alice* wants to proof to *Bob*, that she is, in fact, *Alice*
2. *Alice* holds a document (Base-ID) in her [wallet](https://lissi.id/), that was issued to her, that proves her identity
    1. Such a [document](https://webcache.googleusercontent.com/search?q=cache:BiBK6OBZBFwJ:https://idunion.esatus.com/tx/IDunion_Test/domain/5620) can be obtained [here](https://lissi.id/demo)
    2. In a real world scenario, some citizen office would issue such a document

To prove her identity, *Alice* and *Bob* perform the following steps:
1. *Bob* provides *Alice* a QR code, transporting:
    1. A public key (*Bob* generates and holds the correspending private key)
    2. A list of attributes, he wants to know from *Alice*
    3. A reference to the type of document containing those attributes ([`CRED_DEF`](https://hyperledger-indy.readthedocs.io/projects/node/en/latest/requests-new.html?highlight=CRED_DEF#claim-def))
    4. A label for his identity, that is displayed (and not verified) in the [ID Wallet](https://www.bundesregierung.de/breg-de/suche/e-id-1962112) app. In the [Lissi wallet](https://lissi.id/) only 'Direct connection' is shown.
    5. A callback URL (`serviceEndpoint`)
2. *Alice* scans the QR code and accepts the connection request
    1. *Alice* cannot verify that she is establishing a connection with *Bob*, because his identity is not validated
3. The wallet app prompts *Alice* if she wants to share her personal data and she accepts
4. *Alice* encrypts her personal data using *Bobs* public key and sends it to the given callback URL
5. *Bob* decrypts *Alice* personal data
6. *Bob* performs steps to validate that data (this was out of scope of our analysis)

## The problem
Since the identity of *Bob* is not established and only 'Direct connection' is shown (or some attacker controlled data in the ID Wallet app), *Alice* cannot verify with whom she is sharing her data.
An attacker, *Mallory*, could replace the QR code by performing a *machine-in-the-middle* attack or by replacing a QR code in real world in order to steal personal data. Please note, that we do not demonstrate a mitm-attack here.

The problem (and its implications) are known and have been the topic of [multiple](https://github.com/decentralized-identity/didcomm-messaging/issues/41) Github [issues](https://github.com/hyperledger/aries-rfcs/issues/473) and [public discussions](https://lists.hyperledger.org/g/indy/topic/31208810), but apparently has not been solved.

**Impact**: As a user, one cannot make sure, who receives one's data. The original recipient might have been replaced by a malicious one. A malicious recipient might use the leaked sensitive private data to sell it or to attempt identity theft. Future use-cases might include for example credit card data (see the Lissi demo).

## Demo Time
> We are using the [Lissi wallet](https://lissi.id/) because it is the same (standardized) technology like the [ID Wallet](https://www.bundesregierung.de/breg-de/suche/e-id-1962112) and it seemd more stable to us.
> For our demo, we are using the document `XmfRzF36ViQg8W8pHot1FQ:3:CL:5614:Base-ID`, some example digital identity issued at [https://lissi.id/demo](https://lissi.id/demo).

Steps to reproduce:
1. Download the [Lissi wallet](https://lissi.id/) app
    1. [iOS](https://apps.apple.com/app/lissi-wallet/id1529848685)
    2. [Android](https://play.google.com/store/apps/details?id=io.lissi.mobile.android)
2. On some other device, navigate to the [Lissi demo site](https://lissi.id/demo) and use the `Citizen Office` demo, to receive a base-ID
3. Install python dependencies: `pip install -r requirements.txt`
4. Run the python software: `./poc.py <local ip addr>`
5. Open `http://<local ip addr>:9000/qr` and scan it
6. You'll be prompted a 'Direct connection' request, notice how there's no way for you to validate it
7. Accept the request and your data will appear on the terminal

## Licenses
This PoC utilizes code (`crypto.py`) taken from https://github.com/hyperledger/aries-staticagent-python/ that is licensed under a [Apache License, version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
This code is licensed under the same license.

## Authors
* [Lilith Wittmann](https://twitter.com/LilithWittmann)
* [Flüpke](https://twitter.com/fluepke)
