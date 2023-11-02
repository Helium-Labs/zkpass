# ZKPass | LSIG: Secure Account Access via Salted Password with ZKP

ZKPass uses a stateless LSIG that leverages Zero Knowledge Proof (ZKP) to verify that a user knows the password without exposing it. This authorization is used to sanction spend transactions.

⭐Stars are appreciated⭐

## How it Works

With ZKPass, each user gets a unique LSIG account upon creation, identifiable by a combination of `passpk`, `salt`, `client_id`, and `user_id`.

- `passpk`: A x25519 key derived from `H(password + salt + client_id + user_id)`.
- `salt`: A unique nonce designed to thwart rainbow table attacks.
- `client_id`: An identifier for the application.
- `user_id`: Identifier for the user.

During authentication, public values reproduce the same LSIG (user's account) for signing transactions. The holder, using `H(password + salt + client_id + user_id)`—a slow hashing function to deter brute-force attacks—generates `(passpk, passsk)` with their password. This keypair is then used to delegate authority to an epheremal key pair `(ephemeral_pk, ephemeral_sk)` as proven by `pass_ephermeral_sig`. Then the client can sign transactions, specifically its `Id`, which the LSIG will approve.

## Usage

```typescript
// zkpass is an LSIG account that's generated per user, on account creation, identifiable by (passpk + salt + client_id + user_id).
// passpk is an x25519 key derived from H(password + salt + client_id + user_id)
// salt is a nonce to mitigate rainbow table attacks
// client_id is an application id
// user_id is the users id
import zkpass from './source'

// Compile
const result = await client.compile(Buffer.from(zkpass)).do()
const b64program = result.result

// ephermeral_tx_sig generated per TX, which is the Tx.Id signed with the ephemeral key. The ephemeral key can be for the session.
const args = [ephemeral_pk, pass_ephermeral_sig, ephermeral_tx_sig]
const smartSig = new algosdk.LogicSig(
  new Uint8Array(Buffer.from(b64program, 'base64')),
  args
);

// Proceed to sign
```

## Build

Compile PyTeal to TEAL by calling python on `zkpass_lsig.py`

## License

Subject to the attached GPL V3 license specified in `LICENSE`. The license can be changed at my discretion.

## Disclaimer

No warranties or liabilities offered to the fullest extent of applicable law. Use at your own risk.

Not audited, therefore it's not production ready.

Does this imply I'm somehow the custodian. NO! This is just open-source code (text), not a live service. You are fully responsible for how it's used.

This doesn't mean I'm going to be commiting myself to anything. I reserve the right to change direction at any moment.
