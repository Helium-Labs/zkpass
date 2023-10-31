
from pyteal import *
import sys 
import os

lsig_version = 1

passpk = Bytes("base64", "YQ==")
salt = Bytes("base64", "YQ==")
client_id = Bytes("base64", "YQ==")
user_id = Bytes("base64", "YQ==")

"""
Approves TX if signed by the ephemeral key, which has been delegated access by passsk.
passpk is an x25519 key derived from H(password + salt + client_id + user_id).
password is a user chosen UTF8 password.
"""
def zkpass(
    tmpl_passpk=passpk,
    tmpl_salt=salt,
    tmpl_clientId=client_id,
    tmpl_user=user_id
):
    # Assert clientId, salt & user don't exceed 32 bytes
    clientId_len = Len(tmpl_clientId)
    user_len = Len(tmpl_user)
    salt_len = Len(tmpl_salt)
    salt_cond = salt_len <= Int(32)
    clientId_cond = clientId_len <= Int(32)
    user_cond = user_len <= Int(32)
    bounded_cond = And(clientId_cond, user_cond, salt_cond)

    # Usual safety checks
    safety_cond = And(
        Txn.close_remainder_to() == Global.zero_address(),
        Txn.rekey_to() == Global.zero_address(),
    )

    # Verify ephemeral key has been delegated access by the tmpl_passpk
    ephemeral_pk = Arg(0)
    pass_ephermeral_sig = Arg(1)

    ephemeral_delegated_cond = Ed25519Verify(
        ephemeral_pk,
        pass_ephermeral_sig,
        tmpl_passpk
    )

    # Verify the ephemeral key has signed H(Txn)=Txn.tx_id()
    ephermeral_tx_sig = Arg(2)
    ephemeral_approved_tx_cond = Ed25519Verify(
        Txn.tx_id(),
        ephermeral_tx_sig,
        ephemeral_pk
    )

    return And(safety_cond, bounded_cond, ephemeral_delegated_cond, ephemeral_approved_tx_cond)

if __name__ == "__main__":
    teal = compileTeal(zkpass(), mode=Mode.Signature, version=9)
    with open(os.path.join(sys.path[0], "source.ts"), "w+") as f:
        sourceCode = f"// version {lsig_version}\nexport default `{teal}`"
        f.write(sourceCode)