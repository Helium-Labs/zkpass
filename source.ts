// version 1
export default `#pragma version 9
txn CloseRemainderTo
global ZeroAddress
==
txn RekeyTo
global ZeroAddress
==
&&
byte base64(YQ==)
len
int 32
<=
byte base64(YQ==)
len
int 32
<=
&&
byte base64(YQ==)
len
int 32
<=
&&
&&
arg 0
arg 1
byte base64(YQ==)
ed25519verify
&&
txn TxID
arg 2
arg 0
ed25519verify
&&
return`