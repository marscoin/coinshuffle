"""
Demonstrates hybrid encryption (AES-GCM + RSA): encrypts a message
under a public key and that can only be recovered using the corresponding
secret key.

Requires: Python 2; pycryptodomex
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import urlsafe_b64encode as b64enc, urlsafe_b64decode as b64dec
from Crypto import Random
from binascii import hexlify, unhexlify

# Constants
symmetricKeySizeBytes = 128/8
encMsgKeyBytes = 384
encMsgKeyBytes2 = 128
rsaKeySize = 3072

publicKeyDecryptError = "This is an rsa PUBLIC key, but an rsa PRIVATE key is required for decryption."
decryptionFailedError = "Decryption failed. Encrypted message is not valid."

def test_encryptionRoundTrip():    
    # Make fresh keys
    pubFilename, privFilename = createPubkeyPair("./test")
    origMsg = "This is a super-secret message that needs to be protected"
    print("Original message: '{}'\n".format(origMsg))

    # Encrypt a message
    ctext = publicKeyEncrypt(pubFilename, origMsg)
    print("Ciphertext: {}\n".format(ctext))

    # Recover the message
    err, msg = publicKeyDecrypt(privFilename, ctext)
    if err:
        raise Exception(err)
    print("Recovered message: '{}'".format(msg.decode("utf-8")))
    assert(origMsg == str(msg.decode("utf-8")))


def test_encryptionRoundTrip2():
    # Make fresh keys
    random_gen = Random.new().read
    keypair = RSA.generate(1024, random_gen)

    origMsg = "This is a super-secret message that needs to be protected"
    print("Original message: '{}'\n".format(origMsg))

    pubkey = hexlify(keypair.publickey().exportKey('DER'))
    print("DER")
    print(pubkey)
    pubkey = RSA.importKey(unhexlify(pubkey))
    print(pubkey)
    pubkey = hexlify(pubkey.publickey().exportKey('DER'))
    print(pubkey)
    # Encrypt a message
    ctext = publicKeyEncryptFileless(pubkey, origMsg)
    print("Ciphertext: {}\n".format(ctext))

    # Recover the message
    err, msg = publicKeyDecryptFileless(keypair, ctext)
    if err:
        raise Exception(err)
    print("Recovered message: '{}'".format(msg.decode("utf-8")))
    assert(origMsg == str(msg.decode("utf-8")))

def publicKeyEncrypt(recipientKeyfile, message):
    """
    Applies public key (hybrid) encryption to a given message when supplied 
    with a path to a public key (RSA in PEM format).
    """
    # Load the recipients pubkey from a PEM file
    with open(recipientKeyfile, 'rb') as f:
        recipientKey = RSA.import_key(f.read())

    # Encrypt the message with AES-GCM using a newly selected key
    messageKey, ctext = aesEncrypt(message)

    # Encrypt the message key and prepend it to the ciphertext
    cipher = PKCS1_OAEP.new(recipientKey)
    encMsg = cipher.encrypt(messageKey) + ctext

    # Format the message into b64
    return b64enc(encMsg)


def publicKeyEncryptFileless(pubkey, message):
    """
    Applies public key (hybrid) encryption to a given message when supplied
    with a path to a public key (RSA in PEM format).
    """
    recipientKey = RSA.importKey(unhexlify(pubkey))
    # Encrypt the message with AES-GCM using a newly selected key
    messageKey, ctext = aesEncrypt(message)

    # Encrypt the message key and prepend it to the ciphertext
    cipher = PKCS1_OAEP.new(recipientKey)
    encMsg = cipher.encrypt(messageKey) + ctext

    # Format the message into b64
    return b64enc(encMsg)


def publicKeyDecryptFileless(key, ctext):
    """
    Decrypts an encrypted message with a private (RSA) key.
    Returns: (err, message)
    """
    privkey = key

    # Verify that this is a private key
    if not privkey.has_private():
        return (publicKeyDecryptError, None)

    # Verify the JEE and extract the encrypted message
    encBytes = b64dec(ctext)

    # Separate the encrypted message key from the symmetric-encrypted portion.
    encKey, ctext = encBytes[:encMsgKeyBytes2], encBytes[encMsgKeyBytes2:]

    # Recover the message key
    msgKey = PKCS1_OAEP.new(privkey).decrypt(encKey)

    # Recover the underlying message
    try:
        return (None, aesDescrypt(msgKey, ctext))
    except ValueError:
        return (decryptionFailedError, None)

def publicKeyDecrypt(privkeyFile, ctext):
    """
    Decrypts an encrypted message with a private (RSA) key.
    Returns: (err, message)
    """
    privkey = None
    with open(privkeyFile, 'rb') as f:
        privkey = RSA.import_key(f.read())

    # Verify that this is a private key
    if not privkey.has_private():
        return (publicKeyDecryptError, None)

    # Verify the JEE and extract the encrypted message
    encBytes = b64dec(ctext)

    # Separate the encrypted message key from the symmetric-encrypted portion.
    encKey, ctext = encBytes[:encMsgKeyBytes], encBytes[encMsgKeyBytes:]

    # Recover the message key
    msgKey = PKCS1_OAEP.new(privkey).decrypt(encKey)

    # Recover the underlying message
    try:
        return (None, aesDescrypt(msgKey, ctext))
    except ValueError:
        return (decryptionFailedError, None)

def createPubkeyPair(basename):
    """
    Creates a new secret/key pubkey pair and writes them to distinct files:
    <basename>-public.pem
    <basename>-private.pem
    """
    pubFilename = basename + "-public.pem"
    privFilename = basename + "-private.pem"

    # Create a new key and write both key versions to the correct file
    privkey = RSA.generate(rsaKeySize)
    pubkey = privkey.publickey()
    _writePemFile(pubFilename, pubkey)
    _writePemFile(privFilename, privkey)
    return pubFilename, privFilename

def _writePemFile(filename, key):
    with open(filename, "w") as outfile:
        outfile.write(key.exportKey(format='PEM').decode("utf-8"))

def aesEncrypt(message):
    """
    Encrypts a message with a fresh key using AES-GCM. 
    Returns: (key, ciphertext)
    """
    key = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_GCM)
    ctext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

    # Concatenate (nonce, tag, ctext) and return with key
    return key, (cipher.nonce + tag + ctext)

def aesDescrypt(key, ctext):
    """
    Decrypts and authenticates a ciphertext encrypted with with given key.
    """
    # Break the ctext into components, then decrypt
    nonce,tag,ct = (ctext[:16], ctext[16:32], ctext[32:])
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ct, tag)

####################################
# TESTS
####################################
#In memory
test_encryptionRoundTrip2()

#File file
#test_encryptionRoundTrip()