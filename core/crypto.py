import pgpy
import datetime

def generate_keypair(name, passphrase='', keylen=2048, comment='', include_info=True):
    key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, int(keylen))
    # Compose UID with optional comment
    if comment:
        uid = pgpy.PGPUID.new(name, comment=comment)
    else:
        uid = pgpy.PGPUID.new(name)
    key.add_uid(
        uid,
        usage={pgpy.constants.KeyFlags.Sign, pgpy.constants.KeyFlags.EncryptCommunications},
        hashes=[pgpy.constants.HashAlgorithm.SHA256],
        ciphers=[pgpy.constants.SymmetricKeyAlgorithm.AES256],
        compression=[pgpy.constants.CompressionAlgorithm.ZLIB])
    protected = bool(passphrase)
    if protected:
        key.protect(passphrase, pgpy.constants.SymmetricKeyAlgorithm.AES256, pgpy.constants.HashAlgorithm.SHA256)
    priv = str(key)
    pub = str(key.pubkey)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def insert_credits_and_comment(block, comment, include_info):
        lines = block.splitlines()
        if lines and lines[0].startswith("-----BEGIN"):
            insert_lines = []
            if include_info:
                insert_lines.append("Version: SimplePGP Client V1.0")
            if comment:
                insert_lines.append("Comment: " + comment)
            # Insert after BEGIN ... BLOCK ...
            return '\n'.join([lines[0]] + insert_lines + lines[1:])
        return block

    priv = insert_credits_and_comment(priv, comment, include_info)
    pub = insert_credits_and_comment(pub, comment, include_info)
    return {"name": name, "priv": priv, "pub": pub, "protected": protected, "date": now, "comment": comment}

def pgp_encrypt(message, pubkey_txt):
    pubkey, _ = pgpy.PGPKey.from_blob(pubkey_txt)
    msg = pgpy.PGPMessage.new(message.strip())
    enc = pubkey.encrypt(msg)
    return str(enc)

def pgp_decrypt(enc_txt, privkey_txt, passphrase=''):
    privkey, _ = pgpy.PGPKey.from_blob(privkey_txt)
    msg = pgpy.PGPMessage.from_blob(enc_txt)
    if privkey.is_protected:
        if not passphrase:
            raise ValueError("This key is protected by a passphrase. Please provide it.")
        with privkey.unlock(passphrase):
            dec = privkey.decrypt(msg)
    else:
        with privkey.unlock(""):
            dec = privkey.decrypt(msg)
    return str(dec.message)

def pgp_sign(msg_txt, privkey_txt, passphrase=''):
    privkey, _ = pgpy.PGPKey.from_blob(privkey_txt)
    msg = pgpy.PGPMessage.new(msg_txt.strip())
    # Always unlock with context manager, and check is_unlocked
    if privkey.is_protected:
        if not passphrase:
            raise ValueError("This key is protected by a passphrase. Please provide it.")
        with privkey.unlock(passphrase):
            if not privkey.is_unlocked:
                raise ValueError("Failed to unlock private key. Passphrase may be incorrect.")
            sig = privkey.sign(msg)
    else:
        with privkey.unlock(""):
            if not privkey.is_unlocked:
                raise ValueError("Failed to unlock private key.")
            sig = privkey.sign(msg)
    return str(sig)

def pgp_verify(msg_txt, sig_txt, pubkey_txt):
    pubkey, _ = pgpy.PGPKey.from_blob(pubkey_txt)
    sig = pgpy.PGPSignature.from_blob(sig_txt)
    # Use plain message string for detached signature verification
    return bool(pubkey.verify(msg_txt.strip(), sig))