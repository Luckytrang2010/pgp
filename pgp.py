import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import os
from datetime import timedelta

dir_path = os.path.dirname(os.path.realpath(__file__))

pubkeys = {} #  {"name":"public key string"}
privkeys = {} # {"name":["private key string","passphrase"]}

#there should be 2 folders called pubkeys and privkeys 
for (dirpath, dirnames, filenames) in os.walk(str(dir_path) + "/pubkeys"):
	#pubkeysf.append(filenames)
	for file in filenames:
		with open(str(dirpath) + "/" + file,"r") as f:
			pubkeys[file] = f.read()
for (dirpath, dirnames, filenames) in os.walk(str(dir_path) + "/privkeys"):
	#privkeysf.append(filenames)
	for file in filenames:
		with open(str(dirpath) + "/" + file,"r") as f:
			privkeys[file] = [f.read(),""]

def create_keypair(name,passphrase=None,bits=3072,email=None): 
	#rsa
	keypair = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, bits)
	kuid = pgpy.PGPUID.new(str(name),email=email)
	keypair.add_uid(kuid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
		hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
		ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
		compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
		key_expiration=timedelta(days=365))
	if passphrase != None:
		privkeys[str(name)] = [keypair,str(passphrase)]
		keypair.protect(str(passphrase), SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256) #password protected with aes256
	else:
		privkeys[str(name)] = [keypair,""]
	pubkeys[str(name)] = keypair.pubkey
	return keypair #returns private key; keypair.pubkey is public key

def export_keypairs():
	for i in privkeys:
		with open(dir_path + "/privkeys/" + i + ".asc","w+") as f:
			f.write(str(privkeys[i][0]))
	for i in pubkeys:
		with open(dir_path + "/pubkeys/" + i + ".asc","w+") as f:
			f.write(str(pubkeys[i]))

def encrypt(pubkey,msg): 
	#pubkey = string of public key
	#pub,__ = pgpy.PGPKey.from_file(str(pubkey))

	#encrypt(f.read(),"hello")

	pub,__ = pgpy.PGPKey.from_blob(str(pubkey))
	pmsg = pgpy.PGPMessage.new(str(msg)) 
	return pub.encrypt(pmsg)
def encrypt_to_others(pubkeys,msg):
	#pubkeys = []
	message = pgpy.PGPMessage.new(str(msg))
	enc_msg = None

	cipher = SymmetricKeyAlgorithm.AES256
	session = cipher.gen_key()
	for pk in pubkeys:
		pkk,__ = pgpy.PGPKey.from_blob(str(pk))
		if pubkeys.index(pk) == 0:
			enc_msg = pkk.encrypt(message,cipher=cipher,sessionkey=session)
		else:
			enc_msg = pkk.encrypt(enc_msg,cipher=cipher,sessionkey=session)
	del session
	return enc_msg

def decrypt(privkey,encmsg,passphrase=None):
	decmsg = ""
	priv,__ = pgpy.PGPKey.from_blob(str(privkey))
	if priv.is_unlocked == False:
		with priv.unlock(str(passphrase)):
			decmsg = priv.decrypt(encmsg)
			print(priv.is_unlocked)
	else:
		decmsg = priv.decrypt(encmsg)
	#pmsg = priv.decrypt(encmsg).message
	return decmsg