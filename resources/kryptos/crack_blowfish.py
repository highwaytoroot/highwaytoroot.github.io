with open('creds.txt','rb') as file:
	creds = file.read()

# header: [12:magic][8:salt][8:CFB IV]
pure = creds[12:]

aa = pure[:8] # salt
ab = pure[8:16] # cfb IV
ac = pure[16:24] # username
ad = pure[24:32] # " / -begin pass"
ae = pure[32:40] # pass
af = pure[40:42] # pass


def xsec(key, sec):
	# sec is a string, key is an array of ints
	return ([chr(key[i] ^ ord(sec[i])) for i in range(0,len(sec))])
	

# Attack to plaintext: I know that ac is the xor of the key with the original content and such content is known. 
str = "rijndael"

i=0
key = []
# Iterate the piece of known information
for i in range(0,8):
	# With all the possible bytes (2^8=256)
	for a in range(0,256):
		# ord = from char, returns integer, which can be xored; chr = from integer, returns char.
		r = chr(ord(ac[i])^a)
		if r == str[i]:
			# a is a number representing a char
			key.append(a)

# integers representing char
print key


a1 = ''.join(xsec(key,ac))
a2 = ''.join(xsec(key,ad))
a3 = ''.join(xsec(key,ae))
a4 = ''.join(xsec(key,af))

print a1+a2+a3+a4