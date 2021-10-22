from random import randint
from hashlib import sha256

def bytes_to_int(a):
	return sum([a[i] << ((len(a)-1)-i)*8  for i in range(len(a))])

def block(a, b):
	return [a >> i & (2**b)-1 for i in reversed(range(0,128,b))]

def deblock(a,b):
	return [(a[0]<<b*3|a[1]<<b*2|a[2]<<b|a[3]) >> i & 0xFF for i in reversed(range(0,128,8))]

def PAD(m, block=16): #Padding based on PKCS#7
	n = len(m)%block
	return m + (chr(block - n)*(block - n)).encode()

def UNPAD(m):
	return m[:-m[-1]]

def CHUNK(s, l): #Split string to equal parts of equal length
	return [s[i:i+l] for i in range(0, len(s), l)]

def ROL(a, n, b):
	return (a << n) & (2**b)-1 |(a >> (b - n))

def ROR(a, n, b):
	return (a >> n)|(a << (b - n)) & (2**b)-1

def SHL(a, n, b):
	return (a << n) & (2**b)-1

def ADD(a, b, n):
	return (a + b)%2**n

def MUL(a, b, n):
	return (a * b) % 2**n

def XOR(a, b):
	return a ^ b

def Generate_Key(): #generates random 256-bit key in hex
	with open("chimera.key", "wb") as f:
		f.write(f"{''.join([f'{randint(0,255):02X}' for i in range(16)])}".encode())
		f.close()

class Chimera:
	def __init__(self, key):
		self.r = 10

        #Serpent S-Box
		self.Sbox = (
					(3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12), #S0
					(15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4), #S1
					(8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2), #S2
					(0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14), #S3
					(1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13), #S4
					(15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1), #S5
					(7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0), #S6
					(1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6)) #S7

		self.k = self.KeySchedule(key)

	def Sbox_LookUp(self, m, r):
		r = r%8
		return [(((self.Sbox[r][(i >> 4)&0xF] << 4)&0xFF)|(self.Sbox[r][i&0xF])) for i in m]

	def Permutate(self, a):
		#32-bit permutation box
		P_box = (
		10, 12,  4,  6,  2, 28, 31, 18,
		22,  1, 19, 17, 16,  9, 23, 30,
		14, 20,  5,  7,  8, 25, 21, 11,
		13, 26, 24,  0, 15,  3, 29, 27)

		return int(''.join([f"{a:032b}"[i] for i in P_box]),2)

	def KeySchedule(self, key):
		w = block(int(key[:32].decode(),16),16) #split given key to 8 blocks

		count = ((self.r*4)+8)*2 #calculate numbers of words need to from keys
		for i in range(8, 8+count):
			w.append(ROL((w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9E3779B9 ^ i), 11, 16) % 0xFFFF)
		w = w[8:] #strip off given key blocks
		r = 0 #keep track of round
		for i in range(0, len(w), 2):
			b = (3-r)%8 #choose s-box
			w[i] = bytes_to_int(self.Sbox_LookUp([w[i]>>8&0xFF,w[i]&0xFF], b))
			w[i+1] = bytes_to_int(self.Sbox_LookUp([w[i+1]>>8&0xFF,w[i+1]&0xFF], b))
			r += 1
		return [self.Permutate(w[i]<<16|w[i+1]) for i in range(0,len(w),2)]

	def Whitening(self, a, k):
		return [a[i]^self.k[i+k] for i in range(4)]

	def MDS(self, a): 
		M = (
			(0x01, 0xEF, 0x5B, 0x5B),
			(0x5B, 0xEF, 0xEF, 0x01),
			(0xEF, 0x5B, 0x01, 0xEF),
			(0xEF, 0x01, 0xEF, 0x5B))

		#Matrix multiplication adapted from:
		#https://medium.com/@stevenrouk/the-art-of-problem-solving-one-line-matrix-multiplication-list-comprehension-in-python-f65fbe01d1a9
		return bytes_to_int([i for s in [[sum([x*y for (x, y) in zip(row, col)])%256 for col in zip(*[[i] for i in a])] for row in M] for i in s])

	def Function_g(self, a, r):
		return self.MDS(self.Sbox_LookUp([a>>i&0xFF for i in reversed(range(0,32,8))], r))

	def IDEA_Encrypt(self, p1, p2, p3, p4, k, r):
		p1 = MUL(p1,k[0],16) #1. MUL p1 & k1
		p2 = ADD(p2,k[1],16) #2. ADD p2 & k2
		p3 = ADD(p3,k[2],16) #3. ADD p3 & k3
		p4 = MUL(p4,k[3],16) #4. MUL p4 & k4
		x1 = XOR(p1, p3) #5. XOR p1 & p3
		x2 = XOR(p2, p4) #6. XOR p2 & p4
		x1 = MUL(x1, XOR(k[0], k[1]),16) #7. MUL x1 & k5
		x2 = ADD(x2, x1,16) #8. ADD x2 & x1
		x2 = MUL(x2, XOR(k[2], k[3]),16) #9. MUL x2 & k6
		x1 = ADD(x1, x2,16) #10. ADD x1 & x2
		p1 = XOR(p1, x2) #11. XOR p1 & x2
		p3 = XOR(p3, x2) #12. XOR p3 & x2
		p2 = XOR(p2, x1) #13. XOR p2 & x1
		p4 = XOR(p4, x1) #14. XOR p4 & x1
		return p1,p3,p2,p4

	def RC6_Encrypt(self, a, b, c, d, k, r, lgw = 5):
		b, d = ADD(b, k[0], 16), ADD(d, k[1], 16)
		tmp1, tmp2 = ROL((b*(2*b + 1))%0xFFFF,lgw,16), ROL((d*(2*d + 1))%0xFFFF,lgw,16)
		return ADD(ROL(c^tmp2, tmp1%16, 16), k[3], 16), c, d, ADD(ROL(a^tmp1, tmp2%16, 16), k[2], 16)

	def LT(self, x0, x1, x2, x3):
		x0 = ROL(x0,7,32)
		x2 = ROL(x2,3,32)
		x1 = x1 ^ x0 ^ x2
		x3 = x3 ^ x2 ^ SHL(x0,2,32)
		x1 = ROL(x1,1,32)
		x3 = ROR(x3,9,32)
		x0 = x0 ^ x1 ^ x3
		x2 = x2 ^ x3 ^ SHL(x1,3,32)
		x0 = ROL(x0,5,32)
		x1 = ROL(x1,3,32)
		x2 = ROL(x2,11,32)
		return [x0, x1, x2, x3]

	def InvLT(self, x0, x1, x2, x3):
		x2 = ROR(x2,11,32)
		x1 = ROR(x1,3,32)
		x0 = ROR(x0,5,32)
		x2 = x2 ^ x3 ^ SHL(x1,3,32)
		x0 = x0 ^ x1 ^ x3
		x3 = ROL(x3,9,32)
		x1 = ROR(x1,1,32)
		x3 = x3 ^ x2 ^ SHL(x0,2,32)
		x1 = x1 ^ x0 ^ x2
		x2 = ROR(x2,3,32)
		x0 = ROR(x0,7,32)
		return [x0, x1, x2, x3]

	def PHT(self, a, b):
		return (a+b)%0xFFFFFFFF, (a+(2*b))%0xFFFFFFFF

	def Expand(self, a, b, k0, k1):
		return (a + k0)%0xFFFFFFFF, (b + k1)%0xFFFFFFFF

	def XTEA_Encrypt(self, v0, v1, k):
		return v0 + XOR((v1<<4 ^ v1>>5) + v1, 0x9E3779B9 + k) & 0xFFFFFFFF

	def XTEA_Decrypt(self, v0, v1, k):
		return v0 - XOR((v1<<4 ^ v1>>5) + v1, 0x9E3779B9 + k) & 0xFFFFFFFF

	def Function_f(self, r0, r1, r):
		k = (self.k[(r*4+8)], self.k[(r*4+9)], self.k[(r*4+10)], self.k[(r*4+11)])
		g0, g1 = self.Function_g(XOR(r0, k[0]), r), self.Function_g(ROL(XOR(r1, k[1]),8,32), r)
		if r % 2 == 0: #even rounds
			g = self.IDEA_Encrypt(g0>>16, g0&0xFFFF, g1>>16, g1&0xFFFF, (k[2]>>16,k[2]&0xFFFF,k[3]>>16,k[3]&0xFFFF), r)
		else: #odd rounds
			g = self.RC6_Encrypt(g0>>16, g0&0xFFFF, g1>>16, g1&0xFFFF, (k[2]>>16,k[2]&0xFFFF,k[3]>>16,k[3]&0xFFFF), r)
		a, b = self.PHT(g[0]<<16|g[1], g[2]<<16|g[3])
		return self.Expand(XOR(a, b), b, XOR(k[0],k[2]), XOR(k[1],k[3]))

	def Encrypt(self, m):
		m = self.Whitening(block(bytes_to_int(m[:16]), 32),0)
		
		for r in range(self.r):
			tmp0, tmp1 = self.Function_f(m[0], self.XTEA_Encrypt(m[1], m[0], self.k[(r*4+8)]), r)
			m[2] = XOR(m[2],tmp1)	
			m[3] = self.XTEA_Encrypt(XOR(ROL(m[3],3,32), tmp0),m[2], self.k[(r*4+11)])
			m[0], m[1], m[2], m[3] = m[2], m[3], m[0], m[1]
			m = self.LT(m[0], m[1], m[2], m[3])
		m[0], m[1], m[2], m[3] = m[2], m[3], m[0], m[1]

		return bytes(deblock(self.Whitening(m,4),32))

	def Decrypt(self, m):
		m = self.Whitening(block(bytes_to_int(m[:16]), 32),4)

		m[0], m[1], m[2], m[3] = m[2], m[3], m[0], m[1]
		for r in reversed(range(self.r)):
			m = self.InvLT(m[0], m[1], m[2], m[3])
			tmp0, tmp1 = self.Function_f(m[2], self.XTEA_Encrypt(m[3], m[2], self.k[(r*4+8)]), r)
			m[1] = ROR(XOR(self.XTEA_Decrypt(m[1],m[0], self.k[(r*4+11)]), tmp0),3,32)
			m[0] = XOR(m[0],tmp1)
			m[0], m[1], m[2], m[3] = m[2], m[3], m[0], m[1]

		return bytes(deblock(self.Whitening(m,0),32))

'''Mode of operations'''
'''
Electronic Code Book ECB
Each 256-bit block is encrypted with the same key.
The hash is appended to the back and encrypted with the key.
'''
class Chimera_ECB_SHA256:
	def __init__(self, key):
		self.chimera = Chimera(key)
		self.hash = lambda x: sha256(x).digest()

	def ECB(self, m, mode):
		return (b''.join(map(mode, CHUNK(m,16))))

	def Encrypt_SHA256(self, m):
		return self.ECB(PAD(m), self.chimera.Encrypt) + self.ECB(self.hash(m), self.chimera.Encrypt)

	def Decrypt_SHA256(self, m):
		e = UNPAD(self.ECB(m[:-32], self.chimera.Decrypt))
		if self.hash(e) == self.ECB(m[-32:], self.chimera.Decrypt) : return e
		raise Exception("Hash do not match")

class Chimera_CBC_SHA256:
	def __init__(self, key):
		self.chimera = Chimera(key)
		self.hash = lambda x: sha256(x).digest()

	def XOR(self, a, b):
		return [a[i] ^ b[i] for i in range(len(a))]

	def Encrypt_SHA256(self, m):
		m, IV = CHUNK(PAD(m), 16) + CHUNK(self.hash(m),16), bytes((randint(0,255) for i in range(16)))
		iv = IV
		for i in range(len(m)):
			m[i] = self.chimera.Encrypt(self.XOR(m[i], iv))
			iv = m[i]
		return self.chimera.Encrypt(IV) + b''.join(m)

	def Decrypt_SHA256(self, m):
		m = CHUNK(m,16)
		IV, m = self.chimera.Decrypt(m[0]), m[1:]
		for i in range(len(m)):
			m[i], IV = bytes(self.XOR(self.chimera.Decrypt(m[i]),IV)), list(m[i])
		m = b''.join(m)
		if self.hash(UNPAD(m[:-32])) == m[-32:] : return UNPAD(m[:-32])
		raise Exception("Hash do not match")

class Chimera_CTR_SHA256:
	def __init__(self, key):
		self.chimera = Chimera(key)
		self.hash = lambda x: sha256(x).digest()

	def XOR(self, a, b):
		return [a[i] ^ b[i] for i in range(len(a))]

	def Encrypt_SHA256(self, m):
		m, Nonce, Counter = CHUNK(PAD(m), 16) + CHUNK(self.hash(m), 16), bytes((randint(0,255) for i in range(8))), bytearray(8)
		for i in range(len(m)):
			Counter[(7-(i//256))%8] = i%256
			m[i] = bytes(self.XOR(self.chimera.Encrypt(Nonce+Counter),m[i]))
			if Counter[0] == 255:
				Counter = bytearray(8)
		return self.chimera.Encrypt(PAD(Nonce)) + b''.join(m)

	def Decrypt_SHA256(self, m):
		m, Nonce, Counter = CHUNK(m[16:],16), UNPAD(self.chimera.Decrypt(m[:16])), bytearray(8)
		for i in range(len(m)):
			Counter[(7-(i//256))%8] = i%256
			m[i] = bytes(self.XOR(self.chimera.Encrypt(Nonce+Counter),m[i]))
			if Counter[0] == 255:
				Counter = bytearray(8)
		m = b''.join(m)
		if self.hash(UNPAD(m[:-32])) == m[-32:] : return UNPAD(m[:-32])
		raise Exception("Hash do not match")