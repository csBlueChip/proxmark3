#!/usr/bin/env python3   

# ------------------------------------------------------------------------------
# Imports
#
import re
import os
import sys
import argparse
import pm3
import struct
import json
import datetime
import gc

#============================================================================== ========================================
# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
class Pref:
	DumpPath  = "file.default.dumppath"
	SavePath  = "file.default.savepath"
	TracePath = "file.default.tracepath"

#%=============================================================================
def  getPref (pref):
	p.console("prefs show --json")
	prefs = json.loads(p.grabbed_output)
	return prefs[pref]

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
p = pm3.pm3()

def  pm3Call (cmd,  end='\n',  quiet=False):
	if quiet is not True:
		log.say(f"`{cmd}`", end=end)
	pRes = p.console(cmd)
	pCap = p.grabbed_output
	return pRes, pCap

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#============================================================================== ========================================
class MFClassic:
	def  __init__ (self,  name=""):
		self.clear(name)
		self.setup()

	#+=========================================================================
	def  clear (self,  name=""):
		self.name = name

		self.UID  = ""
		self.mfg  = ""

		self.sCnt = 0   # sector count
		self.sec  = []  # list of sectors

		self.bCnt = 0
		self.blk  = []

	#+=========================================================================
	def  addSec (self,  sectors=1,  blocks=0,  bytes=16):
		for _ in range(sectors):
			s = Sector(blocks, bytes)
			self.sec.append(s)
			self.blk.append(s.blocks)
		self.sCnt += sectors
		self.bCnt += (sectors * blocks)

		return self.sCnt, self.bCnt

	#+=========================================================================
	def  secCnt (self):
		return self.sCnt

	#+=========================================================================
	def  sectors (self):
		return self.sec

	#+=========================================================================
	def  blkCnt (self):
		return self.bCnt

	#+=========================================================================
	def  setup (self):
		pass

	#+=========================================================================
	def  uid (self,  sz=4):
		return self.blk[0].hexP[:3*sz],  self.blk[0].hexB[:sz], 

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#============================================================================== ========================================
class MFC:
	FM11RF32N_18 = 1
	FM11RF32N_20 = 2
	FM11RF08     = 3
	FM11RF08S    = 4

class  MFC_FM11RF08(MFClassic):
	def  __init__ (self):
		super().__init__("FM11RF08")

	#+=========================================================================
	def setup(self):
		self.addSec(sectors=16, blocks=4, bytes=16)

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#============================================================================== ========================================
class Sector:
	def  __init__ (self,  blocks=0,  bytes=16):
		self.clear()
		if blocks > 0:
			self.addBlk(blocks, bytes)

	#+=========================================================================
	def  clear (self):
		self.secN = -1  # sector number
		self.bCnt = 0   # block count
		self.blk  = []  # list of blocks {0..bCnt}

		self.keyA = ""    # eg. "112233445566"
		self.keyB = ""
		self.acl  = 0     # details are card specific

	#+=========================================================================
	def  addBlk (self,  blocks=1,  bytes=16):
		for _ in range(blocks):
			self.blk.append(Block(bytes))
		self.bCnt += blocks

		return self.bCnt

	#+=========================================================================
	def  blkCnt (self):
		return self.bCnt

	#+=========================================================================
	def  blocks (self):
		return self.blk

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#============================================================================== ========================================
"""
[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \\........Y.%._p.
:----,----:----,----:----,----:----,----:----,----:----,----:----,----:----,----:
012345678901234567890123456789012345678901234567890123456789012345678901234567890
0         1         2         3         4         5         6         7         8
"""
class Keyhole:
	NONE     = -1
	A        = 0
	B        = 1
	BACKDOOR = 4

#%=============================================================================
class Block:
	def  __init__ (self,  bytes=0):
		self.clear()
		if bytes > 0:  self.blank(bytes)

	#+=========================================================================
	def  clear (self):
		self.blkN = -1     # block number
		self.hole = -1     # keyhole (used to read block)
		self.keyH = ""     # hex key (used to read block)

		self.lenB = 0      # byte count
		self.text = ""     # ascii text     "XYZ."

		self.hexP = ""     # hex padded     "58 59 5A FF"
		self.hexC = ""     # hex condensed  "58595AFF"
		self.mask = 0      # bit 2^n indicates that hexB[n] is valid
		self.hexB = []     # hex bytes      b'\x58\x59\x5A\xFF'

		self.cmd  = ""     # rdbl() read command (`hf mf rdbl...`)
		self.rdOK = False  # block was successfully read from card (not created by hand)
		self.tryN = 0      # read attempts >= 1 [only valid is rdOK==Tue]

		self.nulV = 0x00   # value      given to null byte
		self.nulH = "--"   # hex string given to null byte
		self.nulC = "?"    # char       given to null byte

		self.notA = "."    # char for not-ascii

	#+=========================================================================
	def  to_dict (self):
		return self.__dict__

	#+=========================================================================
	def  to_json (self,  indent=4):
		return json.dumps(self.to_dict(), indent=indent)

	#+=========================================================================
	def  whoami (self):
		for ref in gc.get_referrers(self):
			if isinstance(ref, dict):
				for key, val in ref.items():
					if val is self:
						return key

	#+=========================================================================
	def  blank (self,  n=16):
		self.clear()

		self.lenB = n

		self.hexP = " ".join([self.nulH] *n)  # hex padded     "58 59 5A FF"
		self.hexC =  self.nulH  * n           # hex condensed  "58595AFF"
		self.hexB = [self.nulV] * n           # hex bytes
		self.text =  self.nulC  * n           # ascii text

		self.cmd  = f"{self.whoami()}.blank({n})"

	#+=========================================================================
	def  rdbl (self,  blkN=0,  hole=Keyhole.NONE,  key="",  retry=3,  end='\n',  quiet=False):
		self.clear()

		self.blkN = blkN
		self.cmd  = f"hf mf rdbl --blk {self.blkN}"
		if (hole != Keyhole.NONE):
			self.hole = hole
			self.cmd += f" -c {self.hole}"
		if (key  != ""):
			self.keyH = key.replace(" ", "")
			self.cmd += f" --key {self.keyH}"

		for self.tryN in range(1, retry+1):
			pRes, pCap = pm3Call(self.cmd, quiet=(quiet or (self.tryN != 1)), end=end)
			if (pRes != 0):  continue  # read fail

			for lin in pCap.split('\n'):
				if (" | " in lin) and (lin[56] != " "):
					self.hexP = re.findall(r'\|\s*(.*?)\s*\|', lin)[0]
					self.hexC = self.hexP.replace(" ", "")
					self.hexB = list(bytes.fromhex(self.hexC))
					self.lenB = len(self.hexB)
					self.text = ''.join(chr(b) if 32 <= b <= 126 else self.notA for b in self.hexB)
					self.rdOK = True
					self.mask = (1 << self.lenB) -1
			if (self.rdOK):  break

		return self.rdOK

	#+=========================================================================
	# Private function
	#   try:
	#      poke( off, val)
	#      pokeT(off, val)
	#      pokeX(off, lenl)
	#   except ValueError as e:
	#      log.say(f"Exception: {e}")
	#
	def  __poke (self, idx,  val):
		if idx >= self.lenB:
			raise ValueError("buffer overflow")

		if val == self.nulH:
			val = self.nulV
			hh  = self.nulH
			ch  = self.nulC
			self.mask &= ~(1 << idx)

		else:
			hh = hex(val)[2:].upper()
			ch = chr(val) if 32 <= val <= 126 else self.notA
			self.mask |= (1 << idx)

		self.hexP      = self.hexP[:idx*3] + hh + self.hexP[(idx*3)+2:]
		self.hexC      = self.hexC[:idx*2] + hh + self.hexC[(idx*2)+2:]
		self.hexB[idx] = val
		self.text      = self.text[:idx]   + ch + self.text[idx+1:]

	#+=========================================================================
	# Poke values in to block
	#   poke(0, 0xff)
	#   poke(1, 0xEEDD)
	#   poke(3, "AA BB")
	#   poke(5, "1122")
	#   poke(7, [65,66,67])
	#
	def  poke (self, offs=0,  val=-1):
		if type(val) == str:
			val = val.replace(" ", "")
			if not all(c in set("0123456789abcdefABCDEF") for c in val):
				return False
			val = list(bytes.fromhex(val))

		elif type(val) == int:
			val = list(bytes.fromhex(hex(val)[2:]))

		elif isinstance(val, list):
			pass

		else:
			return False

		for i in range(0, len(val)):
			self.__poke(offs+i, val[i])

		return True

	#+=========================================================================
	# Patch ASCII (or, in fact, any string)
	#   pokeT(10, datetime.date.today().strftime("%Y-%m-%d"))
	#
	def  pokeT (self, offs=0,  s=""):
		if type(s) != str:  return False

		for i in range(0, len(s)):
			self.__poke(offs+i, ord(s[i]))

		return True

	#+=========================================================================
	# Inavalidate a byte within a block
	# eg. Using a backdoor key to read a trailer
	#     will NOT return the Keys, but WILL return the ACL bits
	#
	def  pokeX (self, offs=0,  cnt=-1):
		if cnt == -1:
			cnt = self.lenB - offs

		for i in range(offs, offs+cnt):
			self.__poke(i, self.nulH)

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#============================================================================== ========================================
class Log:
	def  __init__ (self):
		self.buf   = ''
		self.fspec = None

		# Prompt: default, in-use, enable_flag
		self.prDF  = "[" + color("=", fg="yellow") + "] "
		self.prUse = self.prDF
		self.prEn  = True

		self.log   = False  # start() has been executed
		self.pause = False

	#+=============================================================================
	def  start (self,  fspec,  append=False):
		self.fspec = fspec

		if append is False:
			# erase file
			with open(self.fspec, 'w'):
				pass

		# if input was sent prior to this, flush it now
		if self.buf != '':
			with open(self.fspec, 'a') as f:
				f.write(self.buf)
			self.buf = ''

		self.log   = True
		self.pause = False

		return fspec

	#+=============================================================================
	def  promptSet (self,  prompt = -1):
		if prompt == -1:  prompt = self.prDF
		self.prUse = prompt

	#+=============================================================================
	def  promptEnable (self,  enable=True):
		self.prEn = enable

	#+=============================================================================
	def  promptDisable (self,  enable=True):
		self.prEn = not enable

	#+=============================================================================
	def  on (self,  enable=True):
		self.log = enable

	#+=============================================================================
	def  off (self,  enable=True):
		self.log = not enable

	#+=============================================================================
	def  pause (self):
		now = self.pause
		self.pause = True
		return now

	#+=============================================================================
	def  resume (self, state):
		self.pause = state

	#+=============================================================================
	def say(self,  s='',   end='\n',  flush=False,  prompt=-1,  log=True):
		if self.pause is True:  return

		if prompt == -1:        prompt = self.prUse
		if self.prEn is False:  prompt = ""

		s = f"{prompt}" + f"\n{prompt}".join(s.split('\n'))
		print(s, end=end, flush=flush)

		# if the logfile is yet to be defined, buffer the input
		if self.log is True:
			if self.fspec is not None:
				with open(self.fspec, 'a') as f:
					f.write(s + end)
			else:
				# buffering
				self.buf += s + end

log = Log()

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
def  main ():
#	if not checkVer():
#		return
#	args  = parseCli()

	# No logfile name yet
	log.say("Welome")

	dpath = getPref(Pref.DumpPath) + os.path.sep

	bdKey = getBackdoorKey()
	if bdKey is None:
		log.say("No backdoor key")

	blk0 = Block()
	blk0.rdbl(0, quiet=True)
	log.say(blk0.to_json())

	uid = blk0.hexC[:8]
	logfile = log.start(f"{dpath}hf-mf-{uid}-log.txt")
	log.say("\nLog file: " + color(f"{logfile}", fg="yellow"))


	blk0.poke(0, 0xff)
	blk0.poke(1, 0xEEDD)
	blk0.poke(3, "AA BB")
	blk0.poke(5, "1122")
	blk0.poke(7, [65,66,67])
	log.say(blk0.to_json())

	try:
		blk0.pokeT(10, datetime.date.today().strftime("%Y-%m-%d"))
	except ValueError as e:
		log.say(f"Exception: {e}")

	blk0.pokeX(6, 4)
	log.say(blk0.to_json())

	c = MFC_FM11RF08()
	print(c)

#++============================================================================ ========================================
def  getBackdoorKey (quiet=False):
	if quiet is True:  qlog = log.pause()

	#          FM11RF08S        FM11RF08        FM11RF32
	klist = ["A396EFA4E24F", "A31667A8CEC1", "518b3354E760"]
	bdKey = ""
	blk0  = Block()

	log.say("Trying known backdoor keys...")

	for k in klist:
		if blk0.rdbl(hole=Keyhole.BACKDOOR, key=k, end='') is True:
			s = color('ok', fg='green')
			log.say(f"    ( {s} )", prompt='')
			bdKey = k
			break
		s = color('fail', fg='yellow')
		log.say(f"    ( {s} )", prompt='')

	if bdKey == "":
		log.say("\n Unknown key, or card not detected.", prompt="[" + color("!", fg="red") + "]")
		return None

	if quiet is True:  log.resume(qlog)
	return bdKey



#++============================================================================ ========================================
if __name__ == "__main__":
    main()
