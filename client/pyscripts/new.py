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
	def  __init__ (self,  chip="UNKNOWN",  name="Data"):
		self.chip  = chip   # NFC chip ID
		self.name  = name   # friendly name

		self.clear()
		self.setup()

	#+=========================================================================
	def  clear (self):
		if 'self.sec' in locals():
			for s in self.sec:
				s.clear()

		self.sCnt = 0   # total sector count
		self.bCnt = 0   # total block count

		self.sec  = []  # sequential and contiguous list of all sectors
		self.blk  = []  # sequential and contiguous list of all blocks

		self.hist = ""  # command history

	#+=========================================================================
	def  history (self):
		return self.hist

	#+=========================================================================
	def  addHist (self, cmd):
		self.hist += "; " + cmd
		return self.hist

	#+=========================================================================
	def  addSec (self,  sectors=1,  blocks=0,  bytes=16):
		for _ in range(sectors):
			s = Sector(blocks, bytes, parent=self)
			s.secN = self.sCnt
			self.sec.append(s)
			self.sCnt += 1

			for b in s.blocks():
				b.blkN = self.bCnt
				self.bCnt += 1
			self.blk.extend(s.blocks())

		return self.sCnt, self.bCnt

	#+=========================================================================
	def  secCnt (self):
		return self.sCnt

	#+=========================================================================
	# All Sectors on the card as a single contiguous list
	def  sectors (self):
		return self.sec

	#+=========================================================================
	# Sectors may not be contiguous (eg. RF08S)
	def  sector (self,  n=0):
		if 0 <= n < sCnt:  return self.sec[n]
		else:              return None

	#+=========================================================================
	def  blkCnt (self):
		return self.bCnt

	#+=========================================================================
	# All Blocks on the card as a single contiguous list
	def  blocks (self):
		return self.sblk

	#+=========================================================================
	# Blocks may not be contiguous (eg. RF08S)
	def  block (self,  n=0):
		if 0 <= n < bCnt:  return self.blk[n]
		else:              return None

	#+=========================================================================
	def  setup (self):
		pass

	#+=========================================================================
	def  uid (self,  sz=4):
		return self.blk[0].hexP[:3*sz],  self.blk[0].hexB[:sz], 

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#    type = f"[{fida:02X}:{fidb:02X}]"            # type/name
 #   if fidb == 0x90:
  #      if fida == 0x01 or fida == 0x03 or fida == 0x04:
   #         type += " - Fudan FM11RF08S"
    #        is08S = True
     #
#    elif fidb == 0x1D:
#        if fida == 0x01 or fida == 0x02 or fida == 0x03:
#            type += " - Fudan FM11RF08"
#
#    elif fidb == 0x91 or fidb == 0x98:
#        type += " - Fudan FM11RF08 (never seen in the wild)"
#
#    else:
#        type += " - Unknown (please report)"
#============================================================================== ========================================
# A 1K card with a backdoor key
#
class  MFC_FM11RF08(MFClassic):
	def  __init__ (self,  name="Data"):
		self.bdKey = ["A31667A8CEC1"]  # backdoor keys

		super().__init__(          \
			chip  = "FM11RF08",    \
			name  = name,          \
		)

	#+=========================================================================
	def  match (self,  blk0):
		if (blk0.hexB[15] == 0x1D) and (blk0.hexB[8] in [0x01, 0x02, 0x03]):
			return True
		return False

	#+=========================================================================
	def setup (self):
		self.addSec(sectors=16, blocks=4, bytes=16)

#============================================================================== ========================================
#============================================================================== ========================================
# a 4K card with variable sector sizes
#
class  MFC_FM11RF32N_18(MFClassic):
	def  __init__ (self,  name="Data"):
		self.bdKey = ["518b3354E760"]  # backdoor keys

		super().__init__(           \
			chip  = "FM11RF32N/18", \
			name  = name,           \
		)

	#+=========================================================================
	def setup(self):
		self.addSec(sectors=32, blocks= 4, bytes=16)
		self.addSec(sectors= 8, blocks=16, bytes=16)

#============================================================================== ========================================
#============================================================================== ========================================
# a 4K card with consistent sector sizes
#
class  MFC_FM11RF32N_20(MFClassic):
	def  __init__ (self,  name="Data"):
		self.bdKey = ["518b3354E760"]  # backdoor keys

		super().__init__(           \
			chip  = "FM11RF32N/20", \
			name  = name,           \
		)

	#+=========================================================================
	def setup (self):
		self.addSec(sectors=64, blocks= 4, bytes=16)

#============================================================================== ========================================
#============================================================================== ========================================
# A 1K card with non-contiguous Sector (and Block) numbering : 
#    {0..15,[16..31], 32, 33}, {0..63, [64..127], 128..135}
#
class  MFC_FM11RF08S(MFClassic):
	def  __init__ (self,  name="Data"):
		self.bdKey = ["A396EFA4E24F"]  # backdoor keys

		super().__init__(          \
			chip  = "FM11RF08S",   \
			name  = name,          \
		)

	#+=========================================================================
	def  match (self,  blk0):
		if (blk0.hexB[15] == 0x90) and (blk0.hexB[8] in [0x01, 0x03, 0x04]):
			return True

	#+=========================================================================
	def setup (self):
		self.addSec(sectors=18, blocks=4, bytes=16)
		for sn in range(16, 17+1):  self.sec[sn].secN = sn +16
		for bn in range(64, 71+1):  self.blk[bn].blkN = bn +64

	#+=========================================================================
	def  sector (self,  n):
		super().sector(n if 0 <= n <= 15 else (n-16))

	#+=========================================================================
	def  block (self,  n):
		super().block(n if 0 <= n <= 63 else (n-64))

#============================================================================== ========================================
#============================================================================== ========================================
class  MFC_DEMO(MFClassic):
	def  __init__ (self,  name="Data"):
		super().__init__(  \
			chip = "DEMO", \
			name = name,   \
		)

	#+=========================================================================
	def setup(self):
		self.addSec(sectors=2, blocks=2, bytes=3)

#++============================================================================ ========================================
MFC_ALL = [           \
	MFC_FM11RF08,     \
	MFC_FM11RF08S,    \
	MFC_FM11RF32N_20, \
	MFC_FM11RF32N_18, \
	MFC_DEMO, \
]

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
#============================================================================== ========================================
class Sector:
	def  __init__ (self,  blocks=0,  bytes=16,  parent=None):
		self.__parent = parent

		self.clear()
		if blocks > 0:
			self.addBlk(blocks, bytes, parent=self)

	#+=========================================================================
	def  clear (self):
		if 'self.blk' in locals():
			for b in self.blk:
				b.clear()

		self.secN = -1  # sector number
		self.bCnt = 0   # block count
		self.blk  = []  # list of blocks {0..bCnt}

		self.keyA = ""  # eg. "112233445566"
		self.keyB = ""
		self.bits = ""

		self.hist = ""  # edit history

	#+=========================================================================
	def  history (self):
		return self.hist

	#+=========================================================================
	def  addHist (self, cmd):
		self.hist += ("; " if len(self.hist) else "") + cmd
		if self.__parent is not None:
			self.__parent.addHist(f"[{self.secN}]"+cmd)
		return self.hist

	#+=========================================================================
	def  addBlk (self,  blocks=1,  bytes=16,  parent=None):
		for _ in range(blocks):
			self.blk.append(Block(bytes, parent=parent))
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
import inspect

class Keyhole:
	NONE     = -1
	A        = 0
	B        = 1
	BACKDOOR = 4

#%=============================================================================
class Block:
	def  __init__ (self,  bytes=0,  parent=None):
		self.__parent = parent

		self.clear()
		if bytes > 0:  self.blank(bytes)

	#+=========================================================================
	def  clear (self):
		self.edit = None   # True/False/None => Edited/Read/Empty

		self.blkN = -1     # block number
		self.hole = -1     # keyhole (used to read block)
		self.keyH = ""     # hex key (used to read block)

		self.lenB = 0      # byte count
		self.text = ""     # ascii text     "XYZ."

		self.hexP = ""     # hex padded     "58 59 5A FF"
		self.hexC = ""     # hex condensed  "58595AFF"
		self.mask = 0      # bit 2^n indicates that hexB[n] is valid
		self.hexB = []     # hex bytes      b'\x58\x59\x5A\xFF'

		self.rdOK = False  # block was successfully read from card (not created by hand)
		self.tryN = 0      # read attempts >= 1 [only valid is rdOK==Tue]

		self.nulV = 0x00   # value      given to null byte
		self.nulH = "--"   # hex string given to null byte
		self.nulC = "?"    # char       given to null byte
		self.notA = "."    # char for not-ascii

		self.hist = ""     # rdbl() read command (`hf mf rdbl...`)

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
	def  history (self):
		return self.hist

	#+=========================================================================
	def  addHist (self, cmd):
		self.hist += ("; " if len(self.hist) else "") + cmd
		if self.__parent is not None:
			self.__parent.addHist(f"[{self.blkN}]"+cmd)
		return self.hist

	#+=========================================================================
	def  blank (self,  n=16):
		self.clear()

		self.lenB = n

		self.hexP = " ".join([self.nulH] *n)  # hex padded     "58 59 5A FF"
		self.hexC =  self.nulH  * n           # hex condensed  "58595AFF"
		self.hexB = [self.nulV] * n           # hex bytes
		self.text =  self.nulC  * n           # ascii text

		self.addHist(f"blank({n})")
		self.edit = None

	#+=========================================================================
	def  rdbl (self,  blkN=0,  hole=Keyhole.NONE,  key="",  retry=3,  end='\n',  quiet=False):
		self.clear()

		# build the PM3 command
		self.blkN = blkN
		cmd       = f"hf mf rdbl --blk {self.blkN}"
		if (hole != Keyhole.NONE):
			self.hole = hole
			cmd      += f" -c {self.hole}"
		if (key  != ""):
			self.keyH = key.replace(" ", "")
			cmd      += f" --key {self.keyH}"
		self.addHist(cmd)

		for self.tryN in range(1, retry+1):
			pRes, pCap = pm3Call(cmd, quiet=(quiet or (self.tryN != 1)), end=end)
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

		self.edit = False
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

		# we don't want to mark a block as dirty unless we need to
		if (self.hexB[idx] == val):  return

		valIn = val

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

		self.edit = True

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
			self.addHist(f"poke({offs},\"{val}\")")
			val = val.replace(" ", "")
			if not all(c in set("0123456789abcdefABCDEF") for c in val):
				return False
			val = list(bytes.fromhex(val))

		elif type(val) == int:
			self.addHist(f"poke({offs},{val:#X})".replace("X","x"))
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
		self.addHist(f"pokeT({offs},{s})")

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
		self.addHist(f"pokeX({offs},{cnt})")

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
		self.pse   = False

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

		self.log = True
		self.pse = False

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
		now = self.pse
		self.pse = True
		return now

	#+=============================================================================
	def  resume (self, state=True):
		self.pse = not state

	#+=============================================================================
	def say(self,  s='',   end='\n',  flush=False,  prompt=-1,  log=True):
		if self.pse is True:    return

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
import inspect

#++============================================
def dumpCard(obj):
	print(f",~~~~| {obj.chip}:{obj.name} |~~~~~~~~~~~~~")
	dump_(obj, "|  ", "")
	print(f"`~~~~~~~~~~~~~~~~~~~~~ /{obj.chip}:{obj.name}")

#++============================================
def dump(obj):
	print(f",~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	dump_(obj, "|  ", "")
	print(f"`~~~~~~~~~~~~~~~~~~~~~")

#++============================================
# The recursive bit
#
def dump_ (obj,  iprev="|  ",  istr=""):
	indent = iprev + istr
	if len(indent) > 30:  sys.exit()

	# collect all the atrributes
	cls = obj.__class__                                    # do not go back up the chain!
	attr_instance = {k: v for k, v in obj.__dict__.items() if not k.endswith("__parent")}
	                                                       # no functions         no private stuff
	attr_class    = {k: v for k, v in cls.__dict__.items() if not callable(v) and not k.startswith('__')}

	# filter duplicates
	attrs = [a for a in attr_instance] \
	      + [a for a in attr_class if a not in attr_instance]
#	print(attrs)

	# parse them
	for attr in attrs:
		entry = getattr(obj, attr, None)

		# iterate through lists
		if isinstance(entry, list):
			if len(entry) == 0:
				# empty list
				print(f"{indent}{attr}: []")
				continue
			print(f"{indent}{attr}: [")

			cnt = 0
			for item in entry:
				# if item is a class - recurse in to it
				if hasattr(item, '__dict__'):
					istr = "   "
					print(f"{indent}{istr},~~~~~~| {attr}[{cnt}] |~~~~~~~~~~~~~")
					dump_(item, indent, istr+"|  ")
					print(f"{indent}{istr}`~~~~~~~~~~~~~~~~~~~~~~~~~~~~ /{attr}[{cnt}]")
					cnt += 1
				else:
					# not a class - wrap strings in quotes
					itemWrap = f'"{item}"' if isinstance(item, str) else item
					istr = "   "
					print(f"{indent}{istr}{itemWrap}")

			# end of list
			print(f"{indent}] /{attr}")

		elif hasattr(entry, '__dict__'):
			# if item is a class - recurse in to it
			print(f"{indent}{attr}:")
			dump_(entry, indent, "¦  ")
			print(f"{indent}`~~~~~~~~~~~~~~~~~ /{attr}")

		else:
			# not a class - wrap strings in quotes
			entryWrap = f'"{entry}"' if isinstance(entry, str) else entry
			print(f"{indent}{attr}: {entryWrap}")

#++============================================================================ ========================================
#++============================================================================ ========================================
#++============================================================================ ========================================
def  mfcIdentify ():
	# load a one-off/stand-alone block
	blk0 = Block()
	blk0.rdbl(0, quiet=True)
	if not blk0.rdOK:
		print(f"Failed to read Manufacturing Data (Block #0)")
		return False

	match = []
	for mfc in MFC_ALL:
		cls = mfc()
		nm = cls.__class__.__name__
		print(f"{nm} ", end='')
		if hasattr(cls, 'match'):
			print(f"match ", end='')
			if cls.match(blk0):
				print(f" ( ok )")
				match.append((nm, mfc))
			else:
				print(f" ( fail )")
		else:
			print(f" nomatch")

	return match


#++============================================================================ ========================================
def  main ():
#	if not checkVer():
#		return
#	args  = parseCli()

	# logfile not started - this will get buffered
	log.say("Welome")

	# run the (known) backdoor key check
	bdKey = getBackdoorKey()
	log.say(f"Found backdoor key: {bdKey}")

	# use getPref() to retrive the dump path from the PM3
	dpath = getPref(Pref.DumpPath) + os.path.sep

	# load a one-off block
	blk0 = Block()
	blk0.rdbl(0, quiet=True)

	if blk0.rdOK is False:
		log.say("Failed to read Block #0", prompt="[!] ")
		sys.exit(9)
	else:
		log.say(blk0.to_json())

	# Idenitfy the card from the manufacturing data
	match = mfcIdentify()
	if   len(match) == 0:
		print("No Chip Signature matches found")
	elif len(match) == 1:
		print(f"Chip Signature matches: {match[0][0]}")
		myCard = match[0][1]()
	else:
		names = []
		names.append(m[0] for m in match)
		print(f"Problem: Multiple Chip Signatures match: {names}")

	dump(myCard)
	sys.exit()

	uid = blk0.hexC[:8]
	dpath = getPref(Pref.DumpPath) + os.path.sep
	logfile = log.start(f"{dpath}hf-mf-{uid}-log.txt")
	log.say("\nLog file: " + color(f"{logfile}", fg="yellow"))

	log.pause()

	# lots of way to modify the data
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

	log.resume()

	card = MFC_DEMO("myCard")
	card.blk[2].poke(0, 0xff)
	card.sec[1].blk[0].poke(1, 0xee)
	dumpCard(card)

	dump(blk0)

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
