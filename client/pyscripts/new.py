"""
Key:
	#*   Code in global space
	#%%  Class defintion
	#%+  Method defintion
	#!   warning/todo

SAK
	You need to get the SAK from the card itslef
	the copy in block 0 is a "vanity sak"
	and it not required to match the true SAK
	eg. MF1ICS5004

SAK & ATQA
	The SAK and ATQA are fixed on a given Chip
	so this should probably be specified in the Chip's Class overrides
ATS
	I've got no data on ATS at this time

7 & 10 byte UIDs
	No idea at all!   datasheets are NOT forthcoming!

Sector
	need a block() method
	to get a block from within a sector eg. 0..3

dirty/clean edit state needs to ripple up

"""
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

#+-============================================================================ ========================================
# Optional color support .. `pip install ansicolors`
#
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

#============================================================================== ========================================
#                                                                                PM3 Preferences
#============================================================================== ========================================
class Pref:
	DumpPath  = "file.default.dumppath"
	SavePath  = "file.default.savepath"
	TracePath = "file.default.tracepath"

#+=============================================================================
def  getPref (pref):
	p = pm3.pm3()
	p.console("prefs show --json")
	prefs = json.loads(p.grabbed_output)
	return prefs[pref]

#+============================================================================= ========================================
#                                                                                PM3 CLI Interface
#============================================================================== ========================================
def  pm3Call (cmd,  end='\n',  quiet=False):
	p = pm3.pm3()
	if quiet is not True:
		log.say(f"`{cmd}`", end=end)
	pRes = p.console(cmd)
	pCap = p.grabbed_output
	return pRes, pCap

#%%============================================================================ ========================================
# A MiFare Classic card has Sectors of Blocks                                    MFClassic:  Base Class
#
# You will probably never instantiate one these Base Classes directly
#   but if you do, notice that the arguments are in a different order
#   from those provided to an instatiation of a Card Class
#============================================================================== ========================================
class  MFClassic:
	def  __init__ (self,  chip="UNKNOWN",  name="Data",  desc=""):
		self.chip = chip   # NFC chip ID
		self.name = name   # friendly name
		self.desc = desc   # optional descrptive text

		self.clear()
		self.setup()

	#%+======================================================================== clear
	# (Re)initialise the Card (with 0 sectors)
	#
	def  clear (self):
		if 'self.sec' in locals():
			for s in self.sec:
				s.clear()

		self.note = []  # somewhere to take notes

		self.sak  = -1  # Select Acknowledge
		self.atqa = []  # Answer To reQuest
		self.ats  = []  #! Answer To Select (seemingly present on SOME applicable cards!)
		self.prng = ""  # weak/hard/static/etc.

		self.sCnt = 0   # total sector count
		self.bCnt = 0   # total block count

		self.sec  = []  # sequential and contiguous list of all sectors
		self.blk  = []  # sequential and contiguous list of all blocks

		self.hist = ""  # command history

	#%+======================================================================== get14a
	def  get14a (self):
		self.atqa, self.sak, self.prng = mfcGet14a()

	#%+======================================================================== notes
	# Return the notes for the card
	#
	def  notes (self):
		return self.note

	#%+======================================================================== note
	# Add a note to the card
	#
	def  note (self, txt):
		note += [text]
		return self.note

	#%+======================================================================== noteClr
	# Clear all notes
	#
	def  noteClr (self):
		self.note = []

	#%+======================================================================== history
	# Return the edit history for the card
	#
	def  history (self):
		return self.hist

	#%+======================================================================== addHist
	# Add "cmd" to Card history log
	#
	# Returns the FULL Card history log
	#
	def  addHist (self, cmd):
		self.hist += "; " + cmd
		return self.history()

	#%+======================================================================== addSec
	# Add sectors to a 
	# You MAY specify a number of Blocks. And, if do...
	#   You MAY also specify a number of bytes-per-Block (default=16)
	#
	# Returns a tuple of (SectorCount, BlockCount)
	#
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

		return (self.secCnt(), self.blkCnt())

	#%+======================================================================== secCnt
	# Return the number of Sectors on the Card
	#
	def  secCnt (self):
		return self.sCnt

	#%+======================================================================== sectors
	# Return ALL Sectors on the Card as a single contiguous list[]
	# (Useful for serialisation)
	#
	def  sectors (self):
		return self.sec

	#%+======================================================================== sector
	# Return Sector number 'n'
	# IF Sectors are NOT numbered contiguously (eg. RF08S),
	#   you MUST override this function
	#
	def  sector (self,  n=0):
		if 0 <= n < self.sCnt:  return self.sec[n]
		else:                   return None

	#%+======================================================================== blkCnt
	# Return the number of Block on the Card
	#
	def  blkCnt (self):
		return self.bCnt

	#%+======================================================================== blocks
	# Return ALL Blocks on the Card as a single contiguous list[]
	# (Useful for serialisation)
	#
	def  blocks (self):
		return self.sblk

	#%+======================================================================== block
	# Return Block number 'n'
	# IF Blocks are NOT numbered contiguously (eg. RF08S),
	#   you MUST override this function
	#
	# Blocks may not be contiguous (eg. RF08S)
	#
	def  block (self,  n=0):
		if 0 <= n < bCnt:  return self.blk[n]
		else:              return None

	#%+======================================================================== secAcl
	# Return the ACL bits for the specified Sector - as an unpadded Hex String
	# ...or None, if the Sector does exist, or does not have a Trailer,
	#             or the bytes simply aren't present
	#
	# The location of these is (I believe) fixed as being 
	#   bytes[6..8] of the last Block in the Sector
	#
	# This Method MAY be overridden by the Card specific Class
	# ...I know of NO use case for this functionality
	#
	def  secAcl (self, n):
		sec = self.sector(n)
		if sec is None:  return None

		blk = sec.trailer()
		if blk is None:  return None

		if (blk.lenB < 8):  return None

		return blk.hexC[6*2:(8+1)*2]  # bytes {6..8}[3 bytes == 3*2 hex digits]

	#%+======================================================================== aclIsValid
	# Check if the supplied value is a valid ACL
	#
	# Returns: True/False
	#
	# This Method MAY be overridden by the Card specific Class
	# ...I know of NO use case for this functionality
	#
	def  aclIsValid (self, acl):
		b = valxToList(acl)
		if b is None:  return False

		if not 3 <= len(b) <=4:  return False

		if (b[0] &0x0F) != ~((b[1] &0xF0) >>4):  return False  // C1
		if (b[2] &0x0F) != ~((b[0] &0xF0) >>4):  return False  // C2
		if (b[1] &0x0F) != ~((b[2] &0xF0) >>4):  return False  // C3
		# Byte 4 is (still) "reserved", so we do NOT check it

		return True

	#%+======================================================================== secAclSet
	# Set the ACL bits for the specified Sector
	#
	# Returns Modified Sector, or None
	#
	# This Method MAY be overridden by the Card specific Class
	# ...I know of NO use case for this functionality
	#
	def  secAclSet (self, n, acl):
		sec = self.sector(n)
		if sec is None:  return None

		lstB, txt = valxToList(acl)
		if lstB is None:  return None

		blk = sec.trailer()
		if blk is None:  return None

		if (blk.lenB < 8):  return None

		if not self.aclIsValid(acl):  return None

		self.addHist("secAclSet({n},{txt})")
		sec.addHist("_aclSet({txt})")

		if not blk.poke(6, lasB, 3):  return None

		return sec

	#%+======================================================================== secKey
	# Return a Key for the specified Sector - as an unpadded Hex String
	# ...or None, if the Sector does exist, or does not have a Trailer,
	#             or the bytes simply aren't present
	#
	# The location of these is (I believe) fixed as being 
	#   KeyA : bytes[ 0.. 5] of the last Block in the Sector
	#   KeyB : bytes[10..15] of the last Block in the Sector
	#
	# This Method MAY be overridden by the Card specific Class
	# ...I know of NO use case for this functionality
	#
	def  secKey (self, n, ab):
		sec = self.sector(n)
		if sec is None:  return None

		blk = sec.trailer()
		if blk is None:  return None

		if ab == KeyA:
			if (blk.lenB < 6):  return None
			return blk.hexC[0*2:(5+1)*2]    # bytes { 0.. 5}[6 bytes == 6*2 hex digits]

		elif ab == KeyB:
			if (blk.lenB < 16):  return None
			return blk.hexC[10*2:(15+1)*2]  # bytes {10..15}[6 bytes == 6*2 hex digits]

		return None

	#%+======================================================================== secKeySet
	# Set a Key for the specified Sector
	#
	# Returns Modified Sector, or None
	#
	# This Method MAY be overridden by the Card specific Class
	# ...I know of NO use case for this functionality
	#
	def  secKeySet (self, n, ab, key):
		sec = self.sector(n)
		if sec is None:  return None

		lstB, txt = valxToList(acl)
		if lstB is None:  return None

		blk = sec.trailer()
		if blk is None:  return None

		if ab == KeyA:
			keyX = "KeyA"
			offs = 0

		elif ab == KeyB:
			keyX = "KeyB"
			offs = 10

		if (blk.lenB < offs+6):  return None
		if not blk.poke(offs, lstB, 6):  return None

		self.addHist("secKeySet({n},{keyX},{txt})")
		sec.addHist("_aclSet({keyX},{txt})")

		return sec

	#%+======================================================================== setup
	# This Method MUST be overridden in the inheriting Class
	# It will typically add the Sectors, Blocks, and other Card-specific data
	#
	def  setup (self):
		pass

	#%+======================================================================== uid
	# Returns a tuple of ([N]UID, BCC) [BCC == [N]UID Checksum]
	#
	#   UID is bytes {0..3}  ... returned as an PADDED hex string
	#   BCC is byte  {4}     ... returned as an int
	#
	# This default Method retrieves a 4-byte NUID (+BCC)
	# It MAY be overridden (eg. for 7 or 10 byte UIDs)  #! I have no data from which to work :/
	#
	def  uid (self):
		return (self.blk[0].hexP[0*3:((3+1)*3)-1],  self.blk[0].hexB[4])

	#%+======================================================================== uidIsValid
	# Check if the supplied UID matches the supplied BCC
	#
	# Returns: True/False
	#
	#	myCard = MFClassic()
	#	myUID  = "69 96 e3 60"
	#	myBCC  = "7C"
	#	valid, calculated = myCard.uidIsValid(myUID, myBCC)
	#	if valid is False:
	#		if calculated < 0:
	#			print("Bad UID")
	#		else:
	#			print(f"Checksum mismatch. Correct sum would be: {calculated}")
	#	else:
	#		print("Checksum matches UID")
	#
	# This Method MAY be overridden by the Card specific Class
	# ...I know of NO use case for this functionality
	#
	def  uidIsValid (self, uid, bcc=-1):
		b, txt = valxToList(uid)
		if b is None:  return (False, -1)        # uid is not a uid

		if bcc == -1:
			if len(b) != 5:  return (False, -2)  # BCC not provided
			# extract BCC from UID
			bcc = b[4]
			b   = b[:-1]

		if len(b) != 4:  return (False, -4)      # uid length != 4

		chk = reduce(lambda x, y: x ^ y, b)      # perform XOR checksum

		if chk == bcc:  return (True,  chk)
		else:           return (False, chk)

	#%+======================================================================== show
	def  show (self, hdr=False, ascii=True, sep="_"):
		for s in self.sec:
			s.show(hdr, ascii, sep)
			hdr = False

#%%============================================================================ ========================================
# DEMO - Quite simple a programming and test example                             MFClassic( MFC_DEMO )
#============================================================================== ========================================
class  MFC_DEMO(MFClassic):
	def  __init__ (self,  name="Data",  chip="DEMO",  desc=""):
		#
		# You MAY provide a list of known backdoor keys
		# If there are none you may either omit this definition
		#   or define an empty list. eg.  bdKey = []
		# The keys are formatted as a non-padded string of Hex characters
		#
#		self.bdKey = []
#		self.bdKey = [(4, "123456789ABC")]
#		self.bdKey = [(4, "123456789ABC"), (4, "123456789ABC")]

		# NB. The argument order is swapped in the Base Class
		super().__init__(chip=chip, name=name)  

	#%+======================================================================== match
	# This OPTIONAL Method will examine the data from the provided Block #0
	# and try to establish if the signature matches this Card Variant
	#
	# Return: True/False
	#
#	def  match (self,  sak, blk0):
# This is actually (by means of an example) the FM11RF08S signture
#		if (blk0.hexB[15] == 0x90) and (blk0.hexB[8] in [0x01, 0x03, 0x04]):
#			return True
#		return False

	#%+======================================================================== setup
	# The setup() Method SHOULD be provided 
	# It will typically add the correct number of Sectors & Blocks to the card
	# ...But who knows what the future holds :-)
	#
	def setup (self):
# Eg. This adds a (common, 1K) 16 sectors, each of 4 blocks, each containing 16 bytes
		self.addSec(sectors=16, blocks=4, bytes=16)

	#%+======================================================================== sector
	# IF your Sectors ARE numbered contiguously,
	#    you do NOT need to override the sector() function
	#
	# myCard   = MFC_DEMO("myDemo")
	# sectorNr = 7
	# mySector = myCard.sector(sectorNr)
	#
	# Some cards are do NOT have contiguously numbered Sectors
	#   so you are advised NOT to use:
	# mySector = myCard.sec[sectorNr]
	#
	# Yes, I COULD have made 'sec' Private - but I chose not to because
	#   a) I opted to allow the developer the freedom to work as they wish
	#   b) The dumpClass() function does not show Private data - else it explodes (try it!)
	#
#	def  sector (self,  n):
# Eg. This is the FM11RF08S sector() code
#		super().sector(n if 0 <= n <= 15 else (n-16))

	#%+======================================================================== block
	# IF your Blocks ARE numbered contiguously,
	#    you do NOT need to override the block() function
	#
	# myCard   = MFC_DEMO("myDemo")
	# blockNr  = 53
	# myBlock  = myCard.block(blockNr)
	#
	# Some cards are do NOT have contiguously numbered Blocks
	#   so you are advised NOT to use:
	# myBlock  = myCard.blk[blockNr]
	#
#	def  block (self,  n):
# Eg. This is the FM11RF08S block() code
#		super().block(n if 0 <= n <= 63 else (n-64))


#%%============================================================================ ========================================
# FM11RF08 : A 1K MiFare Classic Card with a backdoor key                        MFClassic( MFC_FM11RF08 )
#============================================================================== ========================================
class  MFC_FM11RF08(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM11RF08"):
		# Backdoor Key(s)
		self.bdKey = [ \
			( 4, "A31667A8CEC1"), \
			( 5, "A31667A8CEC1"), \
			( 6, "A31667A8CEC1"), \
			( 7, "A31667A8CEC1"), \
			(12, "A31667A8CEC1"), \
			(13, "A31667A8CEC1"), \
			(14, "A31667A8CEC1"), \
			(15, "A31667A8CEC1"), \
		]

		super().__init__(chip=chip, name=name)

	#%+======================================================================== match
	# Signature match
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  sak == 0x08 \
		and (blk0.hexB[5:(7+1)] == [0x08, 0x04, 0x00]) \
		and (blk0.hexB[15]      == 0x1D) \
		and (blk0.hexB[8]       in [0x01, 0x02, 0x03]) :
			return True
		return False

	#%+======================================================================== setup
	# 16 Sectors, each of 4 blocks, each of 16 bytes
	#
	def setup (self):
		self.addSec(sectors=16, blocks=4, bytes=16)

#%%============================================================================ ========================================
# FM11RF08_RARE : A 1K MiFare Classic Card not previously seen in the wild       MFClassic( MFC_FM11RF08_RARE )
#     The only KNOWN difference between the 'common' and 'rare' FM11RF08 Cards
#     is the signature ...This knowledge was extracted from the Supply-Chain
#     Validation phone app provided by Fudan [@doegox]
#============================================================================== ========================================
class  MFC_FM11RF08_RARE(MFC_FM11RF08):
	def  __init__ (self,  name="Data",  chip="FM11RF08/RARE"):
		super().__init__(name=name, chip=chip)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  sak == 0x08 \
		and (blk0.hexB[5:(7+1)] == [0x08, 0x04, 0x00]) \
		and (blk0.hexB[15]      in [0x91, 0x98]) :
			return True
		return False

#%%============================================================================ ========================================
# FM11RF08S : A 1K MFC Card with non-contiguous Sector and Block numbering       MFClassic( MFC_FM11RF08S )
#============================================================================== ========================================
class  MFC_FM11RF08S(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM11RF08S"):
		self.bdKey = [(4, "A396EFA4E24F")]  # Backdoor Key

		super().__init__(name=name, chip=chip)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  sak == 0x08 \
		and (blk0.hexB[5:(7+1)] == [0x08, 0x04, 0x00]) \
		and (blk0.hexB[8]       in [0x01, 0x03, 0x04]) \
		and (blk0.hexB[15]      == 0x90) :
			return True

	#%+======================================================================== setup
	# The Sectors & Blocks on the FM11RF08S are non-contiguous
	#   Sectors:{0..15, [16.. 31],  32,  33}
	#   Blocks :{0..63, [64..127], 128..135}
	#
	def setup (self):
		self.addSec(sectors=18, blocks=4, bytes=16)
		for sn in range(16, 17+1):  self.sec[sn].secN = sn +16
		for bn in range(64, 71+1):  self.blk[bn].blkN = bn +64

	#%+======================================================================== sector
	def  sector (self,  n):
		super().sector(n if 0 <= n <= 15 else (n-16))

	#%+======================================================================== block
	def  block (self,  n):
		super().block(n if 0 <= n <= 63 else (n-64))

#%%============================================================================ ========================================
# FM11RF32N/20 : A 4K card with consistent sector sizes                          MFClassic( MFC_FM11RF32N_20 )
# The "/20" is the SAK
#============================================================================== ========================================
class  MFC_FM11RF32N_20(MFClassic):
	def  __init__ (self,       \
		name="myData",         \
		chip="FM11RF32N/20",   \
		desc="(64*4)*16 = 4K"  \
	):

		self.bdKey = [(4, "518b3354E760")]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  (sak == 0x20) \
		and (blk0.hexB[8:(15+1)] == [0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69]) :
			return True

	#%+======================================================================== setup
	# 64 Sectors, each of 4 Blocks, each of 16 Bytes
	#
	def setup (self):
		self.addSec(sectors=64, blocks= 4, bytes=16)

#%%============================================================================ ========================================
# FM11RF32N/18 : A 4K card with non-consistent sector sizes                      MFClassic( MFC_FM11RF32N_18 )
# The "/18" is the SAK
#============================================================================== ========================================
class  MFC_FM11RF32N_18(MFClassic):
	def  __init__ (self,                \
		name="myData",                  \
		chip="FM11RF32N/18",            \
		desc="((32*4)+(8*16))*16 = 4K"  \
	):

		self.bdKey = [(4, "518b3354E760")]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  (sak == 0x18) \
		and (blk0.hexB[5:(7+1)] == [0x18, 0x02, 0x00]) \
		and (blk0.text[8:]      == "FDS70V01") :
			return True

#		and (blk0.hexB[5:(15+1)] == [0x18, 0x02, 0x00, 0x46, 0x44, 0x53, 0x37, 0x30, 0x56, 0x30, 0x31]) :
	#%+======================================================================== setup
	# This Card has: 32 Sectors, each of  4 Blocks, each of 16 Bytes
	#   followed by:  8 Sectors, each of 16 Blocks, each of 16 Bytes
	#                40                 256               4096 (4K)
	#
	def setup(self):
		self.addSec(sectors=32, blocks= 4, bytes=16)
		self.addSec(sectors= 8, blocks=16, bytes=16)

#%%============================================================================ ========================================
# FM1208-10 : A "standard" 1K card                                               MFClassic( MFC_FM1208_10 )
#============================================================================== ========================================
class  MFC_FM1208_10(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM1208-10"):
		# Backdoor Key(s)
		self.bdKey = [ \
			( 4, "A31667A8CEC1"), \
			( 5, "A31667A8CEC1"), \
			( 6, "A31667A8CEC1"), \
			( 7, "A31667A8CEC1"), \
			(12, "A31667A8CEC1"), \
			(13, "A31667A8CEC1"), \
			(14, "A31667A8CEC1"), \
			(15, "A31667A8CEC1"), \
		]

		super().__init__(chip=chip, name=name)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  (sak == 0x28) \
		and (blk0.hexB[ 5:( 8+1)] == [0x28, 0x04, 0x00, 0x90]) \
		and (blk0.hexB[9]         in [0x01, 0x03, 0x04]) \
		and (blk0.hexB[10:(15+1)] == [0x15, 0x01, 0x00, 0x00, 0x00, 0x00]) :
			return True

	#%+======================================================================== setup
	# 16 Sectors, each of 4 blocks, each of 16 bytes
	#
	def setup(self):
		self.addSec(sectors=16, blocks=4, bytes=16)

#%%============================================================================ ========================================
# MF1ICS5004 : A "standard" 1K card                                              MFClassic( MF1ICS5004 )
#============================================================================== ========================================
class  MFC_MF1ICS5004(MFClassic):
	def  __init__ (self,  name="Data",  chip="MF1ICS5004"):
		self.bdKey = [(4, "A31667A8CEC1")]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  (sak == 0x28) \
		and (blk0.hexB[ 5:( 8+1)] == [0x28, 0x04, 0x00, 0x90]) \
		and (blk0.hexB[9]         in [0x01, 0x03, 0x04]) \
		and (blk0.hexB[10:(15+1)] == [0x15, 0x01, 0x00, 0x00, 0x00, 0x00]):
			return True

	#%+======================================================================== setup
	# 16 Sectors, each of 4 blocks, each of 16 bytes
	#
	def setup(self):
		self.addSec(sectors=16, blocks=4, bytes=16)

#============================================================================== ========================================
# If you create a new card, remember to add it to this list!                     MFC_ALL
# For speed, put the most common Cards at the top of the list!
#++============================================================================ ========================================
MFC_ALL = [           \
	MFC_FM11RF08,     \
	MFC_FM11RF08S,    \
	MFC_FM11RF32N_20, \
	MFC_FM11RF32N_18, \
	MFC_FM1208_10,    \
	MFC_DEMO, \
]

#%%============================================================================ ========================================
# A Sector has Blocks                                                            Sector
#============================================================================== ========================================
class Sector:
	def  __init__ (self,  blocks=0,  bytes=16,  parent=None):
		self.__parent = parent

		self.clear()
		if blocks > 0:
			self.addBlk(blocks, bytes)

	#%+======================================================================== clear
	# (Re)initialise a Sector (to be empty)
	# This will also clear all the Blocks in the Sector
	#
	def  clear (self):
		if 'self.blk' in locals():  # will not exist on first call
			for b in self.blk:
				b.clear()

		self.secN = -1  # sector number
		self.bCnt = 0   # block count
		self.blk  = []  # list of blocks {0..bCnt}

		self.hist = ""  # edit history

	#%+======================================================================== history
	# Return the edit history for the Sector
	#
	def  history (self):
		return self.hist

	#%+======================================================================== addHist
	# Add "cmd" to Card history log
	#
	# Returns the FULL Sector history log
	#
	def  addHist (self, cmd):
		self.hist += ("; " if len(self.hist) else "") + cmd
		if self.__parent is not None:
			# prepend the Sector number before passing it to the parent
			self.__parent.addHist(f"[{self.secN}]"+cmd)
		return self.history()

	#%+======================================================================== addBlk
	# Add one-or-more Blocks, of n bytes, to a Sector
	#
	# Returns the new BlockCount (for this Sector)
	#
	def  addBlk (self,  blocks=1,  bytes=16):
		for _ in range(blocks):
			self.blk.append(Block(bytes, parent=self))
		self.bCnt += blocks

		return self.blkCnt()

	#%+======================================================================== blkCnt
	# Returns the number of Blocks in the Sector
	#
	def  blkCnt (self):
		return self.bCnt

	#%+======================================================================== block
	#
	def  block (self):
		if 0 <= n < self.bCnt:  return self.blk[n]
		else:                   return None

	#%+======================================================================== blocks
	# Returns the Blocks in the Sector as a single contiguous list
	# (Useful for serialisation)
	#
	def  blocks (self):
		return self.blk

	#%+======================================================================== trailer
	# Returns the Sector Trailer
	# This block holds the Keys {A, B} and the ACL bits
	#   ...and some other byte I have yet to fully understand
	#      I think it's just a byte of user data that nobody ever seems to use!
	#
	def  trailer (self):
		if (self.blkCnt < 1):  return None
		return self.blk[self.blkCnt -1]

	#%+======================================================================== acl
	# Return the ACL bits for this Sector - as an unpadded Hex String
	# ...or None, if :- 
	#   a) the Sector does not have a Parent*
	#   b) the Sector has no Blocks
	#   c) the Trailer Block does not contain enough Bytes
	#
	# *If you wish to play with the ACL of an "orphan" sector...
	# Instead of:
	#    mySector = Sector()
	# Give it a foster parent:
	#    foster = MFClassic()
	#    foster.addSec(sectors=1, blocks=4, bytes=16)
	#    mySector = foster.sector(1)
	# This is because ACL bits may be handled differently on different cards
	#
	def  acl (self):
		if (self.parent != None) and hasattr(self.parent, 'secAcl'):
			return self.parent.secAcl(self.secN)
		return None

	#%+======================================================================== aclSet
	# Attempts to set the ACL bits
	#
	# Returns: Modified Sector, or None
	#   See self.acl() notes on failure conditions and orphan sectors
	#
	def  aclSet (self,  acl):
		if (self.parent != None) and hasattr(self.parent, 'secAclSet'):
			return self.parent.secAclSet(self.secN, acl)
		return None

	#%+======================================================================== key
	# Return the Keys for this Sector - as an unpadded Hex String
	# ...or None if :-
	#   See self.acl() notes on failure conditions and orphan sectors
	#
	def  key (self, ab):
		if (self.parent != None) and hasattr(self.parent, 'secKey'):
			return self.parent.secKey(self.secN, ab)
		return None

	#%+======================================================================== keySet
	# Attempts to set a Key
	#
	# Returns: Modified Sector, or None
	#   See self.acl() notes on failure conditions and orphan sectors
	#
	def  keySet (self,  ab,  key):
		if (self.parent != None) and hasattr(self.parent, 'secKeySet'):
			return self.parent.secKeySet(self.secN, ab, key)
		return None

	#%+======================================================================== show
	def  show (self, hdr=False, ascii=True, sep="_"):
		for b in self.blk:
			b.show(hdr, ascii, sep)
			hdr = False

#%============================================================================= ========================================
# Keyhole names                                                                  Keyhole
#============================================================================== ========================================
class Keyhole:
	NONE     = -1
	A        = 0
	B        = 1
	BACKDOOR = 4

#%============================================================================= ========================================
# Keye names                                                                     Key
#============================================================================== ========================================
class Key:
	NONE     = -1
	A        = "A"
	B        = "B"

#%============================================================================= ========================================
# A Block has Bytes                                                              Block
#============================================================================== ========================================
class Block:
	def  __init__ (self,  bytes=0,  parent=None):
		self.__parent = parent

		self.clear()
		if bytes > 0:  self.blank(bytes)

	#+========================================================================= clear
	# (Re)initialise a Block (to be empty)
	#
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

#	#+=========================================================================
#	def  to_dict (self):
#		return self.__dict__
#
#	#+=========================================================================
#	def  to_json (self,  indent=4):
#		return json.dumps(self.to_dict(), indent=indent)
#
	#+========================================================================= history
	# Return the edit history for the Sector
	#
	def  history (self):
		return self.hist

	#+========================================================================= addHist
	# Add "cmd" to Card history log
	#
	# Returns the FULL Sector history log
	#
	def  addHist (self, cmd):
		self.hist += ("; " if len(self.hist) else "") + cmd
		if self.__parent is not None:
			self.__parent.addHist(f"[{self.blkN}]"+cmd)
		return self.hist

	#+========================================================================= blank
	# Reinitialise a Block AND put 'n' bytes of placeholder ("--") data in it
	#
	def  blank (self,  n=16):
		self.clear()

		self.lenB = n

		self.hexP = " ".join([self.nulH] *n)  # hex padded     "-- -- -- --"
		self.hexC =  self.nulH  * n           # hex condensed  "--------"
		self.hexB = [self.nulV] * n           # hex bytes
		self.text =  self.nulC  * n           # ascii text

		self.addHist(f"blank({n})")
		self.edit = None

	#+========================================================================= rdbl
	# This call out to the PM3 to read a single block
	#
	# The data from the read is parsed in to the Class
	#
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

	#+========================================================================= __poke
	# Private function
	#
	# This "pokes" a single byte in to a Block
	# ...and keeps all the mappings up to date
	#
	# The following wrappers make sure the data is well formatted first
	#
	#   try:
	#      poke( off, val)
	#      pokeT(off, "text")
	#      pokeX(off, len)
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

	#+========================================================================= poke
	# Poke values in to block
	#   poke(0, 0xff)
	#   poke(1, 0xEEDD)
	#   poke(3, "AA BB")
	#   poke(5, "1122")
	#   poke(7, [65,66,67])
	#
	# An optional 'limit' may be imposed by the user to stop buffer overruns
	#
	def  poke (self,  offs,  val,  limit=-1):
		lstB, txt = valxToList(val)
		if lstB == None:  return False
		if not all(0x00 <= n <= 0xFF for n in lstB):  return False

		if limit < 0:
			lstr  = ""
			limit = len(lstB)
		else:
#			if limit > lenB:  full limit will not be used
#			if limit < lenB:  value will be truncated
			lstr  = ",{limit}"

		for i in range(0, limit):
			if limit <= 0:  break
			self.__poke(offs+i, lstB[i])
			limit -= 1

		self.addHist(f"poke({offs},{txt}{lstr})")
		return True

	#+========================================================================= pokeT
	# Patch ASCII (or, in fact, any string)
	#   pokeT(10, datetime.date.today().strftime("%Y-%m-%d"))
	#
	def  pokeT (self,  offs=0,  s=""):
		self.addHist(f"pokeT({offs},{s})")

		if type(s) != str:  return False

		for i in range(0, len(s)):
			self.__poke(offs+i, ord(s[i]))

		return True

	#+========================================================================= pokeX
	# Inavalidate a byte within a block
	# eg. Using a backdoor key to read a trailer
	#     will NOT return the Keys, but WILL return the ACL bits
	#
	def  pokeX (self,  offs=0,  cnt=-1):
		self.addHist(f"pokeX({offs},{cnt})")

		if cnt == -1:
			cnt = self.lenB - offs

		for i in range(offs, offs+cnt):
			self.__poke(i, self.nulH)

	#+========================================================================= show
	# For now I am going to assume that every block is 16 bytes
	# I have plenty of ideas if this turns out to be a bad assumption
	#
	# If the block is orphan, its Sector will be "  [  ]"
	# Block #0 will be dumped as a manufacturing block
	# The Separator may be changed, use "", " ", or None for spaces
	# ASCII may be disabled: 'ascii=False' (keeps output to <80 chars)
	#
	# 0        1         2         3         4         5         6         7         8         9
	# 123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
	# | Sector:Blk |ACL| Hex                                             | ASCII               |
	# |------------+---+-------------------------------------------------+---------------------|
	# |  1[ 0]:  1 | 7 | 00 11 22 33|44|55|66 77|88 99 00 11|12 13 14 15 | .... .... .... .... |
	# |   [ 1]:  1 | 7 | 00 11 22 33|44 55 66 77|88 99 00 11|12 13 14 15 | .... .... .... .... |
	# |   [ 2]:  1 | 7 | 00 11 22 33|44 55 66 77|88 99 00 11|12 13 14 15 | .... .... .... .... |
	# | 40[15]:256 | 7 | 00 11 22 33 44 55|66 77 88|99|10 11 12 13 14 15 | .... .... .... .... |
	# |   [  ]:256 | 7 | 00 11 22 33 44 55|66 77 88|99|10 11 12 13 14 15 | .... .... .... .... |
	#
	def  show (self, hdr=False, ascii=True, sep="."):
		out = ""

		if hdr is True:
			if ascii is True:
				out += "| Sector:Blk |ACL| Hex                                             | ASCII               |\n"
				out += "|------------|---|-------------------------------------------------|-----.----.----.-----|\n"
			else:
				out += "| Sector:Blk |ACL| Hex                                             |\n"
				out += "|------------|---|-------------------------------------------------|\n"

		# sector
		trl = False
		if self.__parent is not None:
			sec = self.__parent.secN
			idx = self.blkN - self.__parent.blk[0].blkN
			if idx == self.__parent.bCnt -1:
				trl = True
			tmp = f"{sec:#2d}[{idx:#2d}]"
		else:
			tmp = "  [  ]"
		# +block
		out += "| " + tmp + f":{self.blkN:#3d} |"

		# acl
		out += " ? | "

		# hex
		tmp = self.hexP
		if sep == None:  sep = " "
		sep = sep + "|"
		sep = sep[:1]
		# block 0
		if self.blkN == 0:
			tmp = tmp[:( 3+1)*3-1] + sep + tmp[( 3+1)*3:]  # uid|
			tmp = tmp[:( 4+1)*3-1] + sep + tmp[( 4+1)*3:]  # bcc|
			tmp = tmp[:( 5+1)*3-1] + sep + tmp[( 5+1)*3:]  # sak|
			tmp = tmp[:( 7+1)*3-1] + sep + tmp[( 7+1)*3:]  # atqa|
			tmp = tmp[:(11+1)*3-1] + sep + tmp[(11+1)*3:]  # ....|....
		# trailer
		elif trl == True:
			tmp = tmp[:( 5+1)*3-1] + sep + tmp[( 5+1)*3:]  # keya|
			tmp = tmp[:( 8+1)*3-1] + sep + tmp[( 8+1)*3:]  # acl|
			tmp = tmp[:( 9+1)*3-1] + sep + tmp[( 9+1)*3:]  # user|keyb
		# data
		else:
			tmp = tmp[:( 3+1)*3-1] + sep + tmp[( 3+1)*3:]  # ....|....|....|....
			tmp = tmp[:( 7+1)*3-1] + sep + tmp[( 7+1)*3:]
			tmp = tmp[:(11+1)*3-1] + sep + tmp[(11+1)*3:]
		out += tmp + " |"

		#ascii
		if ascii is True:
			tmp = self.text
			tmp = tmp[: 4] + " " + tmp[ 4:]
			tmp = tmp[: 9] + " " + tmp[ 9:]
			tmp = tmp[:14] + " " + tmp[14:]
			out += " " + tmp + " |"

		return out

#%============================================================================= ========================================
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

#+============================================================================= ========================================
# Convert the input "value" to a list of bytes
#
# Returns a tuple: (listOfBytes[], stringRepresentation)
#    The "string" is useful for logging
#
# Here are some examples:
#                      |_String_______
#   poke(0, 0xff)        0xFF
#   poke(1, 0xEEDD)      0xEEDD
#   poke(3, "AA BB")     "AA BB"
#   poke(5, "1122")      "1122"
#   poke(7, [65,66,67])  "[65,66,67]"
#
from functools import reduce

def  valxToList (valX):
	#! should I be using `isinstance(x, thing)` ?
	if type(valX) == str:
		lstB = valX.replace(" ", "")
		if not all(c in set("0123456789abcdefABCDEF") for c in lstB):
			return None
		lstB = list(bytes.fromhex(lstB))
		txt = f"\"{valX}\""

	elif type(valX) == int:
		lstB = list(bytes.fromhex(hex(valX)[2:]))
		txt = f"{valX:#X}".replace("X","x")

	elif type(valX) == list:
		print("lkjlkjlklkjlkjl")
		lstB = valX
		txt = f"{valX}"

	else:
		return (None, "")

	return (lstB, txt)

#+============================================================================= ========================================
import inspect

#+============================================================================= dumpCard
def dumpCard(obj):
	print(f",~~~~| {obj.chip}:{obj.name} |~~~~~~~~~~~~~")
	dump_(obj, "|  ", "")
	print(f"`~~~~~~~~~~~~~~~~~~~~~ /{obj.chip}:{obj.name}")

#+============================================================================= dump
def dump(obj):
	print(f",~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	dump_(obj, "|  ", "")
	print(f"`~~~~~~~~~~~~~~~~~~~~~")

#+============================================================================= dump_
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

#+============================================================================= ========================================
import re

def  mfcGet14a ():
	atqa = None
	sak  = None
	prng = None

	pRes, pCap = pm3Call("hf 14a info", quiet=True)
	if pRes != 0:
		log.say("Read fail")
	else:
		for lin in pCap.split('\n'):
			if atqa == None:
				r = r"ATQA: (.. ..)"
				m = re.search(r, lin)
				if m:  atqa = m.group(1)

			if sak == None:
#				r = r"SAK: (.. \[.\])"
				r = r"SAK: (..)"
				m = re.search(r, lin)
				if m:  sak = m.group(1)

			if prng == None:
				r = r"tion\.\.\.\.\.\.\. (.*)"
				m = re.search(r, lin)
				if m:  prng = m.group(1)

	return (atqa, sak, prng)

#+============================================================================= ========================================
def  mfcIdentify (full=False):
	# load a one-off/stand-alone block
	blk0 = Block()
	blk0.rdbl(0, quiet=True)
	if not blk0.rdOK:
		log.say(f"Failed to read Manufacturing Data (Block #0)")
		return False

	atqa, sak, prng = mfcGet14a();
	vsak = blk0.hexC[5*2:(5+1)*2]
	log.say (f"ATQA={atqa} ; SAK={sak} ({vsak}) ; PRNG={prng}")

	match = []
	for mfc in MFC_ALL:
		cls = mfc()
		nm = cls.__class__.__name__
		log.say(f"{nm} ", end='')
		if hasattr(cls, 'match'):
			log.say(f"match ", end='', prompt='')
			if cls.match(sak, blk0):
				log.say(f" \t( ok )", prompt='')
				match.append((nm, mfc))
				if not full:  break
			else:
				log.say(f" \t( fail )", prompt='')
		else:
			log.say(f" nomatch", prompt='')

	return match

#+============================================================================= ========================================
def  mfcBackdoorKeys (quiet=False):
	if quiet is True:  qlog = log.pause()

	klist = []
	for mfc in MFC_ALL:
		cls = mfc()
#		nm = cls.__class__.__name__
		if hasattr(cls, 'bdKey'):
			# exclude duplicates
			klist.extend([k for k in cls.bdKey if k not in klist])

	# sort by keyhole
	# pragmatically, this will makes things more efficient
	klist = sorted(klist, key=lambda x: x[0])

	log.say(f"Trying known backdoor keys: {klist}")

	# at this point in history, we can do this:
	bdKey = ""
	blk0  = Block()

	if blk0.rdbl(quiet=quiet) is False: 
		log.say("Card not detected")
		return None

	for h,k in klist:
		if blk0.rdbl(hole=h, key=k, end='') is True:
			s = color('ok', fg='green')
			log.say(f"    ( {s} )", prompt='')
			bdKey = k
			bdHole = h
			break
		s = color('fail', fg='yellow')
		log.say(f"    ( {s} )", prompt='')

	if bdKey == "":
		log.say("\n No known backdoor key.", prompt="[" + color("!", fg="red") + "]")
		return None, None

	if quiet is True:  log.resume(qlog)
	return bdKey, bdHole

#++============================================================================ ========================================
def  main ():
#	if not checkVer():
#		return
#	args  = parseCli()


#	for i in range (256):
#		print(format(i, "02X").replace("X","x") + "  " + format(i>>4, "04b") + "'" + format(i&15, "04b")+ f"  {i:#3d}  ", end='')
#		pRes, pCap = pm3Call(f"hf mf rdbl --blk {i}", end='', quiet=True)
 #
#		for lin in pCap.split('\n'):
#			if (" | " in lin) and (lin[56] != " "):
#				print(lin)
#				break
#		else:
#			print("Read Fail")
#		
 #
#	sys.exit(0)


	#-----------------------------------------------------
	# logfile not started - this will get buffered
	log.say("Welcome to the start of the demo...")

	#-----------------------------------------------------
	# run the (known) backdoor key check
	log.say(f"\nLet's see if we can jemmy this with a backdoor key...")

	bdKey, bdHole = mfcBackdoorKeys()
	log.say(f"Found backdoor key: {bdHole}/{bdKey}")

	#-----------------------------------------------------
	# Grab the first 4 bytes of block 0 for the logfile name
	log.say(f"\nGenerate the logfile name...")

	blk0 = Block()
	blk0.rdbl(0, quiet=True)

	if blk0.rdOK is False:
		log.say("Failed to read Block #0 - bailing", prompt="[!] ")
		sys.exit(9)

	#-----------------------------------------------------
	# use getPref() to retrive the dump path from the PM3
	dpath = getPref(Pref.DumpPath) + os.path.sep

	#-----------------------------------------------------
	# We do not know what type of card we have yet
	# so we will assume a 4-byte [N]UID
	uid     = blk0.hexC[:8]
	logfile = log.start(f"{dpath}hf-mf-{uid}-log.txt")
	log.say("Log file: " + color(f"{logfile}", fg="yellow"))

	#-----------------------------------------------------
	# Check UID
	# If we want to use the built-in Card processing,
	# we can't do it on a block that doesn't belong to a Card
	#
	# So let's try again:...
	#   Load Block #0 ...but this time, in to a virtual Card
	#
	# Each Card type/chip  knows things about the way data is
	#   stored on that card. So we need to pick a Card.
	# Each specific card knows if it has a {4, 7, 10} byte UID
	# So we cannot auto-extract the UID without having picked a card type
	# If in doubt, we can use the base class - which, as it stands,
	#   assumes a (common) 4-byte [N]UID
	log.say("\nUID Check {pass, fail}...")

	mfc = MFClassic(name="sandpit")  # start with a blank Card
	mfc.addSec(1, 1)                 # add 1 Sector, containing 1 Block (Block #0)
	mfc.blk[0].rdbl(0)               # reload block 0, this time in to our virtual card
	uid, bcc = mfc.uid()             # now we can start using Card processing features

	# Yes, it would probably, on this occasion, been easier to do this
	# But I wanted an excuse to show how it is done "properly"
#	uid = blk0.hexB[0:4]
#	bcc = blk0.hexB[4]

	#-----------------------------------------------------
	# first one should PASS, second should FAIL
	for i in range(0, 1+1):
		log.say(f"  #{i+1} : [{uid} / " + f"{bcc+i:#2X}]"[2:] + ": ", end='')
		ok, chk = mfc.uidIsValid(uid, bcc+i)
		if ok is True:
			log.say("Pass", prompt='')
		else:
			if chk < 0:
				log.say("Bad UID", prompt='')
			else:
				log.say(f"Fail (should be " + f"{chk:#2X})"[2:], prompt='')

	#-----------------------------------------------------
	# Idenitfy the card from the manufacturing data
	# we will ask for the FULL list of all matches (not just the first match)
	log.say("\nTry to identify the card...")

	match = mfcIdentify(full=True)
	if   len(match) == 0:
		log.say("No Chip Signature matches found")
		myCard = MFC_FM11RF08()

	elif len(match) == 1:
		log.say(f"Chip Signature matches: {match[0][0]}")
		myCard = match[0][1]()

	else:
		names = []
		names.append(m[0] for m in match)
		log.say(f"Problem: Multiple Chip Signatures match: {names}")
		sys.exit(9)

	#-----------------------------------------------------
	# show off the two dump functions
	#   1. developers heirarchical data dump
	#   2. user dnump

	# let's pad the sector to 4 blocks first
#mfc.sector(0).addBlk(3)

	# and load the control info
	mfc.get14a()

	log.say("\nDevelopers dump (of card)...")
	dump(mfc)

	log.say("\nUser dump (of card)...")
	log.say(mfc.show(hdr=True))
















	sys.exit()
#	dump(myCard)

	#-----------------------------------------------------
	log.pause()

	#-----------------------------------------------------
	# lots of way to modify the data
	blk0.poke(0, 0xff)
	blk0.poke(1, 0xEEDD)
	blk0.poke(3, "AA BB")
	blk0.poke(5, "1122")
	blk0.poke(7, [65,66,67])
#	log.say(blk0.to_json())

	try:
		blk0.pokeT(10, datetime.date.today().strftime("%Y-%m-%d"))
	except ValueError as e:
		log.say(f"Exception: {e}")

	blk0.pokeX(6, 4)
#	log.say(blk0.to_json())

	#-----------------------------------------------------
	log.resume()

	card = MFC_DEMO("myCard")
	card.blk[2].poke(0, 0xff)
	card.sec[1].blk[0].poke(1, 0xee)
#	dumpCard(card)

	dump(blk0)

#++============================================================================ ========================================
if __name__ == "__main__":
    main()
