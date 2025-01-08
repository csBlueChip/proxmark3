"""
	#*   Code in global space
	#%%  Class defintion
	#%+  Method defintion
	#!   warning/todo
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
	p.console("prefs show --json")
	prefs = json.loads(p.grabbed_output)
	return prefs[pref]

#*============================================================================= ========================================
#                                                                                PM3 CLI Interface
#============================================================================== ========================================
p = pm3.pm3()

#+=============================================================================
def  pm3Call (cmd,  end='\n',  quiet=False):
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
	def  __init__ (self,  chip="UNKNOWN",  name="Data"):
		self.chip  = chip   # NFC chip ID
		self.name  = name   # friendly name

		self.clear()
		self.setup()

	#%+======================================================================== clear
	# (Re)initialise the Card (with 0 sectors)
	#
	def  clear (self):
		if 'self.sec' in locals():
			for s in self.sec:
				s.clear()

		self.sCnt = 0   # total sector count
		self.bCnt = 0   # total block count

		self.sec  = []  # sequential and contiguous list of all sectors
		self.blk  = []  # sequential and contiguous list of all blocks

		self.hist = ""  # command history

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
		if 0 <= n < sCnt:  return self.sec[n]
		else:              return None

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
		b = valxToLst(acl)
		if b is None:  return False

		if not 3 <= len(b) <=4:  return False

		if (b[0] &0x0F) != ~((b[1] &0xF0) >>4):  return False  // C1
		if (b[2] &0x0F) != ~((b[0] &0xF0) >>4):  return False  // C2
		if (b[1] &0x0F) != ~((b[2] &0xF0) >>4):  return False  // C3
		// Byte 4 is (still) "reserved", so we do NOT check it

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

		lstB, txt = valxToLst(acl)
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

		lstB, txt = valxToLst(acl)
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
	# It MAY be overridden (eg. for 7 or 10 byte UIDs)  #! I don't know how
	#
	def  uid (self):
		return (self.blk[0].hexP[0*3:(3+1)*3],  self.blk[0].hexB[4])

	#%+======================================================================== aclIsValid
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
	def  uiddIsValid (self, uid, bcc=-1):
		b = valxToLst(acl)
		if b is None:  return (False, -1)        # uid is not a uid

		if bcc = -1:
			if len(b) != 5:  return (False, -2)  # BCC not provided
			# extract BCC from UID
			bcc = b[4]
			b   = b[:-1]

		if len(b) != 4:  return (False, -4)      # uid length != 4

		chk = reduce(lambda x, y: x ^ y, b)      # perform XOR checksum

		if chk == bcc:  return (False, chk)
		else:           return (True, chk)

#%%============================================================================ ========================================
# DEMO - Quite simple a programming and test example                             MFClassic( MFC_DEMO )
#============================================================================== ========================================
class  MFC_DEMO(MFClassic):
	def  __init__ (self,  name="Data",  chip="DEMO"):
		#
		# You MAY provide a list of known backdoor keys
		# If there are none you may either omit this definition
		#   or define an empty list. eg.  bdKey = []
		# The keys are formatted as a non-padded string of Hex characters
		#
#		self.bdKey = []
#		self.bdKey = ["123456789ABC"]
#		self.bdKey = ["123456789ABC", "123456789ABC"]

		# NB. The argument order is swapped in the Base Class
		super().__init__(chip=chip, name=name)  

	#%+========================================================================
	# This OPTIONAL Method will examine the data from the provided Block #0
	# and try to establish if the signature matches this Card Variant
	#
	# Return: True/False
	#
#	def  match (self,  blk0):
# This is actually (by means of an example) the FM11RF08S signture
#		if (blk0.hexB[15] == 0x90) and (blk0.hexB[8] in [0x01, 0x03, 0x04]):
#			return True
#		return False

	#%+========================================================================
	# The setup() Method SHOULD be provided 
	# It will typically add the correct number of Sectors & Blocks to the card
	# ...But who knows what the future holds :-)
	#
	def setup (self):
# Eg. This adds a (common, 1K) 16 sectors, each of 4 blocks, each containing 16 bytes
		self.addSec(sectors=16, blocks=4, bytes=16)

	#%+========================================================================
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

	#%+========================================================================
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
		self.bdKey = ["A31667A8CEC1"]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+========================================================================
	# Signature match
	#
	def  match (self,  blk0):
		if (blk0.hexB[15] == 0x1D) and (blk0.hexB[8] in [0x01, 0x02, 0x03]):
			return True
		return False

	#%+========================================================================
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

	#%+========================================================================
	# Signature matching algorithm
	#
	def  match (self,  blk0):
		if (blk0.hexB[15] == 0x1D) and (blk0.hexB[8] in [0x01, 0x02, 0x03]):
			return True
		return False

#%%============================================================================ ========================================
# FM11RF08S : A 1K MFC Card with non-contiguous Sector and Block numbering       MFClassic( MFC_FM11RF08S )
#============================================================================== ========================================
class  MFC_FM11RF08S(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM11RF08S"):
		self.bdKey = ["A396EFA4E24F"]  # Backdoor Key

		super().__init__(name=name, chip=chip)

	#%+========================================================================
	# Signature matching algorithm
	#
	def  match (self,  blk0):
		if (blk0.hexB[15] == 0x90) and (blk0.hexB[8] in [0x01, 0x03, 0x04]):
			return True

	#%+========================================================================
	# The Sectors & Blocks on the FM11RF08S are non-contiguous
	#   Sectors:{0..15, [16.. 31],  32,  33}
	#   Blocks :{0..63, [64..127], 128..135}
	#
	def setup (self):
		self.addSec(sectors=18, blocks=4, bytes=16)
		for sn in range(16, 17+1):  self.sec[sn].secN = sn +16
		for bn in range(64, 71+1):  self.blk[bn].blkN = bn +64

	#%+========================================================================
	def  sector (self,  n):
		super().sector(n if 0 <= n <= 15 else (n-16))

	#%+========================================================================
	def  block (self,  n):
		super().block(n if 0 <= n <= 63 else (n-64))

#%%============================================================================ ========================================
# FM11RF32N/20 : A 4K card with consistent sector sizes                          MFClassic( MFC_FM11RF32N_20 )
# The "/20" is the SAK
#============================================================================== ========================================
class  MFC_FM11RF32N_20(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM11RF32N/20"):
		self.bdKey = ["518b3354E760"]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+========================================================================
	# Signature matching algorithm
	#
	def  match (self,  blk0):
		sak = blk0.hexB[5]  # I need test cards with 7 & 10 
		if (sak == 0x20) and \
		   (blk0.hexB[8:(15+1)] == [0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69]):
			return True

	#%+========================================================================
	# 64 Sectors, each of 4 Blocks, each of 16 Bytes
	#
	def setup (self):
		self.addSec(sectors=64, blocks= 4, bytes=16)

#%%============================================================================ ========================================
# FM11RF32N/18 : A 4K card with non-consistent sector sizes                      MFClassic( MFC_FM11RF32N_18 )
# The "/18" is the SAK
#============================================================================== ========================================
class  MFC_FM11RF32N_18(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM11RF32N/18"):
		self.bdKey = ["518b3354E760"]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+========================================================================
	# Signature matching algorithm
	#
	def  match (self,  blk0):
		sak = blk0.hexB[5]  # I need test cards with 7 & 10 
		if (sak == 0x18) and \
		   (blk0.hexB[5:(15+1)] == [0x18, 0x02, 0x00, 0x46, 0x44, 0x53, 0x37, 0x30, 0x56, 0x30, 0x31]):
			return True

	#%+========================================================================
	# This Card has: 32 Sectors, each of  4 Blocks, each of 16 Bytes
	#   followed by:  8 Sectors, each of 16 Blocks, each of 16 Bytes
	#
	def setup(self):
		self.addSec(sectors=32, blocks= 4, bytes=16)
		self.addSec(sectors= 8, blocks=16, bytes=16)

#%%============================================================================ ========================================
# FM1208-10 : A "standard" 1K card                                               MFClassic( MFC_FM1208_10 )
#============================================================================== ========================================
class  MFC_FM1208-10(MFClassic):
	def  __init__ (self,  name="Data",  chip="FM1208-10"):
		self.bdKey = ["A31667A8CEC1"]  # Backdoor Key

		super().__init__(chip=chip, name=name)

	#%+========================================================================
	# Signature matching algorithm
	#
	def  match (self,  blk0):
		sak = blk0.hexB[5]  # I need test cards with 7 & 10 
		if (sak == 0x28) and \
		   (blk0.hexB[ 5:( 8+1)] == [0x28, 0x04, 0x00, 0x90]) and \
		   (blk0.hexB[9]         in [0x01, 0x03, 0x04]) and \
		   (blk0.hexB[10:(15+1)] == [0x15, 0x01, 0x00, 0x00, 0x00, 0x00]):
			return True

	#%+========================================================================
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
	MFC_FM1208-10,    \
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
			self.addBlk(blocks, bytes, parent=self)

	#%+========================================================================
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

	#%+========================================================================
	# Return the edit history for the card
	#
	def  history (self):
		return self.hist

	#%+========================================================================
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

	#%+========================================================================
	# Add one-or-more Blocks, of n bytes, to a Sector
	#
	# Returns the new BlockCount (for this Sector)
	#
	def  addBlk (self,  blocks=1,  bytes=16):
		for _ in range(blocks):
			self.blk.append(Block(bytes, parent=self))
		self.bCnt += blocks

		return self.blkCnt()

	#%+========================================================================
	# Returns the number of Blocks in the Sector
	#
	def  blkCnt (self):
		return self.bCnt

	#%+========================================================================
	# Returns the Blocks in the Sector as a single contiguous list
	# (Useful for serialisation)
	#
	def  blocks (self):
		return self.blk

	#%+========================================================================
	# Returns the Sector Trailer
	# This block holds the Keys {A, B} and the ACL bits
	#   ...and some other byte I have yet to fully understand
	#      I think it's just a byte of user data that nobody ever seems to use!
	#
	def  trailer (self):
		if (self.blkCnt < 1):  return None
		return self.blk[self.blkCnt -1]

	#%+========================================================================
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
		if (self.parent != None) and (hasattr(self.parent, 'secAcl'):
			return self.parent.secAcl(self.secN)
		return None

	#%+========================================================================
	# Attempts to set the ACL bits
	#
	# Returns: Modified Sector, or None
	#   See self.acl() notes on failure conditions and orphan sectors
	#
	def  aclSet (self,  acl):
		if (self.parent != None) and (hasattr(self.parent, 'secAclSet'):
			return self.parent.secAclSet(self.secN, acl)
		return None

	#%+========================================================================
	# Return the Keys for this Sector - as an unpadded Hex String
	# ...or None if :-
	#   See self.acl() notes on failure conditions and orphan sectors
	#
	def  key (self, ab):
		if (self.parent != None) and (hasattr(self.parent, 'secKey'):
			return self.parent.secKey(self.secN, ab)
		return None

	#%+========================================================================
	# Attempts to set a Key
	#
	# Returns: Modified Sector, or None
	#   See self.acl() notes on failure conditions and orphan sectors
	#
	def  keySet (self,  ab,  key):
		if (self.parent != None) and (hasattr(self.parent, 'secKeySet'):
			return self.parent.secKeySet(self.secN, ab, key)
		return None

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
	# An optional 'limit' may be imposed by the user to stop buffer overruns
	#
	def  poke (self, offs,  val,  limit=-1):
		lstB, txt = valxToList(val)
		if lstB == None:  return False
		if not all(0x00 <= n <= 0xFF for n in lstB):  return False

		if limit < 0:
			lstr  = ""
			limit = len(lstB)
		else
#			if limit > lenB:  full limit will not be used
#			if limit < lenB:  value will be truncated
			lstr  = ",{limit}"

		for i in range(0, limit):
			if limit <= 0:  break
			self.__poke(offs+i, put[i])
			limit -= 1

		self.addHist(f"poke({offs},{txt}{lstr})")
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
def  valxToList (valX)
	#! should I be using `isinstance(x, thing)` ?
	if type(valX) == str:
		lstB = valX.replace(" ", "")
		if not all(c in set("0123456789abcdefABCDEF") for c in lstB):
			return None
		lstB = list(bytes.fromhex(lstB))
		txt = f"\"{valX}\""

	elif type(valX) == int:
		lstB = list(bytes.fromhex(hex(valX)[2:]))
		txt = f"{valX:#X}".replace("X","x"))

	elif type(valX) == list:
		lstB = valX
		txt = f"{valX}"

	else:
		return None

	return (lstB, txt)

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
