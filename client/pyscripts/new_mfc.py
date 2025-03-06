import re

from new_pm3  import *
from new_ansi import c

#%============================================================================= ========================================
# Keyhole names                                                                  Keyhole
#============================================================================== ========================================
class Keyhole:
	A       = 0
	B       = 1
	BD_DFLT = 4

#%============================================================================= ========================================
# Key names                                                                      Key
#============================================================================== ========================================
class Key:
	A       = "A"
	B       = "B"

#%%============================================================================ ========================================
# A MiFare Classic card has Sectors of Blocks                                    MFClassic:  Base Class
#                                                                               ========================================
# __init__   | constructor            | chip, name, desc       | class           |
# clear      | reset to empty card    | -                      | -               |
# setup      | to be overridden       | -                      | -               |
#            |                        |                        |                 |
# get14a     | get {sak, atqa, prng}  | quiet                  | sak, atqa, prng |
# uid        | return card uid        | -                      | uid, bcc        |
# uidIsValid | check uid/bcc          | uid, bcc               | T/F             |
#            |                        |                        |                 |
# note       | add user note          | txt                    | notes[]         |
# notes      | retrieve user notes    | -                      | notes[]         |
# noteClr    | clear user notes       | -                      | -               |
#            |                        |                        |                 |
# addHist    | add to edit history    | cmd                    | history         |
# history    | return edit history    | -                      | history         |
#            |                        |                        |                 |
# addSec     | add sectors            | sectors, blocks, bytes | secCnt, blkCnt  |
# secCnt     | return sector count    | -                      | int             |
# sectors    | return all sectors     | -                      | sectors[]       |
# sector     | return specific sector | n                      | Sector          |
#            |                        |                        |                 |
# secAcl     | return sector acl      | n                      | acl             |
# aclIsValid | check acl bytes        | acl                    | T/F             |
# secAclSet  | set acl for sector     | n, acl                 | sector          |
#            |                        |                        |                 |
# secKey     | return sector key      | n, ab                  | key             |
# secKeySet  | set sector key         | n, ab, key             | sector          |
#            |                        |                        |                 |
# blkCnt     | return block count     | -                      | int             |
# blocks     | return all blocks      | -                      | blocks[]        |
# block      | return specific block  | n                      | Block           |
#            |                        |                        |                 |
# show       | user friendly dump     | header, ascii          | card dump       |
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

	#%+======================================================================== setup
	# This Method MUST be overridden in the inheriting Class
	# It will typically add the Sectors, Blocks, and other Card-specific data
	#
	def  setup (self):
		pass

	#%+======================================================================== get14a
	def  get14a (self, quiet=False):
		self.sak, self.atqa, self.prng = mfcGet14a(quiet)
		return (self.sak, self.atqa, self.prng)

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

	#%+======================================================================== note
	# Add a note to the card
	#
	def  note (self, txt):
		note += [text]
		return self.note

	#%+======================================================================== notes
	# Return the notes for the card
	#
	def  notes (self):
		return self.note

	#%+======================================================================== noteClr
	# Clear all notes
	#
	def  noteClr (self):
		self.note = []

	#%+======================================================================== addHist
	# Add "cmd" to Card history log
	#
	# Returns the FULL Card history log
	#
	def  addHist (self, cmd):
		self.hist += ("; " if len(self.hist) else "") + cmd
		return self.history()

	#%+======================================================================== history
	# Return the edit history for the card
	#
	def  history (self):
		return self.hist

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

		blk = sec.trailer()
		if blk is None:  return None

		if ab == Key.A:
			keyX = "KeyA"
			offs = 0

		elif ab == Key.B:
			keyX = "KeyB"
			offs = 10

		if (blk.lenB < offs+6):  return None
		if not blk.poke(offs, key, 6):  return None

		self.addHist("secKeySet({n},{keyX},{txt})")
		sec.addHist("_aclSet({keyX},{txt})")

		return sec

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
		return self.blk

	#%+======================================================================== block
	# Return Block number 'n'
	# IF Blocks are NOT numbered contiguously (eg. RF08S),
	#   you MUST override this function
	#
	# Blocks may not be contiguous (eg. RF08S)
	#
	def  block (self,  n=0):
		if 0 <= n < self.bCnt:  return self.blk[n]
		else:                   return None

	#%+======================================================================== show
	def  show (self, hdr=False, ascii=True):
		out = ""
		for s in self.sec:
			# dump a sector
			out += s.show(hdr, ascii) + "\n"
			# only 1 header
			hdr = False
			# break between sectors
			if ascii is True:
				out += "|------------|---|-------------------------------------------------|-----.----.----.-----|\n"
			else:
				out += "|------------|---|-------------------------------------------------|\n"

		return out[:-1]

#%%============================================================================ ========================================
# A Sector has Blocks                                                            Sector
#                                                                               ========================================
# __init__ | constructor          | blocks, bytes, parent | -           |
# clear    | reset to empty block | -                     | -           |
#          |                      |                       |             |
# addHist  | add to edit history  | cmd                   | history     |
# history  | return edit history  | -                     | history     |
#          |                      |                       |             |
# addBlk   | add blocks           | blocks, bytes         | blkCnt      |
# blkCnt   | return block count   | -                     | blkCnt      |
# blocks   | return all blocks    | -                     | blocks[]    |
# block    | return a (sub)block  | n                     | Block       |
#          |                      |                       |             |
# trailer  | return the trailer   | -                     | Block       |
# acl      | return the acl       | -                     | acl         |
# aclSet   | set the acl          | acl                   | Sector      |
#          |                      |                       |             |
# keys     | return keys          | ab (first)            | a,b | b,a   |
# keySet   | set keys             | ab, key               | Sector      |
#          |                      |                       |             |
# show     | userfriendly dump    | hdr, ascii            | sector dump |
#
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
	def  clear (self, secN=-1):
		if 'self.blk' in locals():  # will not exist on first call
			for b in self.blk:
				b.clear(b.blkN)

		self.secN = secN  # sector number
		self.bCnt = 0     # block count
		self.blk  = []    # list of blocks {0..bCnt}

		self.hist = ""    # edit history

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

	#%+======================================================================== history
	# Return the edit history for the Sector
	#
	def  history (self):
		return self.hist

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

	#%+======================================================================== blocks
	# Returns the Blocks in the Sector as a single contiguous list
	# (Useful for serialisation)
	#
	def  blocks (self):
		return self.blk

	#%+======================================================================== block
	# return the Nth Block from the Sector
	def  block (self, n):
		if 0 <= n < self.bCnt:  return self.blk[n]
		else:                   return None

	#%+======================================================================== trailer
	# Returns the Sector Trailer
	# This block holds the Keys {A, B} and the ACL bits
	#   ...and some other byte I have yet to fully understand
	#      I think it's just a byte of user data that nobody ever seems to use!
	#
	def  trailer (self):
		if (self.blkCnt() < 1):  return None
		return self.blk[self.blkCnt() -1]

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
	def  keys (self, ab=Key.A):
		if (self.parent != None) and hasattr(self.parent, 'secKey'):
			key1 = self.parent.secKey(self.secN, key.A)
			key2 = self.parent.secKey(self.secN, key.B)
			if ab == Key.B:
				keyx = key1
				key1 = key2
				key2 = keyx
			return key1, key2
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
	def  show (self, hdr=False, ascii=True):
		out = ""
		for b in self.blk:
			out += b.show(hdr, ascii) + "\n"
			hdr = False

		return out[:-1]

#%============================================================================= ========================================
# A Block has Bytes                                                              Block
#                                                                               ========================================
# __init__  | constructor           | -                   | -          |
# clear     | reset block           | -                   | -          |
# blank     | reset & pad           | n                   | -          |
#           |                       |                     |            |
# addHist   | add to history        | cmd                 | history    |
# history   | return history        | -                   | history    |
#           |                       |                     |            |
# rdbl      | read block            | n, hole, key,       |            |
#           |                       |   retry, end, quiet | T/F        |
#           |                       |                     |            |
# __poke    | -private-             |  *magic*            | exception? |
# poke      | poke value to block   | offs, val, limit    | T/F        |
# pokeT     | poke text to block    |  offs, s, limit     | T/F        |
# pokeX     | poke blanks to block  | offs, cnt           | -          |
#           |                       |                     |            |
# isTrailer | last block in sector? | -                   | T/F        |
# show      | userfriendly dump     | -                   | text       |
#
#============================================================================== ========================================
class Block:
	def  __init__ (self,  bytes=0,  parent=None,  blkN=-1):
		self.__parent = parent

		self.clear(blkN, bytes)

	#+========================================================================= clear
	# (Re)initialise a Block (to be empty)
	#
	def  clear (self,  blkN=-1,  bytes=-1):
		self.blkN = blkN   # block number

		self.nulV = 0x00   # value      given to null byte
		self.nulH = "--"   # hex string given to null byte
		self.nulC = "?"    # char       given to null byte
		self.notA = "."    # char for not-ascii

		self.hist = ""     # rdbl() read command (`hf mf rdbl...`)

		self.blank_i(bytes)

	#+========================================================================= blank
	# Reinitialise a Block AND put 'n' bytes of placeholder ("--") data in it
	#
	def  blank (self,  bytes=16):
		self.blank_i(bytes)
		self.addHist(f"blank({bytes})")

	#+========================================================================= blank_i
	def  blank_i (self,  bytes=16):
		self.hole = -1     # keyhole (used to read block)
		self.keyH = ""     # hex key (used to read block)

		self.rdOK = False  # block was successfully read from card (not created by hand)
		self.tryN = 0      # read attempts >= 1 [only valid is rdOK==Tue]
		self.edit = None   # True/False/None => Edited/Read/Empty

		self.lenB = bytes  # byte count
		self.mask = 0      # bit 2^n indicates that hexB[n] is valid

		if self.lenB <= 0:
			self.hexP = ""     # hex padded     "58 59 5A FF"
			self.hexC = ""     # hex condensed  "58595AFF"
			self.hexB = []     # hex bytes      b'\x58\x59\x5A\xFF'
			self.text = ""     # ascii text     "XYZ."

		else: #! will this work for 0 ??
			self.hexP = " ".join([self.nulH] *bytes)  # hex padded     "-- -- -- --"
			self.hexC =  self.nulH  * bytes           # hex condensed  "--------"
			self.hexB = [self.nulV] * bytes           # hex bytes
			self.text =  self.nulC  * bytes           # ascii text

#	#+=========================================================================
#	def  to_dict (self):
#		return self.__dict__
#
#	#+=========================================================================
#	def  to_json (self,  indent=4):
#		return json.dumps(self.to_dict(), indent=indent)
#
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

	#+========================================================================= history
	# Return the edit history for the Sector
	#
	def  history (self):
		return self.hist

	#+========================================================================= rdbl
	# This call out to the PM3 to read a single block
	#
	# The data from the read is parsed in to the Class
	#
	def  rdbl (self,  n=-1,  hole=None,  key="",  retry=3,  end='\n',  quiet=False):
		self.blank_i(self.lenB)

		# build the PM3 command
		cmd = f"hf mf rdbl"

		if (hole != None):
			self.hole = hole
			cmd      += f" -c {self.hole}"

		if (key  != ""):
			self.keyH = key.replace(" ", "")
			cmd      += f" --key {self.keyH}"

		if n == -1:  n = self.blkN
		cmd += f" --blk {n}"

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
		if (self.mask & 1<<idx) and (self.hexB[idx] == val):  return

		valIn = val

		if val == self.nulH:
			val = self.nulV
			hh  = self.nulH
			ch  = self.nulC
			self.mask &= ~(1 << idx)

		else:
			hh = hex(val)[2:].upper().zfill(2)
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
		self.addHist(f"pokeT({offs},\"{s}\")")

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

	#+========================================================================= isTrailer
	def  isTrailer (self):
		if self.__parent is not None:
			sec = self.__parent.secN
			idx = self.blkN - self.__parent.blk[0].blkN
			if idx == self.__parent.bCnt -1:
				return True, sec, idx
			else:
				return False, sec, idx
		return False, -1, -1

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
			out += f"| {c.BBLU}Sector{c.NORM}:{c.BGRN}Blk{c.NORM} |{c.MAG}ACL{c.NORM}| {c.WHT}00 01 02 03 {c.BWHT}04 05 06 07 {c.WHT}08 09 10 11 {c.BWHT}12 13 14 15{c.NORM} |"
			if ascii is True:  out += " ASCII               |"
			out += "\n"

			out += "|------------|---|-------------------------------------------------|"
			if ascii is True:  out += "-----.----.----.-----|"
			out += "\n"

		# sector
		trl, sec, idx = self.isTrailer()
#		tmp = f"{c.BBLU}{sec:#2d}[{idx:#2d}]"
		out += "| " + f"{c.BBLU}{sec:#2d}[{idx:#2d}]" + f"{c.NORM}:{c.BGRN}{self.blkN:#3d}{c.NORM} |"

		# acl
		out += f"{c.MAG} ? {c.NORM}| "

		# hex
		tmp = self.hexP
		# block 0
		if self.blkN == 0:
			s  = c.BCYN + tmp[ 0*3:( 3+1)*3]
			s += c.CYN  + tmp[ 4*3:( 4+1)*3]
			s += c.BGRN + tmp[ 5*3:( 5+1)*3]
			s += c.GRN  + tmp[ 6*3:( 7+1)*3]
			s += c.BYEL + tmp[ 8*3:(15+1)*3]
		# trailer
		elif trl == True:
			s  = c.BYEL + tmp[ 0*3:( 5+1)*3]
			s += c.BMAG + tmp[ 6*3:( 8+1)*3]
			s += c.BBLU + tmp[ 9*3:( 9+1)*3]
			s += c.BYEL + tmp[10*3:(15+1)*3]
		# data
		else:
			s = [tmp[(i+0)*3:(i+4)*3] for i in range(0, len(tmp), 4)]
			s = f"{c.WHT}{s[0]}{c.BWHT}{s[1]}{c.WHT}{s[2]}{c.BWHT}{s[3]}"
		out += s + c.NORM + " |"

		#ascii
		if ascii is True:
			tmp = self.text
			# block 0
			if self.blkN == 0:
				s  = c.BCYN + tmp[ 0: 3+1] + " "
				s += c.CYN  + tmp[ 4: 4+1]
				s += c.BGRN + tmp[ 5: 5+1]
				s += c.GRN  + tmp[ 6: 7+1] + " "
				s += c.BYEL + tmp[ 8:11+1] + " " + tmp[12:15+1]
			# trailer
			elif trl == True:
				s  = c.BYEL + tmp[ 0: 3+1] + " " + tmp[ 4: 5+1]
				s += c.BMAG + tmp[ 6: 7+1] + " " + tmp[ 8: 8+1]
				s += c.BBLU + tmp[ 9: 9+1]
				s += c.BYEL + tmp[10:11+1] + " " + tmp[12:15+1]
			# data
			else:
				s  = c.WHT  + tmp[ 0: 3+1] + " "
				s += c.BWHT + tmp[ 4: 7+1] + " "
				s += c.WHT  + tmp[ 8:11+1] + " "
				s += c.BWHT + tmp[12:15+1]
			out += " " + s + c.NORM + " |"

		return out

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
		lstB = valX
		txt = f"{valX}"

	else:
		return (None, "")

	return (lstB, txt)
