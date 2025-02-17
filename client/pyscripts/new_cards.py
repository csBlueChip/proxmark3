# IF YOU CREATE A NEW CARD, REMEMBER TO ADD IT TO THE LIST AT THE END !

from new_mfc import MFClassic, Sector, Block, Key, Keyhole

#%%============================================================================ ========================================
# 1K as 16*4*16                                                                  MFClassic( MFC_1k )
#============================================================================== ========================================
class  MFC_1K(MFClassic):
	def  __init__ (self,  name="Data",  chip="1K",  desc=""):
		super().__init__(chip=chip, name=name)

	#%+======================================================================== setup
	# Create 16 contiguous Sectors, each of 4 Blocks, each of 16 bytes
	def setup (self):
		self.addSec(sectors=16, blocks=4, bytes=16)

#%%============================================================================ ========================================
# 4K as 64*4*16 (SAK=20)                                                         MFClassic( MFC_4k_64 )
#============================================================================== ========================================
class  MFC_4K_64(MFClassic):
	def  __init__ (self,  name="Data",  chip="4K/64",  desc=""):
		super().__init__(chip=chip, name=name)

	#%+======================================================================== setup
	# Create 64 Sectors, each of 4 Blocks, each of 16 bytes
	#
	def setup (self):
		self.addSec(sectors=64, blocks=4, bytes=16)

#%%============================================================================ ========================================
# 4K as 32*4*16 + 8*16*16  (SAK=18)                                              MFClassic( MFC_4k_40 )
#============================================================================== ========================================
class  MFC_4K_40(MFClassic):
	def  __init__ (self,  name="Data",  chip="4K/40",  desc=""):
		super().__init__(chip=chip, name=name)

	#%+======================================================================== setup
	# Create       32 Sectors, each of  4 Blocks, each of 16 bytes
	# followed by   8 Sectors, each of 16 Blocks, each of 16 bytes
	#
	def setup (self):
		self.addSec(sectors=32, blocks= 4, bytes=16)
		self.addSec(sectors= 8, blocks=16, bytes=16)

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
# FM11RF08 : A 1K MiFare Classic Card with a backdoor key                        MFC_1K( MFC_FM11RF08 )
#============================================================================== ========================================
class  MFC_FM11RF08(MFC_1K):
	def  __init__ (self,  \
		name="Data",      \
		chip="FM11RF08",  \
		desc="Fudan 1K with backdoor" \
	):

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
	def  match (self,  sak,  blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  sak == 0x08 \
		and (blk0.hexB[5:(7+1)] == [0x08, 0x04, 0x00]) \
		and (blk0.hexB[15]      == 0x1D) \
		and (blk0.hexB[8]       in [0x01, 0x02, 0x03]) :
			return True

		return False

#%%============================================================================ ========================================
# FM11RF08_RARE : A 1K MiFare Classic Card not previously seen in the wild       MFC_1K( MFC_FM11RF08_RARE )
#     The only KNOWN difference between the 'common' and 'rare' FM11RF08 Cards
#     is the signature ...This knowledge was extracted from the Supply-Chain
#     Validation phone app provided by Fudan [@doegox]
#============================================================================== ========================================
class  MFC_FM11RF08_RARE(MFC_FM11RF08):
	def  __init__ (self,       \
		name="Data",           \
		chip="FM11RF08/RARE",  \
		desc="Fudan 1K: Rare, please report." \
	):

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
# FM11RF08S : A 1K MFC Card with non-contiguous Sector and Block numbering       MFC_1K( MFC_FM11RF08S )
#============================================================================== ========================================
class  MFC_FM11RF08S(MFC_1K):
	def  __init__ (self,   \
		name="Data",       \
		chip="FM11RF08S",  \
		desc="Fudan 1k w/ supply chain sectors" \
	):
		# Backdoor Key(s)
		self.bdKey = [ \
			( 4, "A396EFA4E24F"), \
			( 5, "A396EFA4E24F"), \
			( 6, "A396EFA4E24F"), \
			( 7, "A396EFA4E24F"), \
			(12, "A396EFA4E24F"), \
			(13, "A396EFA4E24F"), \
			(14, "A396EFA4E24F"), \
			(15, "A396EFA4E24F"), \
		]

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

		return False

	#%+======================================================================== setup
	# The Sectors & Blocks on the FM11RF08S are non-contiguous
	#   Sectors:{0..15, [16.. 31],  32,  33}
	#   Blocks :{0..63, [64..127], 128..135}
	#
	def setup (self):
		self.addSec(sectors=18, blocks=4, bytes=16)
		# renumber the last 2 Sectors / 8 Blocks
		for sn in range(16, 17+1):  self.sec[sn].secN = sn +16
		for bn in range(64, 71+1):  self.blk[bn].blkN = bn +64

	#%+======================================================================== sector
	def  sector (self,  n):
		# map from card_number to array_entry
		super().sector(n if 0 <= n <= 15 else (n-16))

	#%+======================================================================== block
	def  block (self,  n):
		# map from card_number to array_entry
		super().block(n if 0 <= n <= 63 else (n-64))

#%%============================================================================ ========================================
# FM11RF32N/20 : A 4K card with consistent sector sizes                          MFC_4K_64( MFC_FM11RF32N_20 )
# The "/20" is the SAK
#============================================================================== ========================================
class  MFC_FM11RF32N_20(MFC_4K_64):
	def  __init__ (self,       \
		name="myData",         \
		chip="FM11RF32N/20",   \
		desc="(64*4)*16 = 4K"  \
	):

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

		return False

	#%+======================================================================== setup
	# 64 Sectors, each of 4 Blocks, each of 16 Bytes
	#
	def setup (self):
		self.addSec(sectors=64, blocks= 4, bytes=16)

#%%============================================================================ ========================================
# FM11RF32N/18 : A 4K card with non-consistent sector sizes                      MFC_4k_40( MFC_FM11RF32N_18 )
# The "/18" is the SAK
#============================================================================== ========================================
class  MFC_FM11RF32N_18(MFC_4K_40):
	def  __init__ (self,      \
		name="myData",        \
		chip="FM11RF32N/18",  \
		desc="((32*4)+(8*16))*16 = 4K"  \
	):

		self.bdKey = [ \
			( 4, "518b3354E760"), \
			( 5, "518b3354E760"), \
			( 6, "518b3354E760"), \
			( 7, "518b3354E760"), \
			(12, "518b3354E760"), \
			(13, "518b3354E760"), \
			(14, "518b3354E760"), \
			(15, "518b3354E760"), \
		]

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
# FM1208-10 : A "standard" 1K card                                               MFC_1K( MFC_FM1208_10 )
#============================================================================== ========================================
class  MFC_FM1208_10(MFC_1K):
	def  __init__ (self,   \
		name="Data",       \
		chip="FM1208-10",  \
		desc="Fudan 1K with backdoor"  \
	):

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

#%%============================================================================ ========================================
# MF1ICS5004 : A "standard" 1K card                                              MFC_1K( MFC_MF1ICS5004 )
#============================================================================== ========================================
class  MFC_MF1ICS5004(MFClassic):
	def  __init__ (self,    \
		name="Data",        \
		chip="MF1ICS5004",  \
		desc="NXP 1K with backdoor"  \
	):

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
		and (blk0.hexB[10:(15+1)] == [0x15, 0x01, 0x00, 0x00, 0x00, 0x00]):
			return True

#%%============================================================================ ========================================
# SARAH : A 4K card from an unknown origin                                       SARAH
#============================================================================== ========================================
class  MFC_SARAH(MFC_4K_40):
	def  __init__ (self,                \
		name="myData",                  \
		chip="SARAH",                   \
		desc="4K (40/sak=18) mystery card"  \
	):

		super().__init__(chip=chip, name=name, desc=desc)

	#%+======================================================================== match
	# Signature matching algorithm
	#
	def  match (self,  sak, blk0):
		lstB, txt = valxToList(sak)
		if len(lstB) != 1:  return False
		sak = lstB[0]

		if  (sak == 0x18) \
		and (blk0.hexB[5:(7+1)] == [0x98, 0x02, 0x00]) \
		and (blk0.hexB[8:]      == [0xE3, 0x46, 0x00, 0x20, 0x00, 0x00, 0x00, 0x17]) :
			return True

#============================================================================== ========================================
# If you create a new card, remember to add it to this list!                     MFC_ALL
# For speed, put the most common Cards at the top of the list!
#++============================================================================ ========================================
MFC_ALL = [  \
	MFC_FM11RF08,     \
	MFC_FM11RF08S,    \
	MFC_FM11RF32N_20, \
	MFC_FM11RF32N_18, \
	MFC_FM1208_10,    \
	MFC_MF1ICS5004,   \
	MFC_DEMO, \
	MFC_SARAH, \
]
