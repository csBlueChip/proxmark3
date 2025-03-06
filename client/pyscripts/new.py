"""
doegox' id algorithm
https://gist.github.com/doegox/1ddc5725d0f6e3e58a023f6ffbff0d8c


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
#import  pm3

from  new_ansi   import  c    # colour
from  new_log    import  log  # logging
from  new_pm3    import  *    # proxmark API
from  new_mfc    import  *    # mfc classes & helper funtions
from  new_cards  import  *    # known cards

from fm11rf08s_recovery import recovery

import  re                    # regex
import  os                    # OS speific (eg. dir slash)
import  sys                   # system API
import  argparse              # CLI argument parser
import  datetime              # date & time processing

#import  struct                # C struct data
#import  json                  # JSON processor
#import  gc                    # Garbage Collector

#+============================================================================= ========================================
# Parse the CLi argument
MFC_none = 0x00
MFC_1k   = 0x08
MFC_4k40 = 0x18
MFC_4k64 = 0x20

def  parseCli ():
	p = argparse.ArgumentParser(description='Demo script')

	p.add_argument('--1k',   action='store_const', const=MFC_1k,   dest='size', help='assume 16*4*16 = 1K')
	p.add_argument('--4k64', action='store_const', const=MFC_4k40, dest='size', help='assume 64*4*16 = 4K (SAK=20)')
	p.add_argument('--4k40', action='store_const', const=MFC_4k64, dest='size', help='assume 32*4*16 + 8*16*16 = 4K (SAK=18)')

	p.set_defaults(size=MFC_none)

	args = p.parse_args()
	return args

#+============================================================================= ========================================
#import inspect
#import builtins

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

#+============================================================================= printHex
# like `print`, but handle numbers as padded hex
#
def  printHex (*args,  **kwargs):
	hex_args = [
		f'0x{arg:02X}' if isinstance(arg, int) and arg <= 0xFF   else
		f'0x{arg:04X}' if isinstance(arg, int) and arg <= 0xFFFF else
		f'0x{arg:08X}' if isinstance(arg, int) else arg
		for arg in args
	]
	print(*hex_args, **kwargs)

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
					printHex(f"{indent}{istr}", itemWrap)

			# end of list
			print(f"{indent}] /{attr}")

		elif hasattr(entry, '__dict__'):
			# if item is a class - recurse in to it
			print(f"***********************************{indent}{attr}:")
			dump_(entry, indent, "¦  ")
			print(f"{indent}`~~~~~~~~~~~~~~~~~ /{attr}")

		else:
			# not a class - wrap strings in quotes - expand the "mask" in Blocks
			if   isinstance(entry, str):  entry = f'"{entry}"'
			elif attr == "mask"        :  entry = "0x" + format(entry, "04X") + " -> " + format(entry, "016b")[::-1]
			print(f"{indent}{attr}: ", entry)

#+============================================================================= ========================================
#import re

def  mfcGetInfo (nack=False, quiet=False,  end="\n"):
	uid   = None
	atqa  = None
	sak   = None
	prng  = None
	nonce = ""
	nval  = ""
	nack  = None  #! todo

	pRes, pCap = pm3Call("hf mf info", quiet=quiet, end=end)
	if pRes != 0:
		log.say("Read fail")
	else:
		for lin in pCap.split('\n'):
			if uid == None:
				r = r"UID: (.*)"
				m = re.search(r, lin)
				if m:  uid = m.group(1)

			if atqa == None:
				r = r"ATQA: (.. ..)"
				m = re.search(r, lin)
				if m:  atqa = m.group(1)

			if sak == None:
				r = r"SAK: (..)"
				m = re.search(r, lin)
				if m:  sak = m.group(1)

			if prng == None:
				r = r"Prng\.* (.*)"
				m = re.search(r, lin)
				if m:  prng = m.group(1)

			# the nonce output is a right mish mash of randomness
			if nonce == "":
				if " nonce..." in lin:
					if "........." in lin:
						r = r"\.\.\.\. (.*)"
						m = re.search(r, lin)
						if m:  nval = m.group(1)
					else:
						nonce = "static"
						if " enc "   in lin:  nonce += "+encrypted"
						if " nested" in lin:  nonce += "+nested"
						nonce += f":{nval}"

	return {'uid':uid,  'atqa':atqa,  'sak':sak,  'prng':prng,  'nonce':nonce,  'nack':nack}

#+============================================================================= ========================================
def  mfcIdentify (hole,  key,  full=False,  quiet=False):
	# load a one-off/stand-alone block
	blk0 = Block()
	blk0.rdbl(0, hole=hole, key=key, quiet=quiet, end='')
	if not blk0.rdOK:
		log.say(" - Failed to read Manufacturing Data (Block #0)", prompt='')
		return None, None
	else:
		log.say(f" : {blk0.hexP}", prompt='')

	info = mfcGetInfo(quiet=quiet, end='');  # (atqa, sak, prng, nonce, nack)
	sak  = info['sak']
	vsak = blk0.hexC[5*2:(5+1)*2]
	log.say(f" : ATQA={info['atqa']} ; SAK={info['sak']} ({vsak}) ; " + 
	        f"PRNG={info['prng']} ; nonce={info['nonce']}", prompt='')

	if not quiet: log.say ("Checking database...")
	match = []
	for mfc in MFC_ALL:
		cls = mfc()
		nm  = cls.__class__.__name__
		log.say(f"  {nm} ", end='')
		if hasattr(cls, 'match'):
			log.say(f"match ", end='', prompt='')
			if cls.match(sak, blk0):
				log.say(f" \t( {c.GRN}ok{c.NORM} )", prompt='')
				match.append((nm, mfc))
				if not full:  break  # break after first match
			else:
				log.say(f" \t( {c.RED}fail{c.NORM} )", prompt='')
		else:
			log.say(f" nomatch", prompt='')

	return info, match

#+============================================================================= ========================================
def  mfcGuessKey (card=None,  blk=None,  klist=None):

	if card is None:
		if blk is None:
			log.say("No attack vector")
			return None, None
		if blk >= 0:    # block specified (positive number, eg. 10 means block #10)
			#!sanity check
			cnt = blk
		else:           # block count specified (negative number, eg. -10 is 10 blocks {0..9})
			#!sanity check
			cnt = -blk

		card        = MFClassic(1,cnt,16)   # a card with 1 sector of 'cnt' block with 16 bytes
		sector      = card.sector(0)
		sector.secN = 0
		for b in range(0, cnt):             # number the blocks
			sector.block(b).blkN = b

	else:  # Card provided
		if blk is None:      # all blocks on card
			cnt = card.bCnt
		if blk >= 0:         # block specified (positive number, eg. 10 means block #10)
			#!sanity check
			cnt = blk
		else:                # block count specified (negative number, eg. -10 is 10 blocks {0..9})
			#!sanity check
			cnt = -blk

	blist = card.blocks()

	# the caller may append 1 or more keys to the start of the list
	if (type(klist) == str) or (type(klist) == int):
		klist = [klist]

# this list stolen straight out of client/src/mifare/mifaredefault.h
	klist += [
		"d3f7d3f7d3f7",  # NDEF public key
		"4b791bea7bcc",  # MFC EV1 Signature 17 B
		"5C8FF9990DA2",  # MFC EV1 Signature 16 A
		"D01AFEEB890A",  # MFC EV1 Signature 16 B
		"75CCB59C9BED",  # MFC EV1 Signature 17 A
		"707B11FC1481",  # MFC QL88 Signature 17 B
		"2612C6DE84CA",  # MFC QL88 Signature 17 A
		"fc00018778f7",  # Public Transport
		"6471a5ef2d1a",  # SimonsVoss
		"4E3552426B32",  # ID06
		"6A1987C40A21",  # Salto
		"ef1232ab18a0",  # Schlage
		"3B7E4FD575AD",  #
		"b7bf0c13066e",  # Gallagher
		"135b88a94b8b",  # Saflok
		"2A2C13CC242A",  # Dorma Kaba
		"5a7a52d5e20d",  # Bosch
		"314B49474956",  # VIGIK1 A
		"564c505f4d41",  # VIGIK1 B
		"021209197591",  # BTCINO
		"484558414354",  # Intratone
		"EC0A9B1A9E06",  # Vingcard
		"66b31e64ca4b",  # Vingcard
		"97F5DA640B18",  # Bangkok metro key
		"A8844B0BCA06",  # Metro Valencia key
		"E4410EF8ED2D",  # Armenian metro
		"857464D3AAD1",  # HTC Eindhoven key
		"08B386463229",  # troika
		"e00000000000",  # icopy
		"199404281970",  # NSP A
		"199404281998",  # NSP B
		"6A1987C40A21",  # SALTO
		"7F33625BC129",  # SALTO
		"484944204953",  # HID
		"204752454154",  # HID
		"3B7E4FD575AD",  # HID
		"11496F97752A",  # HID
		"3E65E4FB65B3",  # Gym
		"000000000000",  # Blank key
		"9C28A60F7249",  # ICT
		"C9826AF02794",  # ICT
		"010203040506",
		"1a2b3c4d5e6f",
		"123456789abc",
		"123456abcdef",
		"abcdef123456",
		"aabbccddeeff",
		"4d3a99c351dd",
		"1a982c7e459a",
		"714c5c886e97",
		"587ee5f9350f",
		"a0478cc39091",
		"533cb6c723f6",
		"8fd0a4f256e9",
		"0000014b5c31",
		"b578f38a5c61",
		"96a301bce267",
	]










	# first we'll try ffffffffffff in ALL slots
	ff = "FFFFFFFFFFFF"
	for sec in card.sectors():
		if sec.block(0).rdbl(hole=Keyhole.A, key=ff):  return key, Keyhole.A
		if sec.block(0).rdbl(hole=Keyhole.B, key=ff):  return key, Keyhole.B

	# NFCForum MAD key A
#	log.say
	if card.sector(0).block(0).rdbl(hole=Keyhole.A, key="a0a1a2a3a4a5"):  return "a0a1a2a3a4a5", Keyhole.A
	# NFCForum MAD key B
	if card.sector(0).block(0).rdbl(hole=Keyhole.B, key="b0b1b2b3b4b5"):  return "b0b1b2b3b4b5", Keyhole.B
	# NFCForum MAD key B
	if card.sector(0).block(0).rdbl(hole=Keyhole.B, key="89ECA97F8C2A"):  return "89ECA97F8C2A", Keyhole.B

	# now we will try all the other keys in every slot
	for k in klist:
		k = k.replace(" ","")
		for sec in card.sectors():
			if sec.block(0).rdbl(hole=Keyhole.A, key=k):  return k, Keyhole.A
			if sec.block(0).rdbl(hole=Keyhole.B, key=k):  return k, Keyhole.B

	return None, None

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
	# pragmatically, this will make things more efficient
	klist = sorted(klist, key=lambda x: x[0])

	log.say(f"Trying known backdoor keys: {klist}", end='')

	# at this point in history, we can do this:
	bdKey = ""
	blk0  = Block(16)  # 16byte block

	if mfcChkCard() is False:
		log.say(f" - {c.RED}Card not detected{c.NORM}", prompt='')
		return None, None
	else:
		log.say(f" - {c.GRN}Card detected{c.NORM}", prompt='')

	for h,k in klist:
		if blk0.rdbl(0, hole=h, key=k, end='') is True:
			log.say(f"  ( {c.GRN}ok{c.NORM} )", prompt='')
			bdKey = k
			bdHole = h
			break
		log.say(f"  ( {c.RED}fail{c.NORM} )", prompt='')

	if bdKey == "":
		log.say("\n No known backdoor key.", prompt=f"[{c.RED}!{c.NORM}]")
		return None, None

	if quiet is True:  log.resume(qlog)
	return bdKey, bdHole

#+============================================================================= ========================================
def  mfcChkCard ():
	res, cap = pm3Call("hf mf rdbl --blk 0", quiet=True)
	return True if ((res is True) or ("Can't select card" not in cap)) else False

#+============================================================================= ========================================
def  mfcLoadBackdoor (card, hole, key):
	if   card.size == 4096:  sz = "--4k"
#	elif card.size == 2048:  sz = "--2k"    #! no test data/cards
	elif card.size == 1024:  sz = "--1k"
#	elif card.size ==  320:  sz = "--mini"  #! no test data/cards
	else                  :  return False, f"{c.RED}Unknown Card size{c.NORM}"

	#! add retry loop
	cmd      = f"hf mf ecfill -c {hole} --key {key} {sz}"  # `ecfill` seems to return -21 for fail
	res, cap = pm3Call(cmd)
	if res < 0:  return False, f"{c.RED}ecfill failed{c.NORM}"

	#! add retry loop
	cmd      = f"hf mf eview {sz}"
	res, cap = pm3Call(cmd)
	if res < 0:  return False, f"{c.RED}eview failed{c.NORM}"

	"""
[=] -----+-----+-------------------------------------------------+-----------------
[=]  sec | blk | data                                            | ascii
[=] -----+-----+-------------------------------------------------+-----------------
[=]    0 |   0 | B9 56 20 34 FB 08 04 00 01 F2 C7 DA 56 F3 27 1D | .V 4........V.'.
[=]      |   1 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]      |   2 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]      |   3 | 00 00 00 00 00 00 FF 07 80 69 00 00 00 00 00 00 | .........i......
[=]    1 |   4 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
           |||   |                                             |
   11,12,13^^^   ^17                                           ^63  #**
	"""
	for lin in cap.split('\n'):
		if (" | " in lin) and (lin[63] != " "):  #** data ilne
			hexP = lin[17:63+1]                  #** data

			blkN          = int(lin[11:14+1])    #** 3 digit block no.
			blk           = card.block(blkN)
			trl, sec, idx = blk.isTrailer()

			blk.hole = hole
			blk.keyH = key
			blk.rdOK = True
			blk.tryN = 1

			blk.poke(0, hexP)  # this will flag up an edit
			blk.edit = False   # reset the edit flag to "fresh read"

			# backdoor keys do not retrieve other keys - this will set edit to True
			if trl is True:
				blk.pokeX(0, 6)   # keyA
				blk.pokeX(10, 6)  # keyB

	return True, "ok"

#++============================================================================ ========================================
def  main ():
#	if not checkVer():
#		return

	args  = parseCli()

	#-----------------------------------------------------
	# logfile not started - this will get buffered
	log.say(f"{c.BLK}{c.onWHT} Welcome to the start of the demo... {c.NORM}")

	"""
	#-----------------------------------------------------
	# run the (known) backdoor key check
	log.say(f"\n{c.onBLU}Let's see if we can find a backdoor key...{c.EOL}{c.NORM}")

	bdKey, bdHole = mfcBackdoorKeys()
	log.say(f"Found backdoor key: {c.GRN}{bdHole}{c.NORM}/{c.BGRN}{bdKey}{c.NORM}")

	#-----------------------------------------------------
	# Grab the first 4 bytes of block 0 for the logfile name
	log.say(f"\n{c.onBLU}Generate the logfile name...{c.EOL}{c.NORM}")

	blk0 = Block()
	blk0.rdbl(0)#, quiet=True)

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
	log.say(f"Log file: {c.YEL}{logfile}{c.NORM}")

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
	log.say(f"\n{c.onBLU}UID Check {{pass, fail}}...{c.EOL}{c.NORM}")

	mfc = MFClassic(name="sandpit")  # start with a blank Card
	mfc.addSec(1, 1)                 # add 1 Sector, containing 1 Block (Block #0)

	mfc.block(0).rdbl()              # virtual card block(0) = ReaDBLock(0) from real card

	# now we can start using Card processing features
	uid, bcc = mfc.uid()

	# Yes, it would probably, on this occasion, been easier to do this
	# But I wanted an excuse to demo the API
#	uid = blk0.hexB[0:4]
#	bcc = blk0.hexB[4]

	#-----------------------------------------------------
	# First one should PASS; second should FAIL
	for i in range(0, 1+1):
		log.say(f"  #{i+1} : [{uid} / " + f"{bcc+i:#2X}]"[2:] + ": ", end='')
		ok, chk = mfc.uidIsValid(uid, bcc+i)
		if ok is True:
			log.say(f"{c.GRN}Pass{c.NORM}", prompt='')
		else:
			if chk < 0:
				log.say("{c.RED}Bad UID{c.NORM}", prompt='')
			else:
				log.say(f"{c.RED}Fail{c.NORM} (should be " + f"{chk:#2X})"[2:], prompt='')

	# that's that demo done
	del mfc

	#-----------------------------------------------------
	# Idenitfy the card (on the reader) from the manufacturing data
	# we will ask for the FULL list of all matches (not just the first match)
	# ...cos this is API demo/test code, and we'd probably like to spot any overlaps!
	log.say(f"\n{c.onBLU}Try to identify the card...{c.EOL}{c.NORM}")

	match = mfcIdentify(full=True)
	if   len(match) == 0:
		log.say(f"{c.RED}No Chip Signature matches found{c.NORM}")

	elif len(match) == 1:
		log.say(f"Chip Signature matches: {c.BGRN}{match[0][0]}{c.NORM}")
		myCard = match[0][1]()

	else:
		names = []
		names.append(m[0] for m in match)
		log.say(f"Problem: Multiple Chip Signatures match: {names}")

	# we're not actually going to use it at this time
	del myCard

	#-----------------------------------------------------
	# show off the two dump functions
	#   1. developers heirarchical data dump
	#   2. user dnump
	log.say(f"\n{c.onBLU}Demo the editing functions...{c.EOL}{c.NORM}")

	myCard = MFClassic(name="dumpdemo")  # start with a blank Card
	myCard.addSec(2, 3)                  # add 2 Sectors, each containing 3 Blocks

	# generate some data to dump
	myCard.block(0).rdbl(quiet=True)     # load block 0
	myCard.get14a(quiet=True)            # load the control info

	# demo the poke functions
	myCard.block(1).poke( 0, 0xff)       # ff -- ee dd -- aa bb -- 11 22 -- "A "B "C -- --
	myCard.block(1).poke( 2, 0xEEDD)     # 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
	myCard.block(1).poke( 5, "AA BB")
	myCard.block(1).poke( 8, "1122")
	myCard.block(1).poke(11, [65,66,67])

	# This mthod MAY write to the wrong place, or completely fail if the blocks are non-contiguous
	myCard.blk[2].poke(  0, 0XfA)            # No!
	myCard.block(2).poke(2, 0xEe)            # Yes!
	# same thing goes for Sectors
	myCard.sec[0].block(2).poke(   4, 0x88)  # No!
	myCard.sector(0).block(2).poke(6, 160 )  # Yes!
	#... There is an argument to be made for making sec and blk private
	#... The argument against it is that it will made the dump() function problematic

	# let try the pokeText function, and make it overflow the end of the block
	log.say("Trigger an overflow exception...")
	try:
		dateStr = datetime.date.today().strftime("%Y-%m-%d")  # YYYY-MM-DD
		myCard.sector(1).block(0).pokeT(10, dateStr)
	except ValueError as e:
		log.say(f"{c.RED}Exception: {e}{c.NORM}")

	# there is also pokeX which marks a byte as None/Unknown
	myCard.sector(1).block(0).pokeX(13, 2)  # set 2 bytes, starting with byte 13, to "unused"

	log.say("\nShow full log history (for the whole card)")
	log.say(myCard.history().replace("; ","\n"))

	log.say("\nShow log history for Sector 0")
	log.say(myCard.sector(0).history().replace("; ","\n"))

	log.say("\nShow log history Block 3")
	log.say(myCard.block(3).history().replace("; ","\n"))

	#-----------------------------------------------------
	log.say(f"\n{c.onBLU}Developers dump (of [virtual] card)...{c.EOL}{c.NORM}")
# This generates an abusive amount of output, so it's commented out
	log.say("[REDACTED]")
#	dump(myCard)

	#-----------------------------------------------------
	log.say(f"\n{c.onBLU}User dump (of [virtual] card)...{c.EOL}{c.NORM}")
	log.say(myCard.show(hdr=True))

	"""
	#-----------------------------------------------------
	# Let's try this for real
	c.enable(True)  # enable coloured output

	log.say(f"\n{c.onBLU}Let's try this for real...{c.EOL}{c.NORM}")

	#-----------------------------------------------------
	# check card present
	log.say("Check for card : ", end='', flush=True)
	if mfcChkCard() is False:
		log.say(f"{c.RED}not found{c.NORM}", prompt='')
		sys.exit(1)
	else:
		log.say(f"{c.GRN}Card detected{c.NORM}", prompt='')

	#-----------------------------------------------------
	# check for backdoor keys
	bdKey, bdHole = mfcBackdoorKeys()
	if bdKey != None:
		log.say(f"Found backdoor key: {c.GRN}{bdHole}{c.NORM}/{c.BGRN}{bdKey}{c.NORM}")
		key  = bdKey
		hole = bdHole

	else:
		log.say(f"{c.RED}No working backdoor keys")

	#-----------------------------------------------------
	# did we get a backdoor key?
	if bdKey == None:
		#! try and guess a key for block #0
		log.say("just doing backdoor keys at this point!")
		sys.exit(99)

	hole = bdHole
	key  = bdKey

	#-----------------------------------------------------
	# identify card type, and create a virtual one of those
	log.say(f"Identify card type...")

	# mfcIdentify() requires the data from the manufacturing block
	# so we NEED a valid key for it
	info, match = mfcIdentify(hole, key)
	if match is None or len(match) == 0:
		log.say(f"{c.RED}No Chip Signature matches found{c.NORM}")
		sys.exit(1)

	elif len(match) != 1:
		names = []
		names.append(m[0] for m in match)
		log.say(f"{c.RED}Problem: Multiple Chip Signatures match:{c.NORM} {names}")
		sys.exit(2)

	else:
		log.say(f"Chip Signature matches: {c.BGRN}{match[0][0]}{c.NORM}")
		myCard = match[0][1]()

	print(info)
	myCard.setInfo(info)

	# convert card size to PM3 CLI switch value
	if   myCard.size == 4096:  sz = "--4k"
	elif myCard.size == 2048:  sz = "--2k"    #! no test data/cards
	elif myCard.size == 1024:  sz = "--1k"
	elif myCard.size ==  320:  sz = "--mini"  #! no test data/cards
	else                    :  return False, f"{c.RED}Unknown Card size{c.NORM}"

	#-----------------------------------------------------
	log.say(f"Load all data...")

	if bdKey != None:
		# backdoor method ... load data with ecfill
		res, err = mfcLoadBackdoor(myCard, bdHole, bdKey)
		if res is False:
			log.say(f"{c.RED}Load Failed{c.NORM} : {err}")
			sys.exit(22)

		if "static+encrypted" in myCard.nonce:
#			do_recover()
			# test keys for development : "nova-1"
			# recovery() does NOT verify these keys
			keys = [ \
				["", "B578F38A5C61"], ["8C0C5D149C0C", "E015CEE2380A"], \
				["A0A1A2A3A4A5", "0000014B5C31"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], \
				["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], \
				["FFFFFFFFFFFF", "96A301BCE267"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], \
				["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], \
				["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], \
				["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], \
				["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"]  \
			]
#			keys = []

			# recovery() does NOT verify these keys
			for k in keys:
				for ab in [0, 1]:
					# try using the key - if it fails, blank it!
					pass

			log.say(f"\n{c.BYEL}" + "\u2588" + ("\u2580" *77) + "\u2588" + f"{c.NORM}")
			log.say(f"{c.BMAG}¬`script fm11rf08s_recovery.py`{c.NORM}")
			r = recovery(quiet=False, keyset=keys)
			log.say(f"{c.BYEL}" + "\u2588" + ("\u2584" *77) + "\u2588" + f"{c.NORM}\n")

#			keyfile = r['keyfile']
			rkey    = r['found_keys']
#			fdump   = r['dumpfile']
#			rdata   = r['data']

			badrk = 0     # 'bad recovered key' count (ie. not recovered)

			print(rkey)
			#! todo: does recovery() ALWAYS return keys for {0..15, 32}[17] sectors ??
			for k in range(0, (15+1)+1):
				for ab in [0, 1]:
					if rkey[k][ab] == "":
						if badrk == 0:  log.say("Some keys were not recovered: ", end='')
						else:           log.say(", ", end='', prompt='')
						badrk += 1

						kn = k
						if kn > 15:  kn += 16
						log.say(f"[{kn}/", end='', prompt='')
						log.say("A]" if ab == 0 else "B]", end='', prompt='')

					else:
						sec  = k   if k <  16 else k+16
						hole = "A" if ab == 0 else "B"
						myCard.secKeySet(sec, hole, rkey[k][ab])

			if badrk > 0:  log.say("", prompt='')

		else:
#			do_autopwn(myCard, sz)
			cmd = f"hf mf autopwn {sz}"
#			cmd += " -a --key FFFFFFFFFFFF"  # add a known key
			res, cap = pm3Call(cmd, noisy=True)

			reM = r".*sector.*valid key.*"
			reS = r".*sector *([0-9]*) key type (.).*\[ (.{12}).*"
			for lin in cap.split('\n'):
				if re.match(reM, lin) is not None:
					m = re.search(reS, lin)
					sec  = int(m.group(1))
					hole = Key.A if m.group(2) == "A" else Key.B
					key  = m.group(3)
					myCard.secKeySet(sec, hole, key)




	#-----------------------------------------------------
	# backdoor key does not get keys A/B
	# use autopwn to find the keys

#	if "Static enc nonce"
#		r = recovery(quiet=False, keyset=keys)
	"""
nova-1
[=] Sector  0 keyA = A0A1A2A3A4A5
[=] Sector  0 keyB = B578F38A5C61
[=] Sector  1 keyB = E015CEE2380A
[=] Sector  1 keyA = 8C0C5D149C0C
[=] Sector  2 keyA = A0A1A2A3A4A5
[=] Sector  2 keyB = 0000014B5C31
[=] Sector  3 keyA = FFFFFFFFFFFF
[=] Sector  3 keyB = FFFFFFFFFFFF
[=] Sector  4 keyA = FFFFFFFFFFFF
[=] Sector  4 keyB = FFFFFFFFFFFF
[=] Sector  5 keyA = FFFFFFFFFFFF
[=] Sector  5 keyB = FFFFFFFFFFFF
[=] Sector  6 keyA = FFFFFFFFFFFF
[=] Sector  6 keyB = 96A301BCE267
[=] Sector  7 keyA = FFFFFFFFFFFF
[=] Sector  7 keyB = FFFFFFFFFFFF
[=] Sector  8 keyA = FFFFFFFFFFFF
[=] Sector  8 keyB = FFFFFFFFFFFF
[=] Sector  9 keyA = FFFFFFFFFFFF
[=] Sector  9 keyB = FFFFFFFFFFFF
[=] Sector 10 keyA = FFFFFFFFFFFF
[=] Sector 10 keyB = FFFFFFFFFFFF
[=] Sector 11 keyA = FFFFFFFFFFFF
[=] Sector 11 keyB = FFFFFFFFFFFF
[=] Sector 12 keyA = FFFFFFFFFFFF
[=] Sector 12 keyB = FFFFFFFFFFFF
[=] Sector 13 keyA = FFFFFFFFFFFF
[=] Sector 13 keyB = FFFFFFFFFFFF
[=] Sector 14 keyA = FFFFFFFFFFFF
[=] Sector 14 keyB = FFFFFFFFFFFF
[=] Sector 15 keyA = FFFFFFFFFFFF
[=] Sector 15 keyB = FFFFFFFFFFFF
[=] Sector 32 keyB = 00001FEEF30E
[=] Sector 32 keyA = 2ACC3DA8E7DB


[ ["A0A1A2A3A4A5", "B578F38A5C61"], ["8C0C5D149C0C", "E015CEE2380A"],
  ["A0A1A2A3A4A5", "0000014B5C31"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"],
  ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"],
  ["FFFFFFFFFFFF", "96A301BCE267"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"],
  ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"],
  ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"],
  ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"],
  ["FFFFFFFFFFFF", "FFFFFFFFFFFF"], ["FFFFFFFFFFFF", "FFFFFFFFFFFF"] ]

['A0A1A2A3A4A5', 'B578F38A5C61', 'E015CEE2380A', '8C0C5D149C0C', 'A0A1A2A3A4A5', '0000014B5C31', '96A301BCE267', '00001FEEF30E', '2ACC3DA8E7DB']

[+] -----+-----+--------------+---+--------------+----
[+]  Sec | Blk | key A        |res| key B        |res
[+] -----+-----+--------------+---+--------------+----
[+]  000 | 003 | A0A1A2A3A4A5 | 1 | B578F38A5C61 | 1
[+]  001 | 007 | 8C0C5D149C0C | 1 | E015CEE2380A | 1
[+]  002 | 011 | A0A1A2A3A4A5 | 1 | 0000014B5C31 | 1
[+]  003 | 015 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  004 | 019 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  005 | 023 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  006 | 027 | FFFFFFFFFFFF | 1 | 96A301BCE267 | 1
[+]  007 | 031 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  008 | 035 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  009 | 039 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  010 | 043 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  011 | 047 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  012 | 051 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  013 | 055 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  014 | 059 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  015 | 063 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  032 | 131 | 2ACC3DA8E7DB | 1 | 00001FEEF30E | 1
[+] -----+-----+--------------+---+--------------+----


    badrk = 0     # 'bad recovered key' count (ie. not recovered)
    keyfile = r['keyfile']
    rkey    = r['found_keys']
    # fdump = r['dumpfile']
    # rdata = r['data']

    for k in range(0, 16+1):
        for ab in [0, 1]:
            if rkey[k][ab] == "":
                if badrk == 0:
                    lprint("Some keys were not recovered: ", end='')
                else:
                    lprint(", ", end='', prompt='')
                badrk += 1

                kn = k
                if kn > 15:
                    kn += 16
                lprint(f"[{kn}/", end='', prompt='')
                lprint("A]" if ab == 0 else "B]", end='', prompt='')
    if badrk > 0:
        lprint("", prompt='')
    return keyfile

	"""
#	else:



	log.say(myCard.show(hdr=True))

#	dumpCard(myCard)

	sys.exit(99)

	log.say(f"Load all blocks...")
	for b in myCard.blocks():
		b.rdbl(b.blkN, hole=bdHole, key=bdKey, end='')
		log.say("\r", end='', prompt='')
	log.say("\n")



#	#-----------------------------------------------------
#	# find ANY key (for a Nesting attack)
#		log.say("\nTry to guess one of the keys (for Nesting)...")
#		key, hole = mfcGuessKey()
#		if key != None:
#			log.say(f"Guessed a key: {c.GRN}{hole}{c.NORM}/{c.BGRN}{key}{c.NORM}")
#		else:
#			log.say(f"{c.RED}Failed to guess a key")
#			sys.exit(3)



	log.say(myCard.show(hdr=True))


#++============================================================================ ========================================
if __name__ == "__main__":
	main()
