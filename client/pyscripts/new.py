from new_log import Log
print("foo")
log = Log()
print(log)

from new_ansi import \
	cBLK, cBLU, cRED, cMAG, cGRN, cCYN, cYEL, cWHT, \
	cBBLK, cBBLU, cBRED, cBMAG, cBGRN, cBCYN, cBYEL, cBWHT, \
	cDBLK, cDBLU, cDRED, cDMAG, cDGRN, cDCYN, cDYEL, cDWHT, \
	cDGRY, cLGRY, cBRN, \
	onBLK, onBLU, onRED, onMAG, onGRN, onCYN, onYEL, onWHT, \
	cEOL, cNORM, \
	myAnsi

#from new_log import log

#import new_mfc
from new_mfc import MFClassic, Sector, Block, Key, Keyhole

import new_cards


import new_pm3

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
import re
import os
import sys
import argparse
#import pm3
import struct
#import json
import datetime
import gc

##+-============================================================================ ========================================
## Optional color support .. `pip install ansicolors`
##
#try:
#    from colors import color
#except ModuleNotFoundError:
#    def color(s, fg=None):
#        _ = fg
#        return str(s)
#



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
		lstB = valX
		txt = f"{valX}"

	else:
		return (None, "")

	return (lstB, txt)

#+============================================================================= ========================================
import inspect
import builtins

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
def  printHex (*args, **kwargs):
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
import re

def  mfcGet14a (quiet=False, end="\n"):
	atqa = None
	sak  = None
	prng = None

	pRes, pCap = pm3Call("hf 14a info", quiet=quiet, end=end)
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
def  mfcIdentify (full=False, quiet=False):
	# load a one-off/stand-alone block
	blk0 = Block()
	blk0.rdbl(0, quiet=quiet, end='')
	if not blk0.rdOK:
		log.say(" - Failed to read Manufacturing Data (Block #0)", prompt='')
		return None
	else:
		log.say(f" : {blk0.hexP}", prompt='')

	atqa, sak, prng = mfcGet14a(quiet=quiet, end='');
	vsak = blk0.hexC[5*2:(5+1)*2]
	log.say (f" : ATQA={atqa} ; SAK={sak} ({vsak}) ; PRNG={prng}", prompt='')

	if not quiet: log.say ("Checking database...")
	match = []
	for mfc in MFC_ALL:
		cls = mfc()
		nm = cls.__class__.__name__
		log.say(f"  {nm} ", end='')
		if hasattr(cls, 'match'):
			log.say(f"match ", end='', prompt='')
			if cls.match(sak, blk0):
				log.say(f" \t( {cGRN}ok{cNORM} )", prompt='')
				match.append((nm, mfc))
				if not full:  break
			else:
				log.say(f" \t( {cRED}fail{cNORM} )", prompt='')
		else:
			log.say(f" nomatch", prompt='')

	return match

#+============================================================================= ========================================
def  mfcGuessKey (card, klist):
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
	log.say
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
	# pragmatically, this will makes things more efficient
	klist = sorted(klist, key=lambda x: x[0])

	log.say(f"Trying known backdoor keys: {klist}")

	# at this point in history, we can do this:
	bdKey = ""
	blk0  = Block()

	if blk0.rdbl(0, quiet=quiet, end='') is False: 
		log.say(f" - {cRED}Card not detected{cNORM}", prompt='')
		return None
	else:
		log.say(f" - {cGRN}Card detected{cNORM}", prompt='')

	for h,k in klist:
		if blk0.rdbl(0, hole=h, key=k, end='') is True:
			log.say(f"  ( {cGRN}ok{cNORM} )", prompt='')
			bdKey = k
			bdHole = h
			break
		log.say(f"  ( {cRED}fail{cNORM} )", prompt='')

	if bdKey == "":
		log.say("\n No known backdoor key.", prompt=f"[{cRED}!{cNORM}]")
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
	myAnsi(True)
	log.say(f"{cBLK}{onWHT} Welcome to the start of the demo... {cNORM}")

	"""
	#-----------------------------------------------------
	# run the (known) backdoor key check
	log.say(f"\n{onBLU}Let's see if we can find a backdoor key...{cEOL}{cNORM}")

	bdKey, bdHole = mfcBackdoorKeys()
	log.say(f"Found backdoor key: {cGRN}{bdHole}{cNORM}/{cBGRN}{bdKey}{cNORM}")

	#-----------------------------------------------------
	# Grab the first 4 bytes of block 0 for the logfile name
	log.say(f"\n{onBLU}Generate the logfile name...{cEOL}{cNORM}")

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
	log.say(f"Log file: {cYEL}{logfile}{cNORM}")

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
	log.say(f"\n{onBLU}UID Check {{pass, fail}}...{cEOL}{cNORM}")

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
			log.say(f"{cGRN}Pass{cNORM}", prompt='')
		else:
			if chk < 0:
				log.say("{cRED}Bad UID{cNORM}", prompt='')
			else:
				log.say(f"{cRED}Fail{cNORM} (should be " + f"{chk:#2X})"[2:], prompt='')

	# that's that demo done
	del mfc

	#-----------------------------------------------------
	# Idenitfy the card (on the reader) from the manufacturing data
	# we will ask for the FULL list of all matches (not just the first match)
	# ...cos this is API demo/test code, and we'd probably like to spot any overlaps!
	log.say(f"\n{onBLU}Try to identify the card...{cEOL}{cNORM}")

	match = mfcIdentify(full=True)
	if   len(match) == 0:
		log.say(f"{cRED}No Chip Signature matches found{cNORM}")

	elif len(match) == 1:
		log.say(f"Chip Signature matches: {cBGRN}{match[0][0]}{cNORM}")
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
	log.say(f"\n{onBLU}Demo the editing functions...{cEOL}{cNORM}")

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
		log.say(f"{cRED}Exception: {e}{cNORM}")

	# there is also pokeX which marks a byte as None/Unknown
	myCard.sector(1).block(0).pokeX(13, 2)  # set 2 bytes, starting with byte 13, to "unused"

	log.say("\nShow full log history (for the whole card)")
	log.say(myCard.history().replace("; ","\n"))

	log.say("\nShow log history for Sector 0")
	log.say(myCard.sector(0).history().replace("; ","\n"))

	log.say("\nShow log history Block 3")
	log.say(myCard.block(3).history().replace("; ","\n"))

	#-----------------------------------------------------
	log.say(f"\n{onBLU}Developers dump (of [virtual] card)...{cEOL}{cNORM}")
# This generates an abusive amount of output, so it's commented out
	log.say("[REDACTED]")
#	dump(myCard)

	#-----------------------------------------------------
	log.say(f"\n{onBLU}User dump (of [virtual] card)...{cEOL}{cNORM}")
	log.say(myCard.show(hdr=True))

	"""
	#-----------------------------------------------------
	# Let's try this for real
	log.say(f"\n{onBLU}Let's try this for real...{cEOL}{cNORM}")

	match = mfcIdentify()
	if   len(match) == 0:
		log.say(f"{cRED}No Chip Signature matches found{cNORM}")
		sys.exit(1)

	elif len(match) != 1:
		names = []
		names.append(m[0] for m in match)
		log.say(f"{cRED}Problem: Multiple Chip Signatures match:{cNORM} {names}")
		sys.exit(2)

	else:
		log.say(f"Chip Signature matches: {cBGRN}{match[0][0]}{cNORM}")
		myCard = match[0][1]()

	bdKey, bdHole = mfcBackdoorKeys()
	if bdKey != None:
		log.say(f"Found backdoor key: {cGRN}{bdHole}{cNORM}/{cBGRN}{bdKey}{cNORM}")
		key  = bdKey
		hole = bdHole
	else:
		log.say(f"{cRED}No working backdoor keys")

		log.say("\nTry to guess one of the keys (for Nesting)...")
		key, hole = mfcGuessKey()
		if key != None:
			log.say(f"Guessed a key: {cGRN}{hole}{cNORM}/{cBGRN}{key}{cNORM}")
		else:
			log.say(f"{cRED}Failed to guess a key")
			sys.exit(3)

	for b in myCard.blocks():
		b.rdbl(b.blkN, hole=bdHole, key=bdKey)

	log.say(myCard.show(hdr=True))


#++============================================================================ ========================================
if __name__ == "__main__":
	main()
