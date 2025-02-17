"""
from new_ansi import \
	cBLK, cBLU, cRED, cMAG, cGRN, cCYN, cYEL, cWHT, \
	cBBLK, cBBLU, cBRED, cBMAG, cBGRN, cBCYN, cBYEL, cBWHT, \
	cDBLK, cDBLU, cDRED, cDMAG, cDGRN, cDCYN, cDYEL, cDWHT, \
	cDGRY, cLGRY, cBRN, \
	onBLK, onBLU, onRED, onMAG, onGRN, onCYN, onYEL, onWHT, \
	cEOL, cNORM, \
	myAnsi
"""

#+============================================================================= ========================================
# I'm not screwing around with virtual python environments just to get ANSI colours working!
#

cBLK  = ""     # in order of perceived brightness (for colour blind consideration)
cBLU  = ""
cRED  = ""
cMAG  = ""
cGRN  = ""
cCYN  = ""
cYEL  = ""
cWHT  = ""

cBBLK = ""     # bright/bold/intense colours
cBBLU = ""
cBRED = ""
cBMAG = ""
cBGRN = ""
cBCYN = ""
cBYEL = ""
cBWHT = ""

cDBLK = ""     # dark black == black
cDBLU = ""
cDRED = ""
cDMAG = ""
cDGRN = ""
cDCYN = ""
cDYEL = ""
cDWHT = ""

cDGRY = cBBLK  # synonyms
cLGRY = cDWHT
cBRN  = cDYEL

onBLK = ""     # paper colour
onBLU = ""
onRED = ""
onMAG = ""
onGRN = ""
onCYN = ""
onYEL = ""
onWHT = ""

cEOL  = ""     # paint to end of line

cNORM = ""     # system default colours

def  myAnsi (enable=True):
	global cBLK,  cBLU,  cRED,  cMAG,  cGRN,  cCYN,  cYEL,  cWHT
	global cBBLK, cBBLU, cBRED, cBMAG, cBGRN, cBCYN, cBYEL, cBWHT
	global cDBLK, cDBLU, cDRED, cDMAG, cDGRN, cDCYN, cDYEL, cDWHT
	global cDGRY, cLGRY, cBRN
	global onBLK, onBLU, onRED, onMAG, onGRN, onCYN, onYEL, onWHT
	global cEOL
	global cNORM

	if enable is True:
		cBLK  = "\033[0;30m"  # in order of perceived brightness (for colour blind consideration)
		cBLU  = "\033[0;34m"
		cRED  = "\033[0;31m"
		cMAG  = "\033[0;35m"
		cGRN  = "\033[0;32m"
		cCYN  = "\033[0;36m"
		cYEL  = "\033[0;33m"
		cWHT  = "\033[0;37m"

		cBBLK = "\033[1;30m"  # bright/bold/intense colours
		cBBLU = "\033[1;34m"
		cBRED = "\033[1;31m"
		cBMAG = "\033[1;35m"
		cBGRN = "\033[1;32m"
		cBCYN = "\033[1;36m"
		cBYEL = "\033[1;33m"
		cBWHT = "\033[1;37m"

		cDBLK = "\033[2;30m"  # dark black == black
		cDBLU = "\033[2;34m"
		cDRED = "\033[2;31m"
		cDMAG = "\033[2;35m"
		cDGRN = "\033[2;32m"
		cDCYN = "\033[2;36m"
		cDYEL = "\033[2;33m"
		cDWHT = "\033[2;37m"

		cDGRY = cBBLK         # synonyms
		cLGRY = cDWHT
		cBRN  = cDYEL

		onBLK = "\033[40m"    # paper colour
		onBLU = "\033[44m"
		onRED = "\033[41m"
		onMAG = "\033[45m"
		onGRN = "\033[42m"
		onCYN = "\033[46m"
		onYEL = "\033[43m"
		onWHT = "\033[47m"

		cEOL  = "\033[K"      # paint to end of line

		cNORM = "\033[0m"     # system default colours
	else:
		cBLK  = ""
		cBLU  = ""
		cRED  = ""
		cMAG  = ""
		cGRN  = ""
		cCYN  = ""
		cYEL  = ""
		cWHT  = ""

		cBBLK = ""
		cBBLU = ""
		cBRED = ""
		cBMAG = ""
		cBGRN = ""
		cBCYN = ""
		cBYEL = ""
		cBWHT = ""

		cDBLK = ""
		cDBLU = ""
		cDRED = ""
		cDMAG = ""
		cDGRN = ""
		cDCYN = ""
		cDYEL = ""
		cDWHT = ""

		cDGRY = ""
		cLGRY = ""
		cBRN  = ""

		onBLK = ""
		onBLU = ""
		onRED = ""
		onMAG = ""
		onGRN = ""
		onCYN = ""
		onYEL = ""
		onWHT = ""

		cEOL  = ""

		cNORM = ""
