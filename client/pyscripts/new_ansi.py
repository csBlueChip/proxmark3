#+============================================================================= ========================================
# I'm not screwing around with virtual python environments just to get ANSI colours working!
#
class  ANSI:
	def  __init__ (self, dflt=True):
		self.enable(dflt)

	def  __synonyms (self):
		self.DGRY = self.BBLK
		self.LGRY = self.DWHT
		self.BRN  = self.DYEL

	def  enable (self, en=True):
		if en is True:
			self.BLK   = "\033[0;30m"  # in order of perceived brightness (for colour blind consideration)
			self.BLU   = "\033[0;34m"
			self.RED   = "\033[0;31m"
			self.MAG   = "\033[0;35m"
			self.GRN   = "\033[0;32m"
			self.CYN   = "\033[0;36m"
			self.YEL   = "\033[0;33m"
			self.WHT   = "\033[0;37m"

			self.BBLK  = "\033[1;30m"  # bright/bold/intense colours
			self.BBLU  = "\033[1;34m"
			self.BRED  = "\033[1;31m"
			self.BMAG  = "\033[1;35m"
			self.BGRN  = "\033[1;32m"
			self.BCYN  = "\033[1;36m"
			self.BYEL  = "\033[1;33m"
			self.BWHT  = "\033[1;37m"

			self.DBLK  = "\033[2;30m"  # dark black == black
			self.DBLU  = "\033[2;34m"
			self.DRED  = "\033[2;31m"
			self.DMAG  = "\033[2;35m"
			self.DGRN  = "\033[2;32m"
			self.DCYN  = "\033[2;36m"
			self.DYEL  = "\033[2;33m"
			self.DWHT  = "\033[2;37m"

			self.onBLK = "\033[40m"    # paper colour
			self.onBLU = "\033[44m"
			self.onRED = "\033[41m"
			self.onMAG = "\033[45m"
			self.onGRN = "\033[42m"
			self.onCYN = "\033[46m"
			self.onYEL = "\033[43m"
			self.onWHT = "\033[47m"

			self.EOL   = "\033[K"      # paint to end of line

			self.NORM  = "\033[0m"     # system default colours

			self.__synonyms()

		else:
			self.disable(True)

	def  disable (self, dis=True):
		if dis is True:
			self.BLK   = ""  # in order of perceived brightness (for colour blind consideration)
			self.BLU   = ""
			self.RED   = ""
			self.MAG   = ""
			self.GRN   = ""
			self.CYN   = ""
			self.YEL   = ""
			self.WHT   = ""

			self.BBLK  = ""  # bright/bold/intense colours
			self.BBLU  = ""
			self.BRED  = ""
			self.BMAG  = ""
			self.BGRN  = ""
			self.BCYN  = ""
			self.BYEL  = ""
			self.BWHT  = ""

			self.DBLK  = ""  # dark black == black
			self.DBLU  = ""
			self.DRED  = ""
			self.DMAG  = ""
			self.DGRN  = ""
			self.DCYN  = ""
			self.DYEL  = ""
			self.DWHT  = ""

			self.onBLK = ""  # paper colour
			self.onBLU = ""
			self.onRED = ""
			self.onMAG = ""
			self.onGRN = ""
			self.onCYN = ""
			self.onYEL = ""
			self.onWHT = ""

			self.EOL   = ""  # paint to end of line

			self.NORM  = ""  # system default colours

			self.__synonyms()

		else:
			self.enable(True)

c = ANSI()
