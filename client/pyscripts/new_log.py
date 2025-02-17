#import new_ansi as ansi

#%============================================================================= ========================================
class Log:
	def  __init__ (self):
		self.buf   = ''
		self.fspec = None

		# Prompt: default, in-use, enable_flag
#		self.prDF  = f"[{ansi.cYEL}={ansi.cNORM}] "
		self.prDF  = f"[=] "
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
