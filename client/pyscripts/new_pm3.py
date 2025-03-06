import pm3
import json

from new_log  import log
from new_ansi import c

#============================================================================== ========================================
#                                                                                PM3 Preferences
#============================================================================== ========================================
class Pm3Pref:
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
def  pm3Call (cmd,  end='\n',  quiet=False,  noisy=False):
	p = pm3.pm3()

	if noisy is True:      log.say(f"\n{c.BYEL}" + "\u2588" + ("\u2580" *77) + "\u2588" + f"{c.NORM}")

	if quiet is not True:  log.say(f"{c.BMAG}`{cmd}`{c.NORM}", end=end, flush=True)

	pRes = p.console(cmd, quiet=not noisy)

	if noisy is True:      log.say(f"{c.BYEL}" + "\u2588" + ("\u2584" *77) + "\u2588" + f"{c.NORM}\n")

	pCap = p.grabbed_output
	return pRes, pCap

#+============================================================================= ========================================
def  pm3Test ():
	print("in pm3: ", vars(log))
