import new_log

import pm3
import json

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
		log.say(f"{cBMAG}`{cmd}`{cNORM}", end=end, flush=True)
	pRes = p.console(cmd)
	pCap = p.grabbed_output
	return pRes, pCap
