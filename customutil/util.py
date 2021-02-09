import angr
from angrutils import *

def cfgs(proj, simgr, state):
    try:
        print("--CFG--")
        cfg = proj.analyses.CFG()
        plot_cfg(cfg, "cfg", "pdf")  
        print("Plotted to cfg.pdf")
    except Exception as e:
        print(e)
    try:
        print("--CFGEmulated--")
        cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, starts=[simgr.active[0].addr], initial_state=state, context_sensitivity_level=2, resolve_indirect_jumps=True)
        plot_cfg(cfg, "cfg_emul", "pdf")  
        print("Plotted to cfg_emul.pdf")
    except Exception as e:
        print(e)
    try:
        print("--CFGFast--")
        cfg_fast = proj.analyses.CFGFast()
        plot_cfg(cfg_fast, "cfg_fast", "pdf")  
        print("Plotted to cfg_fast.pdf")
    except Exception as e:
        print(e)

def write_stashes(simgr, args):
    filename = "stash_summary.txt"
    file = open(filename,"w+") 
    print('--stashes--')
    for key in simgr.stashes:
        string = str(key) + ": " + str(len(simgr.stashes[key]))
        print(string)
        writeline(file, string)
    print('writing...')
    for key in simgr.stashes:
        writeline(file, "===" + str(key) + ": " + str(len(simgr.stashes[key])) + "===")
        for stash in simgr.stashes[key]:
            writeline(file, str(stash.addr))
            writeline(file, "dump[0]: " + str(stash.posix.dumps(0)))
            writeline(file, "dump[1]: " + str(stash.posix.dumps(1)))
            writeline(file, "dump[2]: " + str(stash.posix.dumps(2)))
            for i in range(len(args)):
                writeline(file, "arg" + str(i) + " " + get_str_from_arg(stash, args[i]))
            writeline(file, "-----")
        if(key == "found" and len(simgr.stashes[key]) > 0):
            foundstate = simgr.stashes[key][0]
            for i in range(len(args)):
                foundfile = open("found_input" + str(i),"wb+")
                foundfile.write(foundstate.solver.eval(args[i], cast_to=bytes))
                foundfile.close()
    print('written to ' + filename)
            
    file.close()

def get_str_from_arg(state, arg):
    str = ""
    solutions = gather_evals(state, arg, 5)
    for bs in solutions:
        try:
            str += bs.decode('UTF-8') + " |\n "
        except:
            str += "no utf-8 |\n "
    return str

def gather_evals(state, arg, max):
    solutions = []
    try:
        for i in range(max):
            solutions = state.solver.eval_upto(arg, i, cast_to=bytes)
    except:
        pass
    return solutions

def writeline(file, string):
    file.write(string + "\n")