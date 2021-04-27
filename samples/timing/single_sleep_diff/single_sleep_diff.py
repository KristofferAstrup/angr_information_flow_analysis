import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_out, util_analysis, util_timing

def main():
    proj = angr.Project('./single_sleep_diff.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./single_sleep_diff.out', arg0])
    simgr = proj.factory.simulation_manager(state)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    high_addrs = [0x401175, 0x401178]

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    for leak in ifa.find_timing_leaks():
        print(leak)
        if isinstance(leak, util_timing.TimingProcedureLeakProof):
            print("state1: " + util_out.get_str_from_arg(leak.state1, arg0, no=1))
            print("state2: " + util_out.get_str_from_arg(leak.state2, arg0, no=1))

if __name__ == "__main__":
    main()
