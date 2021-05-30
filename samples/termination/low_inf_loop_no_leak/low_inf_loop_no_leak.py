import angr
import claripy
from information_flow_analysis import analysis, termination, out

def main():
    proj = angr.Project('low_inf_loop_no_leak.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./low_inf_loop_no_leak.out', arg0])

    high_addrs = [0x40116c] #Only initial branching information is high; loop is low

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    leaks = ifa.analyze()
    assert len(leaks) == 0
    return

if __name__ == "__main__":
    main()
