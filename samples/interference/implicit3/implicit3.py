import angr
import claripy
from information_flow_analysis import analysis, implicit

def main():
    proj = angr.Project('./implicit3.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])

    high_addrs = [0x4011a6, 0x4011a9]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    leaks = ifa.analyze()
    assert len(leaks) == 2 and isinstance(leaks[0], implicit.ImplicitLeak) and isinstance(leaks[1], implicit.ImplicitLeak)
    return 0
    
if __name__ == "__main__":
    main()