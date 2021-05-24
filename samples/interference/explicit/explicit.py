import angr
import claripy
from information_flow_analysis import analysis, explicit

def main():
    proj = angr.Project('explicit.out', load_options={'auto_load_libs':False})
    
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./explicit.out', arg0])

    high_addrs = {0x401158, 0x401155}

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    leaks = ifa.analyze()
    assert len(leaks) == 1 and isinstance(leaks[0], explicit.ExplicitLeak)
    return

if __name__ == "__main__":
    main()
