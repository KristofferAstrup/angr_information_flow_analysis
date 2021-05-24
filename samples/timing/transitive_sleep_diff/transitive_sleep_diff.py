import angr
import claripy
import sys
sys.path.append('../../../')
from information_flow_analysis import analysis, timing

def main():
    proj = angr.Project('transitive_sleep_diff.out', load_options={'auto_load_libs':False})
    
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./transitive_sleep_diff.out', arg0])

    high_addrs = [0x401175, 0x401178]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    leaks = ifa.analyze()
    assert len(leaks) == 1 and isinstance(leaks[0], timing.TimingProcedureLeak)

if __name__ == "__main__":
    main()
