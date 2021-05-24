import angr
import claripy
from information_flow_analysis import analysis, progress

def main():
    proj = angr.Project('implicit_progress.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit_progress.out', arg0])
    
    high_addrs = [0x00401155, 0x00401158]
    
    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    leaks = ifa.analyze()
    assert len(leaks) == 1 and isinstance(leaks[0], progress.ProgressLeakProof)
    return 0

if __name__ == "__main__":
    main()
