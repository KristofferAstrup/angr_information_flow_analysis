import angr
import claripy
import sys
sys.path.append('../../../')
from information_flow_analysis import analysis

def main():
    proj = angr.Project('implicit2.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit2.out', arg0])

    high_addrs = [0x401155, 0x401158]
    
    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    ifa.analyze()
    return 0
    
if __name__ == "__main__":
    main()
