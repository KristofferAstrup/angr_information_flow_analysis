import angr
import claripy
import sys
sys.path.append('../../../')
from information_flow_analysis import analysis, implicit

def main():
    proj = angr.Project('mixed.out', load_options={'auto_load_libs':False})
    
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./mixed.out', arg0])

    high_addrs = [0x4011ac, 0x4011af]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    ifa.analyze()
    return 0

if __name__ == "__main__":
    main()
