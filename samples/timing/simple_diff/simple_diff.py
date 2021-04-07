import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis

def main():
    proj = angr.Project('./simple_diff.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./simple_diff.out', arg0])
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~'

    high_addrs = [0x401155, 0x401158]
    start_addr = 0x401149 #main entry block

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start_addr=start_addr,high_addrs=high_addrs)
    for leak in ifa.find_timing_leaks():
        print(leak)

if __name__ == "__main__":
    main()
