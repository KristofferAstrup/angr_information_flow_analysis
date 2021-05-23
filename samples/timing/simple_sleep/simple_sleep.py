import angr
import claripy
import sys
sys.path.append('../../../')
from information_flow_analysis import analysis

def main():
    proj = angr.Project('./simple_sleep.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./simple_sleep.out', arg0], add_options={angr.options.UNICORN})
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    high_addrs = [0x00401175, 0x00401178]
    start_addr = 0x401169 #main entry block

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start=start_addr,high_addrs=high_addrs)
    for leak in ifa.find_covert_leaks():
        print(leak)

if __name__ == "__main__":
    main()