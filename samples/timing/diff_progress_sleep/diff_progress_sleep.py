import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis

def main():
    proj = angr.Project('diff_progress_sleep.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./diff_progress_sleep.out', arg0], add_options={angr.options.UNICORN})
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'
   
    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=[0x401175, 0x401178])
    ifa.find_and_add_subject_addrs("puts")
    for leak in ifa.find_timing_leaks():
        print(leak)

if __name__ == "__main__":
    main()