import angr
import claripy
from information_flow_analysis import analysis, timing

def main():
    proj = angr.Project('equal_sleep.out', load_options={'auto_load_libs':False})
    
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./equal_sleep.out', arg0])

    high_addrs = [0x401175, 0x401178]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    leaks = ifa.analyze(timing_args=analysis.TimingArgs([timing.SleepTimingFunction()], epsilon=25))
    assert len(leaks) == 0

    leaks = ifa.analyze()
    assert len(leaks) == 1 and isinstance(leaks[0], timing.TimingEpsilonLeak)

if __name__ == "__main__":
    main()
