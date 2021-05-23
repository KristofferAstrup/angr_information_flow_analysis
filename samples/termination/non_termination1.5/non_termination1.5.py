import angr
import monkeyhex
import inspect
import re
import time
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angrutils import *
import networkx as nx
import angr.analyses.reaching_definitions.dep_graph as dep_graph
import matplotlib.pyplot as plt
import pydot
from networkx.drawing.nx_pydot import graphviz_layout
import sys
sys.path.append('../../../')
from information_flow_analysis import information, out, explicit, implicit, progress, termination, analysis

def main():
    proj = angr.Project('non_termination1.5.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./non_termination1.5.out', arg0])
    simgr = proj.factory.simgr(state)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~'

    cfg = information.cfg_emul(proj, simgr, state)
    cdg = proj.analyses.CDG(cfg = cfg)

    high_addrs = [0x401155, 0x401158]
    start_addr = 0x401149 #main entry block

    loop_seer = angr.exploration_techniques.LoopSeer(cfg=cfg, bound=10)
    simgr.use_technique(loop_seer)
    simgr.explore(find=start_addr)
    if len(simgr.found) < 1:
        raise("No main entry block state found!")
    state = simgr.found[0]
    simgr.stash(from_stash='active', to_stash='stash')
    simgr.stash(from_stash='found', to_stash='active')
    simgr.explore()

    out.write_stashes(simgr, args=[arg0], verbose=False)
    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start=start_addr,high_addrs=high_addrs)
    proofs = ifa.find_termination_leaks()
    #proofs = termination.get_termination_leak(super_dep_graph, cfg, high_addrs, simgr.spinning[0], simgr.deadended)
    #print(proofs)

if __name__ == "__main__":
    main()
