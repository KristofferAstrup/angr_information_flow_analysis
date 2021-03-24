import angr
import time
import monkeyhex
import inspect
import re
import claripy
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
import networkx as nx
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from networkx.drawing.nx_pydot import graphviz_layout
import sys
sys.path.append('../../../')
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress

def main():
    proj = angr.Project('non_termination.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./non_termination.out', arg0], add_options={angr.options.UNICORN})
    hier = angr.state_hierarchy.StateHierarchy()
    simgr = proj.factory.simgr(state, hierarchy=hier)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    t0 = time.process_time()

    cfg = util_information.cfg_emul(proj, simgr, state)
    
    start_addr = 0x401149
    loop_seer = angr.exploration_techniques.LoopSeer(cfg=cfg, bound=1000)
    simgr.use_technique(loop_seer)
    simgr.explore(find=start_addr)
    simgr.stash(from_stash='active', to_stash='stash')
    simgr.stash(from_stash='found', to_stash='active')

    simgr.explore()
    
    t1 = time.process_time()
    print("Delta: " + str(t1-t0))

    #util_out.write_stashes(simgr, args=[arg0])
    


    # data = []
    # simgr.active[0].history.subscribe_actions()
    # simgr.active[0].inspect.b('instruction', when=angr.BP_BEFORE, instruction=0x0040115d, action= test )#data.append(s.copy()))

    # simgr.explore()

    # #ref = hier.get_ref(simgr.spinning[0].history)
    # print(list(simgr.spinning[0].history.lineage))
    # for h in simgr.spinning[0].history.lineage:
    #     for ac in h.actions:
    #         try:
    #             print(ac)
    #         except:
    #             pass
    #     break

    # for s in data:
    #     print(s.history.block_count)


    # print(simgr.spinning[0].solver.constraints)
    # print(list(simgr.spinning[0].history.ins_addrs))

    return

# class LoopCompare(angr.state_plugins.SimStatePlugin):
#     def __init__(self):
#          self.arr = []

#     def set_state(state):
#         self.arr = state.arr

def test(s):
    pass
    # for ac in s.history.actions:
    #     print(dir(ac))
    # if not hasattr(s, 'boi'):
    #     s.boi = 0
    # else:
    #     s.boi = s.boi + 1
    # print(s.boi)

    # start_node = util_information.find_cfg_node(cfg, 0x401149)
    # func_addrs = util_explicit.get_unique_reachable_function_addresses(cfg, start_node)
    # funcs = util_information.find_func_from_addrs(proj, func_addrs)
    
    
    # loop_res = proj.analyses.LoopFinder(functions=funcs)
    # loop = loop_res.loops[0]
    # t = angr.analyses.forward_analysis.LoopVisitor(loop)
    # print(type(t))
    # print(dir(t))

if __name__ == "__main__":
    main()
