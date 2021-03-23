import angr
import monkeyhex
import inspect
import re
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angrutils import *
import networkx as nx
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from networkx_query import search_nodes, search_edges
import matplotlib.pyplot as plt
import pydot
from networkx.drawing.nx_pydot import graphviz_layout
import sys
sys.path.append('../../../')
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress

def main():
    proj = angr.Project('non_termination.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./non_termination.out', arg0])
    #state.options |= {angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER}
    simgr = proj.factory.simgr(state)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    # cfg = util_information.cfg_emul(proj, simgr, state)
    # cdg = proj.analyses.CDG(cfg = cfg)

    # simgr.explore(find=0x401180, num_find=10)

    simgr.explore(find=0x040116d)
    found = simgr.found[0]
    simgr.move('active', 'stash')
    simgr.move('found', 'active')
    simgr.step()
    simgr.stash(filter_func = lambda s: s.block().addr != 0x40115d)
    simgr.explore(find=0x0040116d)
    step_sim = simgr.successors(simgr.found[0])
    print(step_sim.unsat_successors)
    #print(sim_succs.unsat_successors)
    # for s in simgr.active:
    #     print(hex(s.addr))
    #     print(util_out.get_str_from_arg(s, arg0, no=10, newline=False))

    #util_out.write_stashes(simgr, args=[arg0])
        
    # print('---')
    # simgr.explore(find=0x40116d)
    # found = simgr.found[0]
    # print(util_out.get_str_from_arg(found, arg0, no=1, newline=False))
    # print('---')
    # simgr = proj.factory.simgr(found)
    # simgr.explore(find=0x40116f, avoid=0x40115d)
    # found = simgr.found[0]
    # print(hex(found.addr))
    # print(found.satisfiable())
    return 0




    found.options |= {angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER}
    print(found.solver.constraints)
    
    found.options |= {angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER}
    vars = found.solver.constraints[len(found.solver.constraints)-1].args
    print(vars)
    #for var in vars:
    #    print(var)
    # print(dir(found.scratch))
    # print(found.scratch.irsb)
    # print(found.scratch.target)
    # print(dir(found.scratch.target))
    # for v in found.scratch.target.variables:
    #     print(list(state.solver.describe_variables(v)))
    return 0

    high_addrs = [0x401155, 0x401158]
    start_addr = 0x401149 #main entry block
    start_node = cfg.model.get_any_node(addr=start_addr)

    post_dom_tree = cdg.get_post_dominators()
    dep_graph = util_explicit.get_super_dep_graph_with_linking(proj, cfg, cdg, start_node)

    branches = util_implicit.find_high_branches(dep_graph, post_dom_tree, start_node, high_addrs)

    simgr.explore(find=0x401149)
    if len(simgr.found) < 1:
        raise("No main entry block state found!")
    state = simgr.found[0]

    for branch in branches:
        leak = util_progress.test_observer_diff(proj, cfg, state, branch)
        if leak:
            print(leak)

    return

if __name__ == "__main__":
    main()
