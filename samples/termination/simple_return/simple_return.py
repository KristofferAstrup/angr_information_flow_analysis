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
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress, util_analysis

def main():
    proj = angr.Project('simple_return.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./simple_return.out', arg0])
    # simgr = proj.factory.simgr(state)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~'

    # cfg = util_information.cfg_emul(proj, simgr, state)
    # cdg = proj.analyses.CDG(cfg = cfg)

    high_addrs = [0x401155, 0x401158]
    start_addr = 0x401149 #main entry block
    # start_node = cfg.model.get_any_node(addr=start_addr)

    # post_dom_tree = cdg.get_post_dominators()
    # dep_graph = util_explicit.get_super_dep_graph_with_linking(proj, cfg, cdg, start_node)

    # branches = util_implicit.find_high_branches(dep_graph, post_dom_tree, start_node, high_addrs)

    # simgr.explore(find=0x401149)
    # if len(simgr.found) < 1:
    #     raise("No main entry block state found!")
    # state = simgr.found[0]

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start_addr=start_addr,high_addrs=high_addrs)
    leaks = ifa.find_all_leaks()
    # for branch in branches:
    #     leak = util_progress.test_observer_diff(proj, cfg, state, branch)
    #     if leak:
    #         print(leak)

    return

if __name__ == "__main__":
    main()
