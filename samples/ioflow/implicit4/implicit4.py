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
from customutil import util_information, util_explicit, util_implicit, util_progress, util_out, util_rda

def main():
    proj = angr.Project('implicit4.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit4.out', arg0])
    simgr = proj.factory.simgr(state)

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        normalize=True, 
        starts=[simgr.active[0].addr],
        initial_state=state,
        context_sensitivity_level=5,
        resolve_indirect_jumps=True
    )

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)
    post_dom_tree = cdg.get_post_dominators()

    start_addr = 0x401149
    subject_addrs = [0x40119b]
    high_addrs = [0x00401155, 0x00401158]
    
    cfg_node = util_information.find_cfg_node(cfg, 0x40119b)

    start_node = cfg.model.get_all_nodes(addr=start_addr)[0]

    start_node = util_information.find_cfg_node(cfg, start_addr)
    rda_graph = util_rda.get_super_dep_graph_with_linking(proj, cfg, cdg, start_node)

    util_explicit.enrich_rda_graph_explicit(rda_graph, high_addrs, subject_addrs)
    util_implicit.enrich_rda_graph_implicit(rda_graph, post_dom_tree, start_node)
    
    util_out.draw_rda_graph(proj, rda_graph)
    
    #Should not find anything
    for path in util_implicit.find_implicit(rda_graph, subject_addrs):
        print(path)

    for branch in util_implicit.find_high_branches(rda_graph, post_dom_tree, start_node, high_addrs):
        leak = util_progress.test_observer_diff(proj, cfg, state, branch)
        print(leak)

    return 0

if __name__ == "__main__":
    main()
