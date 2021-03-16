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
import sys
sys.path.append('../../../')
from customutil import util

def main():
    proj = angr.Project('implicit2.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit2.out', arg0])
    simgr = proj.factory.simgr(state)

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        normalize=True, 
        starts=[simgr.active[0].addr],
        initial_state=state,
        context_sensitivity_level=5,
        state_add_options=angr.options.refs,
        resolve_indirect_jumps=True
    )

    plot_cfg(cfg,"cfg_emul",format="pdf")

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)
    start_addr = 0x401149

    start_node = util.find_cfg_node(cfg, start_addr)
    func_addrs = util.get_unique_reachable_function_addresses(cfg, start_node)
    super_dep_graph = util.get_super_dep_graph(proj, func_addrs)
    util.link_externals_to_earliest_definition(super_dep_graph, cdg, [start_node])

    subject_addrs = [0x401168, 0x40118a]

    util.draw_graph(super_dep_graph.graph, "superRDA.pdf")

    post_dom_tree = cdg.get_post_dominators()

    start_node = cfg.model.get_all_nodes(addr=start_addr)[0]
    high_addrs = [0x401155, 0x401158]
    high_nodes_addr = util.find_high_node_addrs(super_dep_graph, post_dom_tree, start_node, high_addrs)
    print(util.hexlist(high_nodes_addr))

    for path in util.find_implicit(super_dep_graph, post_dom_tree, start_node, subject_addrs, high_addrs):
        print("path")
        for step in path:
            print(hex(step.codeloc.ins_addr))

    return 0
    
if __name__ == "__main__":
    main()
