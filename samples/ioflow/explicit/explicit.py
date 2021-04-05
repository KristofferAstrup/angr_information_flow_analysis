import angr
import monkeyhex
import inspect
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angrutils import *
import networkx as nx
from networkx_query import search_nodes, search_edges
import sys
sys.path.append('../../../')
from customutil import util_information, util_explicit, util_implicit, util_out, util_analysis

def main():
    proj = angr.Project('explicit.out', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()
    # simgr = proj.factory.simgr(state)

    # cfg = proj.analyses.CFGEmulated(
    #     keep_state=True, 
    #     fail_fast=True, 
    #     starts=[state.addr], 
    #     initial_state=state,
    #     state_add_options=angr.options.refs,
    #     context_sensitivity_level = 4
    # )

    # ddg = proj.analyses.DDG(cfg = cfg)
    # cdg = proj.analyses.CDG(cfg = cfg)

    # print('--------')

    low_addrs = {0x401172}
    high_addrs = {0x401158, 0x401155}
    start_addr = 0x401149

    # start_node = cfg.model.get_all_nodes(addr=start_addr)[0]
    
    # rda = util_explicit.get_super_dep_graph_with_linking(proj, cfg, cdg, start_node)

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start_addr=start_addr,high_addrs=high_addrs,subject_addrs=low_addrs)
    leaks = ifa.find_all_leaks()
    print(leaks)
    # explicit_paths = list(util_explicit.find_explicit(rda, low_addrs, high_addrs))
    # for path in explicit_paths:
    #     print(path.print_path())

    #util_out.draw_super_dep_graph(proj, cfg, cdg, start_node=start_node, high_addrs=high_addrs, subject_addrs=low_addrs)
    return

if __name__ == "__main__":
    main()
