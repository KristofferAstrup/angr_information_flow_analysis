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
from customutil import util_information, util_explicit, util_implicit, util_out, util_rda, util_analysis

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

    high_addrs = {0x401158, 0x401155}
    start_addr = 0x401149

    # start_node = cfg.model.get_all_nodes(addr=start_addr)[0]
    # arg_regs = util_information.get_sim_proc_reg_args(proj, puts_proc)
    # print(arg_regs)
    # # start_node = cfg.model.get_all_nodes(addr=start_addr)[0]
    # subject_addrs = []
    # for wrap_addr in util_information.get_sim_proc_function_wrapper_addrs(proj, puts_proc):
    #     for caller in util_information.get_function_node(cdg, wrap_addr).predecessors:
    #         for reg in arg_regs:
    #             offset, size = proj.arch.registers[reg.reg_name]
    #             for occ_node in util_information.find_first_reg_occurences_from_cdg_node(cdg, super_dep_graph, caller, offset, start_addr):
    #                 subject_addrs.append(occ_node.codeloc.ins_addr)


    #rda_graph = util_rda.get_super_dep_graph_with_linking(proj, cfg, cdg, start_node)
    #util_explicit.enrich_rda_graph_explicit(rda_graph, high_addrs, low_addrs)

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start_addr=start_addr,high_addrs=high_addrs)
    subject_addr = ifa.find_and_add_subject_addrs("puts")
    leaks = ifa.find_all_leaks()
    
    #util_out.draw_rda_graph(proj, rda_graph)
    return

if __name__ == "__main__":
    main()
