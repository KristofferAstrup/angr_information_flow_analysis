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
    proj = angr.Project('mixed.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./mixed.out', arg0])
    simgr = proj.factory.simgr(state)

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 0
    )
    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)

    high_addrs = [0x4011ac, 0x4011af]
    start_addr = 0x4011a0

    puts_proc = "puts"
    arg_regs = util.get_sim_proc_reg_args(proj, puts_proc)
    subject_addrs = []
    for wrap_addr in util.get_sim_proc_function_wrapper_addrs(proj, puts_proc):
        for caller in util.get_function_node(cdg, wrap_addr).predecessors:
            for reg in arg_regs:
                offset, size = proj.arch.registers[reg.reg_name]
                for occ_node in util.find_first_reg_occurences_from_cdg_node(cdg, ddg, caller, offset, start_addr):
                    subject_addrs.append(occ_node[0].location.ins_addr)

    start_node = util.find_cfg_node(cfg, start_addr)
    func_addrs = util_information.get_unique_reachable_function_addresses(cfg, start_node)
    super_dep_graph = util.get_super_dep_graph(proj, func_addrs)

    util.link_externals_to_earliest_definition(super_dep_graph, cdg, [start_node])
    
    util.draw_graph(super_dep_graph.graph, fname="super_rda.pdf")

    for explicit_path in util.find_explicit(super_dep_graph, subject_addrs, high_addrs):
        print('----Path-----')
        for step in explicit_path.path:
            print(hex(step.codeloc.ins_addr))

    return 0

if __name__ == "__main__":
    main()
