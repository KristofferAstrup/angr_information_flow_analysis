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
from customutil import util

def main():
    proj = angr.Project('nothing.out', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 4
    )

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)

    util.link_similar_ins_regs(ddg)

    mainAddress = 0x401149
    highAddresses = [0x401155, 0x401158]

    puts_proc = "puts"

    arg_regs = util.get_sim_proc_reg_args(proj, puts_proc)

    subject_addrs = []
    for wrap_addr in util.get_sim_proc_function_wrapper_addrs(proj, puts_proc):
        for caller in util.get_function_node(cdg, wrap_addr).predecessors:
            for reg in arg_regs:
                offset, size = proj.arch.registers[reg.reg_name]
                for occ_node in util.find_first_reg_occurences_from_cdg_node(cdg, ddg, caller, offset, mainAddress):
                    subject_addrs.append(occ_node[0].location.ins_addr)
    print('Subjects:')
    print(util.hexlist(subject_addrs))
    
    print('Explicits:')
    for path in util.find_explicit(proj, ddg, subject_addrs, highAddresses):
        print("Explicit flow:")
        print(path)

    print('Implicits:')
    main_node = util.find_cdg_node(cdg, mainAddress)
    for implicit_high in util.find_implicit_high_ins_addr(proj, cdg, ddg, main_node, highAddresses):
        #print("subject: " + str(subject_addrs) + " | highs: " + str([hex(implicit_high)]))
        for path in util.find_explicit(proj, ddg, subject_addrs, [implicit_high]):
            print("Implicit flow:")
            print(path)

    return 0

if __name__ == "__main__":
    main()
