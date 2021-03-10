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
    util.link_similar_ins_regs(ddg)
    #util.link_similar_mem(ddg)
    #return 
    # vfg = proj.analyses.VFG(cfg = cfg, function_start=proj.entry,
    #     context_sensitivity_level=4, interfunction_level=4,
    #     remove_options={ angr.options.OPTIMIZE_IR })
    # util.draw_graph(vfg.graph, "vfg.pdf")
    # vsa = angr.analyses.VSA_DDG(vfg=vfg,context_sensitivity_level=4,interfunction_level=4,keep_data=True)
    # util.draw_graph(vsa.graph, fname="vsa.pdf")
    
    print('---')
    for path in util.find_explicit(proj, ddg, [0x401174], [0x4011c5]):
        print(path)
    print('---')
    for path in util.find_explicit(proj, ddg, [0x40115d], [0x401174]):
        print(path)
    

    return

    util.clear_constant_ddg_nodes(ddg)
    #libc_start_main_node = list(util.find_cdg_block_nodes(cdg, 0x4011a0))[0]
    #print(libc_start_main_node)
    #block_addr_whitelist = list(util.find_all_descendants_block_address(cfg, libc_start_main_node))
    #block_addr_whitelist.append(libc_start_main_node[0].block.addr)
    #print(util.hexlist(block_addr_whitelist))
    #util.filter_ddg_block_whitelist(ddg, block_addr_whitelist)
    imp_nodes = list(util.find_ddg_nodes(ddg, 0x40115d))
    print(imp_nodes)
    imp_nodes += util.get_all_ancestors_of_ddg_ins(ddg, imp_nodes)
    util.filter_ddg_node_whitelist(ddg, imp_nodes)
    plot_ddg_data(ddg.data_graph, "ddg_40115d", format="pdf", asminst=True, vexinst=False)
    
    # plot_cdg(cfg, cdg, "cdg", format="pdf")
    # return 

    highAddresses = [0x4011ac, 0x4011af]

    for path in util.find_explicit(proj, ddg, [0x401195], highAddresses):
        #if len(path) > 1:
        print(path)

    return 

    mainAddress = 0x4011a0

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
