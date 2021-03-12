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
from customutil import util

def main():
    proj = angr.Project('implicit.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit.out', arg0])
    simgr = proj.factory.simgr(state)

    # cfg = proj.analyses.CFGEmulated(
    #     keep_state=True, 
    #     fail_fast=True, 
    #     starts=[state.addr], 
    #     initial_state=state,
    #     state_add_options=angr.options.refs,
    #     context_sensitivity_level = 10
    # )

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        normalize=True, 
        starts=[simgr.active[0].addr],
        initial_state=state,
        context_sensitivity_level=5,
        resolve_indirect_jumps=True
    )
    print("CHECK HERE!!\n")
    #print(cfg.immediate_postdominators(0x401149))


    #print(cfg.immediate_postdominators(nodes[0]))
    #print(dir(nodes[0]))

    # return
    # print(nodes[0])
    # print(nodes[1].input_state)

    # nodes = cfg.get_all_nodes(addr=0x500008)
    # print(dir(nodes[0]))
    # print(nodes[0].merge(*iterables, key=None, reverse=False))
    # print(nodes[1].input_state) 
    
    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)
    #print(cdg.graph.nodes)
    ''' print(dir(cdg.graph))
    print((cfg.immediate_postdominators(nodes[0])))
    print("------")
    print((cfg.immediate_postdominators(nodes[0])[nodes2[0]]))
    util.draw_tree(cdg.get_post_dominators()) '''
    #util.draw_tree(angr.utils.graph.PostDominators(cfg.graph,nodes[0]).post_dom,fname="Node1.pdf")
    nodes = cfg.model.get_all_nodes(addr=0x401184)
    nodes2 = cfg.model.get_all_nodes(addr=0x401179)
    branch = cfg.model.get_all_nodes(addr=0x401149)
    print(nodes)
    print(nodes2)
    test_nodes(cdg,nodes[0],nodes2[0])
    return

    util.link_similar_ins_regs(ddg)

    main_address = proj.kb.functions.function(name='main').addr
    main_node = util.find_cdg_node(cdg, main_address)
    high_addresses = {0x401158, 0x401155}
    puts_proc = "puts"

    arg_regs = util.get_sim_proc_reg_args(proj, puts_proc)

    subject_addrs = []
    for wrap_addr in util.get_sim_proc_function_wrapper_addrs(proj, puts_proc):
        for caller in util.get_function_node(cdg, wrap_addr).predecessors:
            for reg in arg_regs:
                offset, size = proj.arch.registers[reg.reg_name]
                for occ_node in util.find_first_reg_occurences_from_cdg_node(cdg, ddg, caller, offset, main_address):
                    subject_addrs.append(occ_node[0].location.ins_addr)
    print('Subjects:')
    print(util.hexlist(subject_addrs))
    
    print('Explicits:')
    for path in util.find_explicit(proj, ddg, subject_addrs, high_addresses):
        print(path)

    print('Implicits:')
    for implicit_high in util.find_implicit_high_ins_addr(proj, cdg, ddg, main_node, high_addresses):
        #print("subject: " + str(subject_addrs) + " | highs: " + str([hex(implicit_high)]))

        for path in util.find_explicit(proj, ddg, subject_addrs, [implicit_high]):
            print(path)

    return 0

def test_nodes(cdg,node1, node2):
    n1_to_n2=False
    n2_to_n1=False
    try:
        path = nx.dijkstra_path(cdg.get_post_dominators(),node1,node2)
        n1_to_n2=True
    except:
        pass #No path

    try:
        path = nx.dijkstra_path(cdg.get_post_dominators(),node2,node1)
        n2_to_n1=True
    except:
        pass #No path

    if n1_to_n2:
        print("Node1 postdominates Node2")
        return node1
    elif n2_to_n1:
        return node2
        print("Node2 postdominates Node1")
    else:
        return None
        print("Node1 and Node2 does not postdominate each other")

  
    



if __name__ == "__main__":
    main()
