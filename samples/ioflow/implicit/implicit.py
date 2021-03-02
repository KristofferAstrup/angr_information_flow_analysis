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
    proj = angr.Project('implicit.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit.out', arg0])
    simgr = proj.factory.simgr(state)

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 10
    )

    print(list(util.get_arg_regs(proj)))
    return 0

    # cfg = proj.analyses.CFG(resolve_indirect_jumps=True, 
    #                            cross_references=True, 
    #                            force_complete_scan=False, 
    #                            normalize=True, 
    #                            symbols=True)

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)

    n = list(util.find_ddg_nodes(ddg,0x401180))[0]
    sub_ddg = ddg.data_sub_graph(n, simplified=False)
    util.draw_graph(sub_ddg, fname="sub.pdf")
    return 0
    #print(list(util.find_explicit(proj, ddg, [0x401190], [0x401180])))

    #return 0
    #print(dir(ddg))
    #return 0
    # print(dir(cdg))
    # return 0

    # plot_cdg(cfg, cdg, fname="cdg_2", format="pdf")
    # plot_ddg_data(ddg.data_graph, fname="ddg_2", format="pdf")
    # return 0
    
    # main_func = None
    # for funcInfo in proj.analyses.Identifier().func_info:
    #     if(funcInfo.name == "main"):
    #         main_func = funcInfo

    # res = angr.analyses.reaching_definitions.ReachingDefinitionsAnalysis(
    #     subject = main_func,
    #     func_graph = main_func.graph,
    #     cc = main_func.calling_convention,
    #     observation_points = [("fuckdig", 0x0040118b, 0)],
    #     dep_graph = dep_graph.DepGraph(),
    #     function_handler=
    # )

    highAddresses = [0x401155, 0x401158]

    branch_addr = 0x401149
    branch_ins = None
    for n in cdg.graph.nodes(data=True):
        if n[0].block_id and n[0].block_id.addr == branch_addr:
            branch_ins = n[0].instruction_addrs[len(n[0].instruction_addrs)-1]
            print(hex(branch_ins))
    print("BRANCH: " + str(branch_ins))
    print('-----')

    util.link_similar_ins_regs(ddg)

    isHighContext = False
    for path in util.find_explicit(proj, ddg, [branch_ins], highAddresses):
        # for step in path:
        #     print(hex(step.location.ins_addr))
        # print('---')
        isHighContext = True

    print('-------------------------------')

    func_nodes = list(util.find_procedure_nodes(proj, ddg, "puts"))
    
    for path in util.find_explicit(proj, ddg, lowNodes=func_nodes, highAddresses=[0x401179, 0x401180]):
        print(path)

    print('----DEN SKAL VÆRE TOM-----')
    for path in util.find_explicit(proj, ddg, lowNodes=func_nodes, highAddresses=highAddresses):
        print(path)


if __name__ == "__main__":
    main()
