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
sys.path.append('../../../../')
from angr_taint import launcher

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

    # cfg = proj.analyses.CFG(resolve_indirect_jumps=True, 
    #                            cross_references=True, 
    #                            force_complete_scan=False, 
    #                            normalize=True, 
    #                            symbols=True)

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)
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


    # taint_engine = launcher.TaintLauncher('implicit_2.out', log_path="angr_taint.out")
    # taint_engine.run(start_addr=branch_ins, check_function=lambda x: True)
    
    # return 0

    groupedRegNodes = {}
    for n in ddg.data_graph.nodes(data=True):
        try:
            if isinstance(n[0].variable, SimRegisterVariable):
                key = str(n[0].variable.reg)+":"+str(hex(n[0].location.ins_addr))
                groupedRegNodes.setdefault(key, []).append(n[0])
        except:
            pass

    for k in groupedRegNodes:
        nodes = groupedRegNodes[k]
        for i in range(len(nodes)):
            if i==0:
                continue
            ddg.data_graph.add_edge(nodes[i-1], nodes[i])
            ddg.data_graph.add_edge(nodes[i], nodes[i-1])

    isHighContext = False
    for path in util.find_explicit(proj, ddg, [branch_ins], highAddresses):
        for step in path:
            print(hex(step.location.ins_addr))
        print('---')
        isHighContext = True


if __name__ == "__main__":
    main()
