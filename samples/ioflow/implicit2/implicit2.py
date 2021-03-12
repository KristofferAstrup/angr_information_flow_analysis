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
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 10
    )
    #cfg = proj.analyses.CFGFast()

    #ddg = proj.analyses.DDG(cfg = cfg)
    #cdg = proj.analyses.CDG(cfg = cfg)

    #util.draw_everything(proj, simgr, state)

    # for arg in util.get_arg_regs(proj):
    #     print(arg)
    

    # func = proj.kb.functions.function(addr=0x401149)
    # print(func)
    # rda = proj.analyses.ReachingDefinitions(
    #     subject = func,
    #     cc = func.calling_convention,
    #     dep_graph = dep_graph.DepGraph(),
    #     observe_all=True
    # )
    # print(dir(rda.dep_graph))
    # util.draw_graph(rda.dep_graph.graph, fname="rda.pdf")

    #return 0

if __name__ == "__main__":
    main()
