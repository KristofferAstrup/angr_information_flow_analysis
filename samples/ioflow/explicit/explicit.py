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
    proj = angr.Project('explicit.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    arg1 = claripy.BVS('arg1', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./explicit.out', arg0, arg1])
    simgr = proj.factory.simgr(state)

    idfer = proj.analyses.Identifier()
    for funcInfo in idfer.func_info:
        if(funcInfo.name == "puts"):
            puts_func_info = funcInfo

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 2
    )

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)
    plot_cdg(cfg, cdg, fname="cdg", format="pdf")

    print('--------')

    lowAddresses = {0x401172}
    highAddresses = {0x401158, 0x401155}

    for path in util.find_explicit(proj, ddg, lowAddresses, highAddresses):
        print(path)

    return 0

if __name__ == "__main__":
    main()
