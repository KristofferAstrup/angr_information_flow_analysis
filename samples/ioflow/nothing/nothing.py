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
    main_node = None
    for n in cfg.graph.nodes:
        if "main" == n.name:
            main_node = n
            break
    
    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)

    print('--------')

    lowAddresses = {0x401175}
    highAddresses = {0x401158, 0x401155}
    # for arg_node in util.find_ddg_arg_nodes(proj, ddg, main_node.addr):
    #     highAddresses.append(arg_node.location.ins_addr)
    # print(highAddresses)
    
    for path in util.find_explicit(proj, ddg, lowAddresses, highAddresses):
        print(path)

    return 0

if __name__ == "__main__":
    main()



# for n in util.find_ddg_arg_nodes(proj, ddg):
#         highAddresses.append(n.location.ins_addr)


   # idfer = proj.analyses.Identifier()
    # for funcInfo in idfer.func_info:
    #     if(funcInfo.name == "puts"):
    #         puts_func_info = funcInfo
