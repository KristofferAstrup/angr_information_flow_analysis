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
        context_sensitivity_level = 2
    )

    ddg = proj.analyses.DDG(cfg = cfg)
    cdg = proj.analyses.CDG(cfg = cfg)

    branch_addr = 0x401149
    branch_ins = None
    for n in cdg.graph.nodes(data=True):
        if n[0].block_id and n[0].block_id.addr == branch_addr:
            #print(dir(n[0]))
            #print(n[0].successors)
            branch_ins = n[0].instruction_addrs[len(n[0].instruction_addrs)-1]
            #print(hex(n[0].return_target))
    
    regBlacklist = [proj.arch.ip_offset]
    for n in ddg.data_graph.nodes(data=True):
        if n[0].location.ins_addr == branch_ins and not isinstance(n[0].variable, SimConstantVariable):
            if(n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist):
                continue
            print(n[0])
            print(dir(n[0]))
            print('---')


if __name__ == "__main__":
    main()
