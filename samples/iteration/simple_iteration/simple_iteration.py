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
from information_flow_analysis import information, out, explicit, implicit, progress

def main():
    proj = angr.Project('simple_iteration.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./simple_iteration.out', arg0])
    simgr = proj.factory.simgr(state)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    simgr.explore(find=0x401149)
    simgr.stash(from_stash='active', to_stash='stash')
    simgr.stash(from_stash='found', to_stash='active')

    simgr.explore()

    loop_seer = angr.exploration_techniques.LoopSeer(cfg=cfg, bound=100000)
    simgr.use_technique(loop_seer)
    simgr.explore()


if __name__ == "__main__":
    main()
