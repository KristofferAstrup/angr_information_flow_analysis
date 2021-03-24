import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_out

def refine_loop_body(cfg, loop):
    return 0

#Find (approx) inf loops




 # cfg = util_information.cfg_emul(proj, simgr, state)
    # start_node = util_information.find_cfg_node(cfg, 0x401149)
    # func_addrs = util_explicit.get_unique_reachable_function_addresses(cfg, start_node)
    # funcs = util_information.find_func_from_addrs(proj, func_addrs)
    # loop_res = proj.analyses.LoopFinder(functions=funcs)
    # # for loop in loop_res.loops:
    # #     print(hex(loop.entry.addr))
    # #     print(loop.body_nodes)
    # #     for block in loop.body_nodes:
    # #         print(hex(block.addr))
    # #         print(block.predecessors())
    # for k in loop_res.loops_hierarchy.keys():
    #     print('--')
    #     print(hex(k))
    #     for loop in loop_res.loops_hierarchy[k]:
    #         print(hex(loop.entry.addr))