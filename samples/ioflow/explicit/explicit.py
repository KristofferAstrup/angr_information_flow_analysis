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
from customutil import util_information, util_explicit, util_implicit, util_out, util_rda, util_analysis

def aftyr(state):
    print("awd")

def before(state):
    print("awd")

def main():
    proj = angr.Project('explicit.out', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()

    simgr = proj.factory.simgr(state)
    simgr.explore(find=0x401149)
    state = simgr.found[0]
    start_state.inspect.b('fork', when=angr.BP_BEFORE, action=self.fork_before_handler)
    start_state.inspect.b('fork', when=angr.BP_AFTER, action=self.fork_after_handler)
    simgr = proj.factory.simgr(state)
    simgr.run()

    return

    high_addrs = {0x401158, 0x401155}
    start_addr = 0x401149

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start=start_addr,high_addrs=high_addrs)
    subject_addr = ifa.find_and_add_subject_addrs("puts")
    ifa.draw_everything()
    ifa.find_all_leaks()
    return

if __name__ == "__main__":
    main()
