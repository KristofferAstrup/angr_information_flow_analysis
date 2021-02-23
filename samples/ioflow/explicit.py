import angr
import monkeyhex
import inspect
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angrutils import claripy
import networkx as nx
from networkx_query import search_nodes, search_edges
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('explicit.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./explicit.out', arg0])
    simgr = proj.factory.simgr(state)

    # print(proj.arch)
    # return 0

    idfer = proj.analyses.Identifier()
    for funcInfo in idfer.func_info:
        if(funcInfo.name == "puts"):
            puts_func_info = funcInfo

    #print(puts_func_info)
    
    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 2
    )

    # fm = FunctionManager(proj.kb)
    # func = fm.get_by_addr(addr=puts_func_info.addr)
    # print(func)

    # return 0
    # putsnode = cfg.get_any_node(puts_func_info.addr)
    # putscallernodes = cfg.model.get_predecessors(putsnode)
    # print(putscallernodes)

    ddg = proj.analyses.DDG(cfg = cfg)

    # print("-------")

    # for n in ddg.data_graph.nodes:
    #     attrs = vars(n)
    #     print(', '.join("%s: %s" % item for item in attrs.items()))
    #     location = n.location
    #     break

    print('-------------')

    #for node in search_nodes(ddg.data_graph, {"contains": ["location", puts_func_info.addr]}):
    #input_register_variables = []
    for n in ddg.data_graph.nodes(data=True):
        node = n[0]
        # print(type(n[0].location))
        # for a in dir(n[0].location):
        #     print(n[0].location.block_addr)
        # break
        #print(n[0].location)
        #if n[0].location == 5:
        if node.location.ins_addr == 0x401158 and (not isinstance(node.variable, SimConstantVariable)):
            #print(node)
            #print('####')
            #search(ddg, node.variable, 10)
            #input_register_variables.append(node.variable)
    
            for definition in ddg.find_sources(node.variable, simplified_graph=False):
                if definition.location.block_addr == 0x401149:
                    search(ddg, definition.variable, 10)

            print('-------------')
            continue

        # if(node.location.block_addr == puts_func_info.addr):
        #     if(isinstance(node.variable, SimConstantVariable)):
        #         continue
        #     nodes.append(node)
    # for var in input_register_variables:
    #     search(ddg, var)
        #try:
        
            # print(consumers)
            # print('----')

        #except:
        #    pass


    return 0

def search (ddg, var, iters):
    for definition in ddg.find_definitions(var, simplified_graph=False):
        # if iters == 0:
        #     print("TERM")
        #     print(definition)
        #     continue
        # if iters != 0:
            print('----')
            print(definition)
            print('--')
            consumers = ddg.find_consumers(definition, simplified_graph=False)
            for consumer in consumers:
                print(consumer)
                #print('==' + str(consumer.variable))
                #search(ddg, consumer.variable, iters-1)
            #if len(consumers) == 0:
                #print("DONE")
                #print(definition)

if __name__ == "__main__":
    main()

    # for node in nodes:
    #     print(node.variable)
    #     defs = ddg.find_definitions(node, simplified_graph=True)
    #     print(defs)

    # print(location)

    # print(ddg.get_predecessors(location))

    #networkx_query.search_nodes(ddg.data_graph, )

    # vfg = proj.analyses.VFG(cfg = cfg)
    # ddg = proj.analyses.VSA_DDG(vfg = vfg)
    #plot_ddg_data(ddg.data_graph, fname="ddg", format="pdf",vexinst=False)


    #print(ddg)
    #return 0

    # print(ddg.data_graph.nodes)

    # ret_val_reg = 'rsi'
    # ret_val_reg_offset, ret_val_reg_size = proj.arch.registers[ret_val_reg]
    # ret_var = SimRegisterVariable(ret_val_reg_offset, ret_val_reg_size * 8)

    # t = ddg.find_definitions(ret_var)
    # print(t)

    # print(len(ddg.data_graph.nodes))

    # cl = CodeLocation(
    #     puts_procedure.addr, 
    #     stmt_idx=None,
    #     sim_procedure=puts_procedure)
    # ddg_preds = ddg.get_predecessors(cl)
    # print(ddg_preds)

    # for pred in puts_preds:
    #     return_site_addr = pred.addr + pred.size
    #     cl = CodeLocation(return_site_addr, -1)
    #     ddg_preds = ddg.get_predecessors(cl)
    #     print(ddg_preds)

    # co = simgr.found[0].regs[24]
    # print(co)
    
    # for reg in proj.arch.argument_registers:
    #     print(reg)

    #simgr.found[0].regs.get(reg)

    #0x401149 main
    # simgr.explore(find=0x401149, num_find=1)
    # found = simgr.found[0]
    # print(found)

    # simgr = proj.factory.simgr(found)
    # found.inspect.b('simprocedure', when=angr.BP_AFTER, action=lambda s:
    #     print(s.regs)
    # )
    # simgr.run()

    # 
    # plot_cfg(cfg, 
    #     "cfg_fast_trunc", 
    #     "pdf", 
    #     asminst=True, 
    #     remove_imports=True,  
    #     vexinst=True,
    #     debug_info=True,
    #     remove_path_terminator=False
    # )  

    #util.write_stashes(simgr)
