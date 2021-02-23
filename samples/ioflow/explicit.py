import angr
import monkeyhex
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('explicit.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./explicit.out', arg0])
    simgr = proj.factory.simgr(state)

    idfer = proj.analyses.Identifier()
    for funcInfo in idfer.func_info:
        if(funcInfo.name == "puts"):
            puts_func_info = funcInfo
    simgr.explore(find=puts_func_info.addr)
    found = simgr.found[0]
    
    #6295648 main procedure
    #5242888 puts procedure
    puts_procedure = proj._sim_procedures[5242888]
    
    print(found)
    #sim = proj._sim_procedures[found.addr]
    print()

    cfg = proj.analyses.CFGEmulated(
        keep_state=True, 
        fail_fast=True, 
        starts=[state.addr], 
        initial_state=state,
        state_add_options=angr.options.refs,
        context_sensitivity_level = 2
    )

    # puts_func = cfg.get_any_node(puts_func_info.addr)
    # puts_preds = cfg.get_all_predecessors(puts_func)

    ddg = proj.analyses.DDG(cfg = cfg)

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

    cl = CodeLocation(
        puts_procedure.addr, 
        stmt_idx=None,
        sim_procedure=puts_procedure)
    ddg_preds = ddg.get_predecessors(cl)
    print(ddg_preds)

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

    return 0

if __name__ == "__main__":
    main()