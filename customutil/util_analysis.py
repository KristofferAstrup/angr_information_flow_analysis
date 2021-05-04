import angr
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress, util_termination, util_timing, util_rda

class InformationFlowAnalysis:
    def __init__(self, proj, high_addrs, state=None, start=None, subject_addrs=[]):
        self.project = proj
        self.state = state if state else proj.factory.entry_state()
        self.simgr = proj.factory.simgr(self.state)#, hierarchy=angr.state_hierarchy.StateHierarchy())
        self.cfg = util_information.cfg_emul(self.project, self.simgr, self.state)
        self.ddg = proj.analyses.DDG(cfg = self.cfg)
        self.cdg = proj.analyses.CDG(cfg = self.cfg)
        self.high_addrs = high_addrs
        self.subject_addrs = list(subject_addrs)

        self.start_node = None
        if isinstance(start, int):
            self.start_node = self.cfg.model.get_any_node(addr=start)
        if isinstance(start, str):
            self.start_node = util_information.find_cfg_function_node(self.cfg, start)
        if not self.start_node:
            self.start_node = self.cfg.model.get_any_node(addr=self.state.addr)

        self.function_addrs = util_information.get_unique_reachable_function_addresses(self.cfg, self.start_node)
        self.rda_graph = util_rda.get_super_dep_graph_with_linking(self.project, self.cfg, self.start_node, func_addrs=self.function_addrs)
        self.post_dom_tree = self.cdg.get_post_dominators()
        
        self.simgr.explore(find=self.start_node.addr)
        if len(self.simgr.found) < 1:
            raise("No main entry block state found!")
        self.state = self.simgr.found[0]
        self.__enrich_rda__()

    def find_explicit_flows(self):
        if not self.subject_addrs:
            raise Exception("Please add subject addresses to the InformationFlowAnalysis")
        self.__enrich_rda__()
        flows = []
        for explicit_flow in util_explicit.find_explicit(rda_graph=self.rda_graph, subject_addrs=self.subject_addrs):
            flows.append(explicit_flow)
        return flows

    def find_implicit_flows(self):
        if not self.subject_addrs:
            raise Exception("Please add subject addresses to the InformationFlowAnalysis")
        self.__enrich_rda__()
        flows = []
        for implicit_flow in util_implicit.find_implicit(rda_graph=self.rda_graph, subject_addrs=self.subject_addrs):
            flows.append(implicit_flow)
        return flows

    def find_termination_leaks(self, spinning_state=None, progress_states=None):
        self.__enrich_rda__()
        if not spinning_state or not progress_states:
            loop_seer = angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=10)
            simgr = self.simgr.copy()
            simgr.use_technique(loop_seer)
            simgr.explore(find=self.start_node.addr)
            if len(simgr.found) < 1:
                raise("No main entry block state found!")
            state = simgr.found[0]
            simgr.stash(from_stash='active', to_stash='stash')
            simgr.stash(from_stash='found', to_stash='active')
            simgr.explore()
            spinning_state = simgr.spinning[0]
            progress_states = simgr.deadended

        proofs = util_termination.get_termination_leak(self.rda_graph, self.cfg, self.high_addrs, spinning_state, progress_states)
        return proofs

    def find_timing_leaks(self):
        self.__enrich_rda__()
        branchings = util_implicit.find_high_branchings(self.rda_graph, self.cdg, self.function_addrs, self.high_addrs)
        leaks = []
        for branching in branchings:
            for leak in util_timing.test_timing_leaks(self.project, self.cfg, self.state, branching):
                leaks.append(leak)
        return leaks

    def find_progress_leaks(self):
        self.__enrich_rda__()
        branchings = util_implicit.find_high_branchings(self.rda_graph, self.cdg, self.function_addrs, self.high_addrs)   
        leaks = []
        for branching in branchings:
            leak = util_progress.test_observer_diff(self.project, self.cfg, self.state, branching)
            if leak:
                leaks.append(leak)
        return leaks

    def find_and_add_subject_addrs(self, procedure_name):
        subject_addrs = []
        arg_regs = util_information.get_sim_proc_reg_args(self.project, procedure_name)
        for wrap_addr in util_information.get_sim_proc_function_wrapper_addrs(self.project, procedure_name):
            for wrapper in util_information.find_cfg_nodes(self.cfg, wrap_addr):
                for caller in wrapper.predecessors:
                    for reg in arg_regs:
                        offset, size = self.project.arch.registers[reg.reg_name]
                        for occ_node in util_information.find_first_reg_occurences_from_cfg_node(self.rda_graph, caller, offset, self.start_node.addr):
                            subject_addrs.append(occ_node.codeloc.ins_addr)
        subject_addrs = list(set(subject_addrs))
        if subject_addrs:
            self.subject_addrs.extend(subject_addrs)
        return subject_addrs

    #---Precedence---
    #   Explicit (static)
    #   Implicit (static)
    #   Termination (concolic)
    #   Progress (concolic)
    #   Timing (concolic)
    #----------------
    def find_all_leaks(self):
        if self.subject_addrs:
            explicit_flows = self.find_explicit_flows()
            if len(list(explicit_flows)) > 0:
                print(f"Found {len(explicit_flows)} explicit flow{('s' if len(explicit_flows) > 1 else '')}:")
                print(explicit_flows)
                return explicit_flows
            print("Found no explicit flows")

            implicit_flows = self.find_implicit_flows()
            if implicit_flows:
                print(f"Found {len(implicit_flows)} implicit flow{'s' if len(implicit_flows) > 1 else ''}:")
                print(implicit_flows)
                return implicit_flows
            print("Found no implicit flows")
        else:
            print("No subject addresses found, skipping implicit/explicit")
        termination_leaks = self.find_termination_leaks()
        if len(list(termination_leaks)) > 0:
            print(f"Found {len(termination_leaks)} termination leak{'s' if len(termination_leaks) > 1 else ''}:")
            print(termination_leaks)
            return termination_leaks
        print("Found no termination leaks")

        progress_leaks = self.find_progress_leaks()
        if len(list(progress_leaks)) > 0:
            print(f"Found {len(progress_leaks)} progress leak{'s' if len(progress_leaks) > 1 else ''}:")
            print(progress_leaks)
            return progress_leaks
        print("Found no progress leaks")

        timing_leaks = self.find_timing_leaks()
        if timing_leaks:
            print(f"Found {len(timing_leaks)} timing leak{'s' if len(timing_leaks) > 1 else ''}:")
            print(timing_leaks)
            return timing_leaks
        print("Found no timing leaks")

        print("No leaks found")
        return []

    def __enrich_rda__(self):
        util_explicit.enrich_rda_graph_explicit(self.rda_graph, self.high_addrs, self.subject_addrs)
        util_implicit.enrich_rda_graph_implicit(self.rda_graph, self.cdg, self.function_addrs)

    def draw_everything(self):
        self.cfg_fast = self.project.analyses.CFGFast()
        util_out.draw_everything_with_data(self.project, self.cfg, self.cfg_fast, self.cdg, self.post_dom_tree, self.rda_graph)

    def bound_reached_handler(self, loopSeer, succ_state):
        self.s = loopSeer
        loopSeer.cut_succs.append(succ_state)
        #DO STUFF

    def call_before_handler(self, state):
        sim_name = state.inspect.simprocedure_name
        if not sim_name in self.__progress_function_names:
            return
        plugin = state.plugins[util_progress.ProgressRecordPlugin.NAME]
        plugin.callfunction = self.__progress_function_map[sim_name]
        plugin.callstate = state
        pass

    def call_after_handler(self, state):
        plugin = state.plugins[util_progress.ProgressRecordPlugin.NAME]
        if not plugin.callfunction:
            return
        if state.addr in plugin.callfunction.addrs:
            return
        sim_name = state.inspect.simprocedure_name
        if not plugin.callstate:
            return
        progress_obj = plugin.callfunction.progress_delegate(plugin.callstate, state)
        plugin.callfunction = None
        plugin.callstate = None
        progress_record = util_progress.ProgressRecord(progress_obj, state.history.block_count, )
        plugin.records.append(progress_record)

    def find_covert_leaks(self, bound=50, epsilon_threshold=0, record_procedures=None, progress_functions=None):
        if not record_procedures:
            record_procedures = [("sleep", None)]
            
        if not progress_functions:
            progress_functions = [
                util_progress.PutsProgressFunction(self.project.kb),
                util_progress.PrintfProgressFunction(self.project.kb)
            ]

        start_state = self.state.copy()
        simgr = self.project.factory.simgr(start_state)
        self.__covert_simgr = simgr
        self.__progress_function_names = list(map(lambda f: f.name, progress_functions))
        self.__progress_function_map = {f.name : f for f in progress_functions}

        start_state.inspect.b('simprocedure', when=angr.BP_BEFORE, action=self.call_before_handler)
        start_state.inspect.b('exit', when=angr.BP_AFTER, action=self.call_after_handler)
        #Make bp for exiting high block (from CDG) and add instruction count to current TimingInterval of TimingPlugin
        start_state.register_plugin(util_progress.ProgressRecordPlugin.NAME, util_progress.ProgressRecordPlugin([],None,None))
        start_state.register_plugin(util_timing.ProcedureRecordPlugin.NAME, util_timing.ProcedureRecordPlugin({}))
        hook_addrs = []
        if record_procedures:
            for record_procedure in record_procedures:
                proc_name = record_procedure[0]
                proc_addr = util_information.get_sim_proc_addr(proj, proc_name)
                if proc_addr:
                    proc = proj._sim_procedures[proc_addr]
                    proc_wrapper_funcs = util_information.get_sim_proc_function_wrapper_addrs(proj, proc_name)
                    for wrap_addr in proc_wrapper_funcs:
                        args = proc.cc.args if not record_procedure[1] else record_procedure[1]
                        proj.hook(wrap_addr, lambda s: util_timing.procedure_hook(proj, s, proc, args))
                        hook_addrs.append(wrap_addr)

        simgr = self.project.factory.simgr(start_state)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=bound, limit_concrete_loops=True, bound_reached=self.bound_reached_handler))

        # while(True):
        #     if len(simgr.active) == 0:
        #         break
        #     simgr.step()
        simgr.run()

        for addr in hook_addrs:
            proj.unhook(addr)

        for spinning_state in simgr.spinning:
            leak = util_termination.get_termination_leak(self.rda_graph, self.cfg, self.high_addrs, spinning_state, simgr.deadended)
            if leak:
                return [leak]

        #

        #For each TimingInterval 

        return []