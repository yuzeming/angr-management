from os import stat
from re import A
from typing import List, TYPE_CHECKING
import types

from angr import AngrError, SimError, SimulationManager, options
from angr.state_plugins.sim_action import SimAction, SimActionData
from angr.state_plugins.heap import SimHeapPTMalloc, PTChunk
import claripy
from angrmanagement.plugins.base_plugin import BasePlugin

if TYPE_CHECKING:
    from angr.sim_state import SimState


RED_ZONE_SIZE = 32
class SimHeapPTMallocWithRedzone(SimHeapPTMalloc):
    def __init__(self, heap_base=None, heap_size=None):
        super().__init__(heap_base, heap_size)
    
    def _malloc(self, sim_size):
        return self.malloc(sim_size+2* RED_ZONE_SIZE) + RED_ZONE_SIZE

    def _free(self, ptr):
        return self.free(ptr-RED_ZONE_SIZE)

    def _calloc(self, sim_nmemb, sim_size):
        size = self._conc_alloc_size(sim_nmemb * sim_size)
        addr = self.malloc(size + 2*RED_ZONE_SIZE )  + RED_ZONE_SIZE
        if addr == 0:
            return 0
        if size != 0:
            z = self.state.solver.BVV(0, size * 8)
            self.state.memory.store(addr, z)
        return addr

    def _realloc(self, ptr, size):
        return self.realloc(ptr-RED_ZONE_SIZE, size+2*RED_ZONE_SIZE)+ RED_ZONE_SIZE


class MemoryChecker(BasePlugin):
    AllowList = ["free","malloc","__libc_start_main"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.states = self.workspace.instance.states
        self.states.am_subscribe(self.install_state_plugin)
        
    def install_state_plugin(self, **kwargs):
        if kwargs.get("src",None) != "new":
            return
        state = kwargs.get("state") # type: SimState
        state.register_plugin('heap', SimHeapPTMallocWithRedzone())
        state.options.update({options.TRACK_MEMORY_ACTIONS})
        
    def check_address(self, state: 'SimState', act_list: 'List[SimActionData]'):
        act_list = sorted(act_list, key=lambda act: state.solver.eval(act.addr.ast))
        chunk = PTChunk(state.heap.heap_base, state.heap.state)
        for act in act_list:
            addr = state.solver.eval(act.addr.ast)
            
            if addr < chunk.base:
                continue
            
            while chunk is not None and chunk.base + state.solver.eval(chunk.get_size()) <= addr:
                chunk = chunk.next_chunk()
            
            
            if chunk is None:
                break
            
            size = state.solver.eval(chunk.get_size())
            
            err_str = ""
            if chunk.is_free():
                err_str = "\n=== Use-After-Free ===\nMemory Address:{:#x}\nInstrument Address:{:#x}\n".format(addr, act.ins_addr)
            
            elif addr < chunk.base + 2 * chunk._chunk_size_t_size + RED_ZONE_SIZE:
                err_str = "\n=== Out-of-Bound(Low) ===\nMemory Address:{:#x}\nInstrument Address:{:#x}\n".format(addr, act.ins_addr)

            elif chunk.base + size - RED_ZONE_SIZE <= addr:
                err_str = "\n=== Out-of-Bound(High) ===\nMemory Address:{:#x}\nInstrument Address:{:#x}\n".format(addr, act.ins_addr)

            if err_str:
                if state.posix.stderr.writable:
                    state.posix.stderr.write(None ,err_str.encode())
                return True
            
        return False

    def check_heap(self, state: 'SimState'):
        #heap = state.heap #type: SimHeapPTMalloc
        #heap.print_heap_state()

        actions=state.history.actions.hardcopy #type: List[SimAction]
        if len(actions) == 0:
            return False
        last_bbl_addr = actions[-1].bbl_addr
        address_list = []
        for act in reversed(actions):
            if act.bbl_addr != last_bbl_addr :
                break
            if act.type=='mem' and \
                (act.sim_procedure is None or act.sim_procedure.display_name not in self.AllowList):
                address_list.append(act)
        return self.check_address(state, address_list)

    def step_callback(self, simgr):
        simgr.move("active","Heap_Checker",self.check_heap)
