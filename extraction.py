#!/usr/bin/env python3
"""
KVM Interface Enumerator for Guest-to-Host Escape Research
Extracts ioctls, hypercalls, and exposed functions from KVM modules
"""

import os
import re
import subprocess
import json
from pathlib import Path

class KVMEnumerator:
    def __init__(self, kernel_path="/lib/modules/$(uname -r)"):
        self.kernel_path = os.path.expandvars(kernel_path)
        self.results = {
            'ioctls': [],
            'hypercalls': [],
            'exposed_functions': [],
            'device_files': [],
            'msrs': []
        }
    
    def run_cmd(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return ""
    
    def extract_ioctls_from_source(self, filepath):
        """Extract IOCTL definitions from C headers"""
        ioctls = []
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Pattern for KVM ioctls
            patterns = [
                r'#define\s+(KVM_[A-Z_]+)\s+(_IO|_IOW|_IOR|_IOWR)\([^)]+\)',
                r'#define\s+(KVM_[A-Z_]+)\s+0x[0-9a-fA-F]+',
                r'#define\s+(KVM_[A-Z_]+)\s+\d+'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        ioctls.append(match[0])
                    else:
                        ioctls.append(match)
            
            # Also look for ioctl function definitions
            ioctl_funcs = re.findall(r'\b(?:ioctl|unlocked_ioctl)\s*\([^)]+\)', content)
            self.results['exposed_functions'].extend(ioctl_funcs)
            
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        
        return ioctls
    
    def extract_hypercalls(self, filepath):
        """Extract KVM hypercall definitions"""
        hypercalls = []
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # KVM hypercall patterns
            patterns = [
                r'#define\s+(KVM_HC_[A-Z_]+)\s+\d+',
                r'KVM_HYPERCALL\s*\([^)]+\)',
                r'kvm_hypercall\d+\s*\([^)]*\)'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                hypercalls.extend(matches)
                
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        
        return hypercalls
    
    def analyze_kvm_module(self, module_path):
        """Analyze KVM kernel module for exposed symbols"""
        print(f"\n[*] Analyzing module: {module_path}")
        
        # Use modinfo to get module info
        modinfo = self.run_cmd(f"modinfo {module_path}")
        
        # Extract exported symbols using nm
        symbols = self.run_cmd(f"nm -g {module_path} 2>/dev/null | grep ' T ' | head -20")
        
        # Look for ioctl handlers
        ioctl_refs = self.run_cmd(f"objdump -t {module_path} 2>/dev/null | grep -i ioctl")
        
        return {
            'modinfo': modinfo,
            'symbols': symbols.split('\n') if symbols else [],
            'ioctl_refs': ioctl_refs.split('\n') if ioctl_refs else []
        }
    
    def scan_kvm_headers(self):
        """Scan KVM header files for interfaces"""
        header_paths = [
            "/usr/include/linux/kvm.h",
            "/usr/include/linux/kvm_para.h",
            f"{self.kernel_path}/source/include/linux/kvm*.h",
            f"{self.kernel_path}/source/include/uapi/linux/kvm.h"
        ]
        
        for pattern in header_paths:
            for header in Path('/').glob(pattern.lstrip('/')):
                if header.exists():
                    print(f"[+] Scanning header: {header}")
                    
                    # Extract ioctls
                    ioctls = self.extract_ioctls_from_source(str(header))
                    self.results['ioctls'].extend(ioctls)
                    
                    # Extract hypercalls
                    hypercalls = self.extract_hypercalls(str(header))
                    self.results['hypercalls'].extend(hypercalls)
    
    def find_kvm_devices(self):
        """Find KVM-related device files"""
        devices = []
        
        # Check /dev/kvm
        if os.path.exists("/dev/kvm"):
            devices.append("/dev/kvm")
            
        # Check for vhost devices
        vhost_devs = self.run_cmd("find /dev -name 'vhost*' -type c 2>/dev/null")
        if vhost_devs:
            devices.extend(vhost_devs.split('\n'))
        
        # Check for virtio devices
        virtio_devs = self.run_cmd("ls /sys/class/virtio*/ 2>/dev/null")
        
        self.results['device_files'] = devices
        return devices
    
    def enumerate_msrs(self):
        """Enumerate MSRs exposed to KVM guests"""
        try:
            # Check MSR bitmaps and passthrough
            msr_files = [
                "/sys/module/kvm_intel/parameters/allow_unsafe_msrs",
                "/sys/module/kvm/parameters/allow_unsafe_msrs"
            ]
            
            msrs = []
            for msr_file in msr_files:
                if os.path.exists(msr_file):
                    with open(msr_file, 'r') as f:
                        msrs.append(f"{msr_file}: {f.read().strip()}")
            
            # Common KVM-related MSRs
            kvm_msrs = [
                "MSR_KVM_SYSTEM_TIME",
                "MSR_KVM_WALL_CLOCK",
                "MSR_KVM_ASYNC_PF_EN",
                "MSR_KVM_STEAL_TIME",
                "MSR_KVM_PV_EOI_EN"
            ]
            
            self.results['msrs'] = kvm_msrs
            return msrs
            
        except Exception as e:
            print(f"Error enumerating MSRs: {e}")
            return []
    
    def run(self):
        print("[*] KVM Attack Surface Enumerator")
        print("[*] =============================\n")
        
        # 1. Find KVM modules
        print("[1] Finding KVM modules...")
        kvm_modules = self.run_cmd("lsmod | grep -i kvm")
        print(kvm_modules)
        
        # 2. Scan headers
        print("\n[2] Scanning KVM headers for ioctls and hypercalls...")
        self.scan_kvm_headers()
        
        # 3. Find device files
        print("\n[3] Finding KVM device files...")
        self.find_kvm_devices()
        
        # 4. Enumerate MSRs
        print("\n[4] Enumerating MSRs...")
        self.enumerate_msrs()
        
        # 5. Analyze specific modules
        print("\n[5] Analyzing KVM kernel modules...")
        modules_to_analyze = [
            "/dev/kvm",  # Character device
            f"{self.kernel_path}/kernel/arch/x86/kvm/kvm.ko",
            f"{self.kernel_path}/kernel/arch/x86/kvm/kvm-intel.ko",
            f"{self.kernel_path}/kernel/drivers/ptp/ptp_kvm.ko"
        ]
        
        for module in modules_to_analyze:
            if os.path.exists(module):
                analysis = self.analyze_kvm_module(module)
                if analysis['symbols']:
                    print(f"\n  Module {module}:")
                    for sym in analysis['symbols'][:5]:  # Show first 5
                        print(f"    {sym}")
        
        # 6. Print summary
        print("\n" + "="*60)
        print("SUMMARY OF KVM ATTACK SURFACE")
        print("="*60)
        
        print(f"\n[*] IOCTLs found: {len(set(self.results['ioctls']))}")
        for ioctl in sorted(set(self.results['ioctls']))[:10]:  # Show first 10
            print(f"  - {ioctl}")
        if len(self.results['ioctls']) > 10:
            print(f"  ... and {len(self.results['ioctls']) - 10} more")
        
        print(f"\n[*] Hypercalls found: {len(set(self.results['hypercalls']))}")
        for hc in sorted(set(self.results['hypercalls'])):
            print(f"  - {hc}")
        
        print(f"\n[*] Device files accessible:")
        for dev in self.results['device_files']:
            print(f"  - {dev}")
        
        print(f"\n[*] MSRs exposed to guests:")
        for msr in self.results['msrs']:
            print(f"  - {msr}")
        
        # Save results
        with open('kvm_attack_surface.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[*] Results saved to kvm_attack_surface.json")
        
        return self.results

if __name__ == "__main__":
    enumerator = KVMEnumerator()
    results = enumerator.run()
