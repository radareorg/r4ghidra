// Example R2Ghidra JavaScript file
// This script demonstrates the capabilities of the 'js' command and r2pipe interface

// Get current address
var addr = r2.cmd('s').trim();
console.log('Current address: ' + addr);

// Seek to 0
r2.cmd('s 0');
console.log('Moved to address 0x0');

// Get program info
var info = r2.cmdj('ij');
if (info) {
    console.log('Binary info:');
    console.log('- Format: ' + info.core.format);
    console.log('- Bits: ' + info.core.bits);
    console.log('- Architecture: ' + info.core.arch);
}

// List a few functions
console.log('\nFunctions:');
var funcs = r2.cmdj('aflj');
if (funcs && funcs.length > 0) {
    // Just show the first 5 functions
    var count = Math.min(5, funcs.length);
    for (var i = 0; i < count; i++) {
        console.log(funcs[i].name + ' @ ' + funcs[i].offset);
    }
    if (funcs.length > count) {
        console.log('... and ' + (funcs.length - count) + ' more');
    }
}

// Return to the original address
r2.cmd('s ' + addr);

// Show the result from a custom command
console.log('\nCustom command result:');
console.log(r2.cmd('?e Hello from JavaScript!'));

console.log('\nScript execution completed successfully!');